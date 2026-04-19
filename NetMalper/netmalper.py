#!/usr/bin/env python3
"""
netmalper.py — network recon mapper  v2.0.0
Runs nmap (deep scan) + socket scanner (fallback/parallel) and merges results
into an Obsidian-style force-directed link graph (JSON → netmalper_viewer.html).

Usage:
  python netmalper.py <target> [options]

Scan modes (auto-detected, can be overridden):
  nmap is used when available.  Socket scanner always runs in parallel.
  Results are merged — nmap wins on version/OS/script data, socket fills gaps.

Nmap flags used (based on privileges):
  root/sudo  →  -sS  (SYN scan, fast & stealthy)
  non-root   →  -sT  (TCP connect, no raw sockets needed)
  always     →  -sV  (service/version detection)
               --script default  (NSE default scripts)
  root only  →  -O   (OS fingerprinting)

Options:
  --ports PORT_RANGE    Ports to scan (default: top common ports)
                        Accepts: 80,443  or  1-1024  or  22,80,100-200
  --subdomains FILE     Wordlist for subdomain brute-force
  --out FILE            Output JSON path (default: <target>_graph.json)
  --timeout SEC         Per-probe timeout (default: 3)
  --threads N           Socket scanner threads (default: 30)
  --nmap-timing T       Nmap timing template 1-5 (default: 4)
  --no-nmap             Skip nmap, socket scanner only
  --no-socket           Skip socket scanner, nmap only
  --no-http             Skip HTTP endpoint probing
  --no-ports            Skip all port scanning
  --no-subs             Skip subdomain enumeration
  --no-dns              Skip DNS chain resolution
  --open-viewer         Open viewer HTML after scan
  --viewer FILE         Path to netmalper_viewer.html

Node types in output graph:
  root | subdomain | ip | port | service | endpoint | dns_record | cname |
  os_guess | nse_finding
"""

import argparse
import concurrent.futures
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
import urllib.parse
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

VERSION = "2.0.0"

# ── colour palette ────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
CY = "\033[96m"
GN = "\033[92m"
YL = "\033[93m"
RD = "\033[91m"
GY = "\033[90m"
MG = "\033[95m"
BL = "\033[94m"

def log(level, msg):
    ts  = datetime.now().strftime("%H:%M:%S")
    sym = {
        "info":  f"{CY}[*]{R}",
        "ok":    f"{GN}[+]{R}",
        "warn":  f"{YL}[!]{R}",
        "err":   f"{RD}[-]{R}",
        "nmap":  f"{MG}[N]{R}",
        "sock":  f"{BL}[S]{R}",
        "merge": f"{YL}[M]{R}",
    }
    print(f"{GY}{ts}{R} {sym.get(level, '[?]')} {msg}", flush=True)

def banner(target, has_nmap, is_root):
    priv  = f"{GN}root ✓{R}" if is_root  else f"{YL}non-root{R}"
    nmap_ = f"{GN}found ✓{R}" if has_nmap else f"{RD}not found — socket only{R}"
    print(f"""
{CY}╔══════════════════════════════════════════════════════╗
║  {B}netmalper{R}{CY}  v{VERSION}  —  nmap-powered recon mapper     ║
╚══════════════════════════════════════════════════════╝{R}
{GY}  target   : {B}{target}{R}
{GY}  nmap      : {nmap_}
{GY}  privs     : {priv}
{GY}  time      : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}
""")

# ── privilege + nmap detection ────────────────────────────────────────────────
def check_root() -> bool:
    try:    return os.geteuid() == 0
    except: return False

def find_nmap() -> Optional[str]:
    return shutil.which("nmap")

# ── graph ─────────────────────────────────────────────────────────────────────
class Graph:
    def __init__(self):
        self.nodes: dict[str, dict] = {}
        self.edges: list[dict] = []

    def add_node(self, nid: str, label: str, ntype: str, data: dict = None) -> str:
        if nid not in self.nodes:
            self.nodes[nid] = {"id": nid, "label": label, "type": ntype, "data": data or {}}
        else:
            # merge data — don't overwrite existing keys with empty values
            existing = self.nodes[nid]["data"]
            for k, v in (data or {}).items():
                if v not in (None, "", [], {}):
                    existing[k] = v
        return nid

    def add_edge(self, src: str, dst: str, label: str = ""):
        for e in self.edges:
            if e["source"] == src and e["target"] == dst and e["label"] == label:
                return
        self.edges.append({"source": src, "target": dst, "label": label})

    def to_dict(self, meta: dict) -> dict:
        return {"meta": meta, "nodes": list(self.nodes.values()), "edges": self.edges}

# ── DNS resolution chain ──────────────────────────────────────────────────────
def dns_chain(fqdn: str, g: Graph, parent_id: str, timeout: int = 3):
    current, prev_id, depth, seen = fqdn, parent_id, 0, set()
    while depth < 10:
        if current in seen: break
        seen.add(current); depth += 1
        cname_target = None
        try:
            r = subprocess.run(["dig", "+short", "CNAME", current],
                               capture_output=True, text=True, timeout=timeout)
            lines = [l.strip().rstrip(".") for l in r.stdout.strip().splitlines() if l.strip()]
            if lines: cname_target = lines[0]
        except Exception: pass

        if cname_target:
            nid = f"cname:{cname_target}"
            g.add_node(nid, cname_target, "cname", {"fqdn": cname_target})
            g.add_edge(prev_id, nid, "CNAME")
            log("ok", f"  CNAME {current} → {cname_target}")
            prev_id, current = nid, cname_target
        else:
            try:
                ips = socket.getaddrinfo(current, None)
                for ip in {r[4][0] for r in ips}:
                    nid = f"ip:{ip}"
                    try:    rdns, _, _ = socket.gethostbyaddr(ip)
                    except: rdns = ip
                    g.add_node(nid, ip, "ip", {
                        "ip": ip, "reverse_dns": rdns,
                        "is_private": _is_private(ip),
                    })
                    g.add_edge(prev_id, nid, "A")
                    log("ok", f"  A {current} → {ip} ({rdns})")
            except Exception as ex:
                log("warn", f"  DNS fail for {current}: {ex}")
            break

def _is_private(ip: str) -> bool:
    try:    return ipaddress.ip_address(ip).is_private
    except: return False

# ── subdomain enumeration ─────────────────────────────────────────────────────
BUILTIN_SUBS = [
    "www","mail","smtp","pop","imap","ftp","sftp","ssh",
    "api","api2","api3","v1","v2","v3",
    "dev","dev2","development","staging","stage","stg",
    "test","testing","qa","uat","sandbox","demo",
    "admin","administrator","portal","dashboard","panel",
    "login","auth","sso","oauth","accounts",
    "cdn","static","assets","media","img","images","files",
    "blog","docs","help","support","wiki","kb",
    "shop","store","checkout","payment","payments",
    "app","web","mobile","m","wap",
    "internal","intranet","corp","vpn","remote",
    "git","gitlab","github","bitbucket","repo","code",
    "ci","cd","jenkins","travis","build",
    "db","database","mysql","postgres","redis","mongo",
    "grafana","kibana","prometheus","monitor","metrics",
    "k8s","kubernetes","docker","registry","harbor",
    "backup","bak","old","legacy",
    "ns","ns1","ns2","dns","dns1","dns2",
    "mx","mx1","mx2","webmail",
    "status","health","ping",
    "webhooks","webhook","hooks","callback",
    "push","pull","events",
    "beta","alpha","rc",
    "secure","ssl","tls",
    "office","teams","slack","chat",
    "crm","erp","hr",
    "analytics","track","pixel",
    "proxy","gateway","edge",
    "search","solr","elasticsearch","es",
]

def enum_subdomains(target, wordlist, g, root_id, timeout, threads):
    found = []
    def check(sub):
        fqdn = f"{sub}.{target}"
        try:
            ips = socket.getaddrinfo(fqdn, None, timeout=timeout)
            if ips: return fqdn, [r[4][0] for r in ips]
        except: pass
        return None, None

    log("info", f"Brute-forcing {len(wordlist)} subdomains ({threads} threads)…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for fqdn, ips in ex.map(lambda s: check(s), wordlist):
            if fqdn:
                nid = f"sub:{fqdn}"
                g.add_node(nid, fqdn, "subdomain", {"fqdn": fqdn, "ips": list(set(ips))})
                g.add_edge(root_id, nid, "subdomain")
                log("ok", f"  {fqdn} → {', '.join(set(ips))}")
                found.append(fqdn)
                dns_chain(fqdn, g, nid, timeout)
    return found

# ── service map (socket fallback) ─────────────────────────────────────────────
SERVICE_MAP = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",
    80:"HTTP",110:"POP3",143:"IMAP",443:"HTTPS",445:"SMB",
    465:"SMTPS",587:"SMTP/TLS",993:"IMAPS",995:"POP3S",
    1433:"MSSQL",1521:"Oracle",2375:"Docker",2376:"Docker-TLS",
    3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",4848:"GlassFish",
    5432:"PostgreSQL",5672:"RabbitMQ",5900:"VNC",6379:"Redis",
    7474:"Neo4j",8080:"HTTP-Alt",8443:"HTTPS-Alt",8888:"Jupyter",
    9000:"SonarQube",9200:"Elasticsearch",9300:"ES-Internal",
    11211:"Memcached",15672:"RabbitMQ-Mgmt",27017:"MongoDB",
    27018:"MongoDB-Alt",50070:"Hadoop",
}

DEFAULT_PORTS = [
    21,22,23,25,53,80,110,143,443,445,
    993,995,3306,3389,5432,6379,
    8080,8443,8888,9200,27017,
]

def parse_port_range(s: str) -> list[int]:
    ports = []
    for part in s.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.extend(range(int(a), int(b)+1))
        else:
            ports.append(int(part))
    return sorted(set(ports))

# ══════════════════════════════════════════════════════════════════════════════
#  NMAP SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def build_nmap_cmd(nmap_bin: str, host: str, ports: list[int],
                   is_root: bool, timing: int) -> list[str]:
    port_str = ",".join(map(str, ports))
    cmd = [nmap_bin]

    # scan type
    if is_root:
        cmd += ["-sS"]          # SYN scan — fast, stealthy
        cmd += ["-O"]           # OS fingerprinting (root only)
    else:
        cmd += ["-sT"]          # TCP connect (no raw sockets)

    cmd += [
        "-sV",                  # service/version detection
        "--version-intensity", "5",
        "--script", "default",  # NSE default category
        f"-T{timing}",          # timing template
        "-p", port_str,
        "--open",               # only show open ports
        "-oX", "-",             # XML output to stdout
        "--host-timeout", "120s",
        host,
    ]
    return cmd

def run_nmap(nmap_bin: str, host: str, ports: list[int],
             is_root: bool, timing: int) -> Optional[str]:
    cmd = build_nmap_cmd(nmap_bin, host, ports, is_root, timing)
    log("nmap", f"Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        if result.returncode not in (0, 1):
            log("warn", f"nmap exited {result.returncode}: {result.stderr[:200]}")
        return result.stdout if result.stdout.strip() else None
    except subprocess.TimeoutExpired:
        log("warn", f"nmap timed out on {host}")
        return None
    except Exception as e:
        log("err", f"nmap failed: {e}")
        return None

# ── XML parser ────────────────────────────────────────────────────────────────
def parse_nmap_xml(xml_str: str) -> list[dict]:
    """
    Parse nmap XML output.
    Returns list of host dicts:
    {
      "host": str,
      "state": str,
      "os_matches": [ {"name", "accuracy"} ],
      "ports": [
        {
          "port":     int,
          "protocol": str,
          "state":    str,
          "service":  str,
          "product":  str,
          "version":  str,
          "extrainfo":str,
          "cpe":      [str],
          "scripts":  [ {"id", "output"} ],
        }
      ]
    }
    """
    hosts = []
    try:
        root = ET.fromstring(xml_str)
    except ET.ParseError as e:
        log("warn", f"nmap XML parse error: {e}")
        return []

    for host_el in root.findall("host"):
        state_el = host_el.find("status")
        if state_el is not None and state_el.get("state") != "up":
            continue

        # resolve address
        addr = ""
        for addr_el in host_el.findall("address"):
            if addr_el.get("addrtype") == "ipv4":
                addr = addr_el.get("addr", "")
                break
        if not addr:
            continue

        host_data = {"host": addr, "state": "up", "os_matches": [], "ports": []}

        # OS fingerprinting
        os_el = host_el.find("os")
        if os_el is not None:
            for osmatch in os_el.findall("osmatch"):
                host_data["os_matches"].append({
                    "name":     osmatch.get("name", ""),
                    "accuracy": osmatch.get("accuracy", ""),
                })

        # ports
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for port_el in ports_el.findall("port"):
                state_el2 = port_el.find("state")
                if state_el2 is None or state_el2.get("state") != "open":
                    continue

                portnum   = int(port_el.get("portid", 0))
                protocol  = port_el.get("protocol", "tcp")
                svc_el    = port_el.find("service")
                service   = ""
                product   = ""
                version   = ""
                extrainfo = ""
                cpe_list  = []

                if svc_el is not None:
                    service   = svc_el.get("name", "")
                    product   = svc_el.get("product", "")
                    version   = svc_el.get("version", "")
                    extrainfo = svc_el.get("extrainfo", "")
                    for cpe_el in svc_el.findall("cpe"):
                        cpe_list.append(cpe_el.text or "")

                # NSE scripts
                scripts = []
                for script_el in port_el.findall("script"):
                    sid    = script_el.get("id", "")
                    output = script_el.get("output", "")
                    # also grab table output for richer scripts
                    tables = []
                    for tbl in script_el.findall(".//elem"):
                        key = tbl.get("key", "")
                        val = tbl.text or ""
                        if key and val:
                            tables.append(f"{key}: {val}")
                    if tables:
                        output = output + "\n" + "\n".join(tables[:8])
                    scripts.append({"id": sid, "output": output.strip()[:400]})

                host_data["ports"].append({
                    "port":      portnum,
                    "protocol":  protocol,
                    "state":     "open",
                    "service":   service,
                    "product":   product,
                    "version":   version,
                    "extrainfo": extrainfo,
                    "cpe":       cpe_list,
                    "scripts":   scripts,
                })

        hosts.append(host_data)
    return hosts

# ── inject nmap results into graph ────────────────────────────────────────────
def inject_nmap(host_results: list[dict], host: str, g: Graph, parent_id: str):
    """
    For each parsed nmap host result, add/update port nodes, version nodes,
    OS guess nodes, and NSE finding nodes.
    """
    for hr in host_results:
        ip = hr["host"]
        ip_nid = f"ip:{ip}"

        # ensure IP node exists
        if ip_nid not in g.nodes:
            try:    rdns, _, _ = socket.gethostbyaddr(ip)
            except: rdns = ip
            g.add_node(ip_nid, ip, "ip", {
                "ip": ip, "reverse_dns": rdns,
                "is_private": _is_private(ip),
                "source": "nmap",
            })
            g.add_edge(parent_id, ip_nid, "A")

        # OS guess nodes
        for osm in hr["os_matches"][:2]:  # top 2 guesses
            if not osm["name"]: continue
            oslabel = f"{osm['name']} ({osm['accuracy']}%)"
            osnid   = f"os:{ip}:{osm['name'][:40]}"
            g.add_node(osnid, osm["name"][:30], "os_guess", {
                "os_name":  osm["name"],
                "accuracy": osm["accuracy"],
                "host":     ip,
            })
            g.add_edge(ip_nid, osnid, f"OS {osm['accuracy']}%")
            log("nmap", f"  OS guess: {oslabel}")

        # port / service / NSE nodes
        for p in hr["ports"]:
            portnum  = p["port"]
            svc_name = p["service"] or SERVICE_MAP.get(portnum, "unknown")
            product  = p["product"]
            version  = p["version"]
            version_str = " ".join(filter(None, [product, version, p["extrainfo"]])).strip()

            port_nid  = f"port:{ip}:{portnum}"
            edge_label = f"port/{svc_name}"

            # port node — merge in nmap enrichment
            g.add_node(port_nid, f":{portnum}", "port", {
                "port":        portnum,
                "service":     svc_name,
                "product":     product,
                "version":     version,
                "version_str": version_str,
                "protocol":    p["protocol"],
                "cpe":         p["cpe"],
                "host":        ip,
                "source":      "nmap",
            })
            g.add_edge(ip_nid, port_nid, edge_label)

            vstr = f"{GN}{portnum}/open{R}  {YL}{svc_name}{R}"
            if version_str: vstr += f"  {GY}{version_str}{R}"
            log("nmap", f"  {vstr}")

            # NSE script finding nodes
            for script in p["scripts"]:
                if not script["output"]: continue
                # skip boring/always-present scripts
                boring = {"ssl-date", "ssh-hostkey", "http-server-header"}
                if script["id"] in boring: continue

                snid = f"nse:{ip}:{portnum}:{script['id']}"
                # truncate output for label
                out_preview = script["output"].split("\n")[0][:50]
                g.add_node(snid, script["id"], "nse_finding", {
                    "script_id": script["id"],
                    "output":    script["output"],
                    "port":      portnum,
                    "host":      ip,
                })
                g.add_edge(port_nid, snid, "NSE")
                log("nmap", f"  NSE [{script['id']}] {out_preview}")

# ══════════════════════════════════════════════════════════════════════════════
#  SOCKET SCANNER
# ══════════════════════════════════════════════════════════════════════════════

def socket_scan(host: str, ports: list[int], g: Graph, parent_id: str,
                timeout: int, threads: int) -> list[int]:
    """TCP connect scan using socket. Fills gaps nmap may miss."""
    open_ports = []

    def probe(port):
        try:
            with socket.create_connection((host, port), timeout=timeout):
                return port, True
        except: return port, False

    log("sock", f"Socket scanning {host} ({len(ports)} ports, {threads} threads)…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, p): p for p in ports}
        for fut in concurrent.futures.as_completed(futures):
            port, is_open = fut.result()
            if is_open:
                svc  = SERVICE_MAP.get(port, "unknown")
                nid  = f"port:{host}:{port}"
                # only add if nmap didn't already add it
                if nid not in g.nodes:
                    g.add_node(nid, f":{port}", "port", {
                        "port": port, "service": svc,
                        "host": host, "source": "socket",
                    })
                    g.add_edge(parent_id, nid, f"port/{svc}")
                    log("sock", f"  {host}:{port} open ({svc})")
                else:
                    # mark that socket confirmed it too
                    g.nodes[nid]["data"]["socket_confirmed"] = True
                open_ports.append(port)
    return open_ports

# ══════════════════════════════════════════════════════════════════════════════
#  MERGE — run nmap + socket in parallel, merge results
# ══════════════════════════════════════════════════════════════════════════════

def scan_host(host: str, ports: list[int], g: Graph, parent_id: str,
              timeout: int, threads: int,
              nmap_bin: Optional[str], is_root: bool,
              use_nmap: bool, use_socket: bool, timing: int) -> list[int]:
    """
    Run nmap and socket scanner concurrently, merge into graph.
    Returns combined list of open ports.
    """
    nmap_future   = None
    socket_future = None

    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as ex:
        if use_nmap and nmap_bin:
            nmap_future = ex.submit(
                run_nmap, nmap_bin, host, ports, is_root, timing
            )
        if use_socket:
            socket_future = ex.submit(
                socket_scan, host, ports, g, parent_id, timeout, threads
            )

        socket_ports = []
        if socket_future:
            socket_ports = socket_future.result()

        nmap_xml = None
        if nmap_future:
            nmap_xml = nmap_future.result()

    # inject nmap results (enriches/overrides socket data)
    nmap_ports = []
    if nmap_xml:
        host_results = parse_nmap_xml(nmap_xml)
        if host_results:
            inject_nmap(host_results, host, g, parent_id)
            for hr in host_results:
                nmap_ports += [p["port"] for p in hr["ports"]]
        else:
            log("warn", f"nmap returned no hosts for {host}")

    # merge: union of both scanners' open ports
    all_open = sorted(set(socket_ports + nmap_ports))

    if nmap_xml and use_socket:
        only_socket = set(socket_ports) - set(nmap_ports)
        only_nmap   = set(nmap_ports)   - set(socket_ports)
        both        = set(socket_ports) & set(nmap_ports)
        log("merge", f"  socket={len(socket_ports)}  nmap={len(nmap_ports)}  "
                     f"both={len(both)}  socket-only={len(only_socket)}  "
                     f"nmap-only={len(only_nmap)}")

    return all_open

# ══════════════════════════════════════════════════════════════════════════════
#  HTTP PROBING
# ══════════════════════════════════════════════════════════════════════════════

PROBE_PATHS = [
    "/","/healthz","/health","/ping","/status",
    "/robots.txt","/sitemap.xml","/.well-known/security.txt",
    "/api","/api/v1","/api/v2",
    "/metrics","/prometheus","/actuator","/actuator/health",
    "/debug/pprof/","/debug/vars","/debug/requests","/debug/events",
    "/.env","/config.json","/app.json",
    "/admin","/admin/","/dashboard",
    "/swagger","/swagger-ui","/swagger-ui.html",
    "/openapi.json","/api-docs",
    "/version","/info","/build",
    "/server-status","/server-info",
    "/.git/HEAD","/.git/config",
    "/wp-login.php","/wp-admin",
    "/phpmyadmin","/adminer",
]

def probe_http(host: str, g: Graph, parent_id: str,
               timeout: int, threads: int, open_ports: list[int]):
    schemes = []
    if 443 in open_ports or 8443 in open_ports:
        schemes.append(("https", 443 if 443 in open_ports else 8443))
    if 80 in open_ports or 8080 in open_ports:
        schemes.append(("http", 80 if 80 in open_ports else 8080))
    if not schemes:
        schemes = [("https", 443), ("http", 80)]

    targets = [(s, p, path) for s, p in schemes for path in PROBE_PATHS]

    def check(scheme, port, path):
        url = (f"{scheme}://{host}:{port}{path}"
               if port not in (80, 443)
               else f"{scheme}://{host}{path}")
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "netmalper/2.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return url, resp.status, resp.headers.get("Content-Type",""), \
                       resp.headers.get("Server",""), resp.headers.get("Content-Length","?")
        except urllib.error.HTTPError as e:
            return url, e.code, "", "", ""
        except: return url, None, "", "", ""

    log("info", f"HTTP probing {len(targets)} paths on {host}…")
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
        for url, code, ctype, server, length in ex.map(lambda t: check(*t), targets):
            if code in (200, 201, 301, 302, 401, 403):
                clr = GN if code == 200 else (YL if code in (301,302) else RD)
                log("ok", f"  {clr}{code}{R} {url}  {GY}{server}{R}")
                path = urllib.parse.urlparse(url).path
                nid  = f"endpoint:{url}"
                g.add_node(nid, path or "/", "endpoint", {
                    "url": url, "status": code,
                    "content_type": ctype, "server": server,
                    "content_length": length,
                    "interesting": code == 200,
                })
                g.add_edge(parent_id, nid, str(code))

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="netmalper v2 — nmap-powered recon graph mapper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("target")
    ap.add_argument("--ports",        default=",".join(map(str, DEFAULT_PORTS)))
    ap.add_argument("--subdomains",   default=None)
    ap.add_argument("--out",          default=None)
    ap.add_argument("--timeout",      type=int, default=3)
    ap.add_argument("--threads",      type=int, default=30)
    ap.add_argument("--nmap-timing",  type=int, default=4, choices=range(1,6))
    ap.add_argument("--no-nmap",      action="store_true")
    ap.add_argument("--no-socket",    action="store_true")
    ap.add_argument("--no-http",      action="store_true")
    ap.add_argument("--no-ports",     action="store_true")
    ap.add_argument("--no-subs",      action="store_true")
    ap.add_argument("--no-dns",       action="store_true")
    ap.add_argument("--open-viewer",  action="store_true")
    ap.add_argument("--viewer",       default="netmalper_viewer.html")
    args = ap.parse_args()

    target   = args.target.lower().strip()
    target   = re.sub(r'^https?://', '', target).rstrip("/")
    out_path = args.out or f"{target.replace('.','_')}_graph.json"

    is_root  = check_root()
    nmap_bin = None if args.no_nmap else find_nmap()
    use_nmap = bool(nmap_bin) and not args.no_nmap
    use_sock = not args.no_socket

    banner(target, bool(nmap_bin), is_root)

    if use_nmap and is_root:
        log("info", f"{GN}SYN scan + OS fingerprinting enabled (root){R}")
    elif use_nmap:
        log("warn", f"Running as non-root — using TCP connect scan (-sT), no OS fingerprint")
        log("warn", f"  Run with sudo for SYN scan + OS detection")

    t0 = time.time()
    g  = Graph()

    root_id = f"root:{target}"
    g.add_node(root_id, target, "root", {"fqdn": target})

    # ── 1. DNS chain ──────────────────────────────────────────────────────────
    if not args.no_dns:
        log("info", "Resolving DNS chain for root…")
        dns_chain(target, g, root_id, args.timeout)

    # ── 2. Subdomain enumeration ──────────────────────────────────────────────
    found_subs = []
    if not args.no_subs:
        log("info", "Starting subdomain enumeration…")
        wordlist = BUILTIN_SUBS
        if args.subdomains:
            with open(args.subdomains) as f:
                wordlist = [l.strip() for l in f if l.strip()]
        found_subs = enum_subdomains(target, wordlist, g, root_id,
                                     args.timeout, args.threads)

    # ── 3. Port scanning (nmap + socket, merged) ──────────────────────────────
    ports = parse_port_range(args.ports)

    scan_targets = [target]
    scan_targets += [n["data"]["ip"] for n in g.nodes.values() if n["type"] == "ip"]
    scan_targets  = list(dict.fromkeys(scan_targets))

    all_open: dict[str, list[int]] = {}
    if not args.no_ports:
        for st in scan_targets:
            parent = (f"root:{target}" if st == target
                      else f"ip:{st}"   if f"ip:{st}" in g.nodes
                      else root_id)
            log("info", f"{'─'*48}")
            log("info", f"Scanning {B}{st}{R}")
            open_p = scan_host(
                st, ports, g, parent,
                args.timeout, args.threads,
                nmap_bin, is_root,
                use_nmap, use_sock,
                args.nmap_timing,
            )
            all_open[st] = open_p

    # ── 4. HTTP probing ───────────────────────────────────────────────────────
    if not args.no_http:
        log("info", f"{'─'*48}")
        for ht in [target] + found_subs:
            op = all_open.get(ht, [])
            parent = f"root:{target}" if ht == target else f"sub:{ht}"
            probe_http(ht, g, parent, args.timeout, args.threads, op)

    # ── write output ──────────────────────────────────────────────────────────
    duration = round(time.time() - t0, 2)
    meta = {
        "target":      target,
        "timestamp":   datetime.now(timezone.utc).isoformat(),
        "duration_s":  duration,
        "version":     VERSION,
        "nmap_used":   use_nmap,
        "root_scan":   is_root,
        "node_count":  len(g.nodes),
        "edge_count":  len(g.edges),
    }
    data = g.to_dict(meta)
    with open(out_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"""
{CY}{'─'*54}
  {GN}Scan complete{R}{CY} in {B}{duration}s{R}
  {GN}Nodes     :{R} {len(g.nodes)}
  {GN}Edges     :{R} {len(g.edges)}
  {GN}nmap used :{R} {GN+'yes'+R if use_nmap else RD+'no'+R}
  {GN}root scan :{R} {GN+'yes (SYN+OS)'+R if is_root else YL+'no (TCP connect)'+R}
  {GN}output    :{R} {out_path}
{CY}{'─'*54}{R}
""")

    if args.open_viewer and os.path.exists(args.viewer):
        import webbrowser
        webbrowser.open(
            f"file://{os.path.abspath(args.viewer)}"
            f"?graph={urllib.parse.quote(os.path.abspath(out_path))}"
        )

    return out_path

if __name__ == "__main__":
    main()
