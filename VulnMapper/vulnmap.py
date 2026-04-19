#!/usr/bin/env python3
"""
vulnmap.py — vulnerability mapper
Reads a netmalper graph.json, runs nuclei + nikto + OpenVAS against
discovered targets, and writes findings back as vuln nodes into the graph.

Usage:
  python vulnmap.py <graph.json> [options]

Options:
  --out FILE           Output graph JSON (default: overwrites input)
  --nuclei-templates T Nuclei template path or tag (default: cves,misconfig,default-logins,exposed-panels)
  --nuclei-severity S  Min severity: info,low,medium,high,critical (default: low)
  --nikto-tuning T     Nikto tuning options (default: 123457b)
  --openvas-host H     OpenVAS GVM host (default: 127.0.0.1)
  --openvas-port P     OpenVAS GVM TLS port (default: 9390)
  --openvas-user U     GVM username (default: admin)
  --openvas-pass P     GVM password (default: reads OPENVAS_PASS env var)
  --openvas-timeout S  Seconds to wait for OpenVAS scan (default: 600)
  --skip-nuclei        Skip nuclei
  --skip-nikto         Skip nikto
  --skip-openvas       Skip OpenVAS
  --threads N          Parallel tool threads (default: 4)
  --dry-run            Print commands without executing
"""

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Optional

VERSION = "1.0.0"

# ── colours ───────────────────────────────────────────────────────────────────
R  = "\033[0m";  B  = "\033[1m"
CY = "\033[96m"; GN = "\033[92m"; YL = "\033[93m"
RD = "\033[91m"; GY = "\033[90m"; MG = "\033[95m"

SEV_COLOR = {
    "critical": "\033[41m\033[97m",
    "high":     RD,
    "medium":   YL,
    "low":      CY,
    "info":     GY,
    "unknown":  GY,
}

def log(level, msg):
    ts  = datetime.now().strftime("%H:%M:%S")
    sym = {
        "info":    f"{CY}[*]{R}",
        "ok":      f"{GN}[+]{R}",
        "warn":    f"{YL}[!]{R}",
        "err":     f"{RD}[-]{R}",
        "nuclei":  f"{MG}[N]{R}",
        "nikto":   f"{CY}[K]{R}",
        "openvas": f"{YL}[O]{R}",
        "vuln":    f"{RD}[V]{R}",
    }
    print(f"{GY}{ts}{R} {sym.get(level,'[?]')} {msg}", flush=True)

def banner(graph_path: str, target_count: int):
    print(f"""
{RD}╔══════════════════════════════════════════════════════╗
║  {B}vulnmap{R}{RD}  v{VERSION}  —  vulnerability graph mapper        ║
╚══════════════════════════════════════════════════════╝{R}
{GY}  input   : {B}{graph_path}{R}
{GY}  targets : {B}{target_count}{R}
{GY}  time    : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{R}
""")

# ── severity helpers ──────────────────────────────────────────────────────────
SEV_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1, "unknown": 0}

def norm_severity(s: str) -> str:
    s = (s or "").lower().strip()
    return s if s in SEV_RANK else "unknown"

# ══════════════════════════════════════════════════════════════════════════════
#  GRAPH HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def load_graph(path: str) -> dict:
    with open(path) as f:
        return json.load(f)

def save_graph(data: dict, path: str):
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    log("ok", f"Graph saved → {path}")

class VulnGraph:
    def __init__(self, data: dict):
        self.data  = data
        self.nodes = {n["id"]: n for n in data["nodes"]}
        self.edges = data["edges"]

    def add_vuln_node(self, nid: str, label: str, data: dict):
        if nid not in self.nodes:
            node = {"id": nid, "label": label, "type": "vuln", "data": data}
            self.nodes[nid] = node
            self.data["nodes"].append(node)

    def add_edge(self, src: str, dst: str, label: str = ""):
        for e in self.edges:
            if e["source"] == src and e["target"] == dst and e["label"] == label:
                return
        edge = {"source": src, "target": dst, "label": label}
        self.edges.append(edge)
        self.data["edges"].append(edge)

    def get_http_targets(self) -> list[dict]:
        """Return list of {url, host, port, parent_id} for HTTP/HTTPS endpoints."""
        targets = []
        for nid, node in self.nodes.items():
            if node["type"] != "port":
                continue
            port = node["data"].get("port")
            host = node["data"].get("host", "")
            if not host or port not in (80, 443, 8080, 8443):
                continue
            scheme = "https" if port in (443, 8443) else "http"
            port_suffix = "" if port in (80, 443) else f":{port}"
            url = f"{scheme}://{host}{port_suffix}"
            targets.append({
                "url":       url,
                "host":      host,
                "port":      port,
                "scheme":    scheme,
                "parent_id": nid,
            })
        return targets

    def get_all_hosts(self) -> list[dict]:
        """Return unique {host, open_ports, parent_id} for nuclei / OpenVAS."""
        seen = {}
        # from IP nodes
        for nid, node in self.nodes.items():
            if node["type"] == "ip":
                ip = node["data"].get("ip", "")
                if ip and ip not in seen:
                    seen[ip] = {"host": ip, "open_ports": [], "parent_id": nid}
        # collect open ports per host
        for nid, node in self.nodes.items():
            if node["type"] == "port":
                h = node["data"].get("host", "")
                p = node["data"].get("port")
                if h in seen and p:
                    seen[h]["open_ports"].append(p)
        # also include root + subdomain FQDNs
        for nid, node in self.nodes.items():
            if node["type"] in ("root", "subdomain"):
                fqdn = node["data"].get("fqdn", "")
                if fqdn and fqdn not in seen:
                    seen[fqdn] = {"host": fqdn, "open_ports": [], "parent_id": nid}
        return list(seen.values())

    def update_meta(self, vuln_count: int, duration: float):
        self.data["meta"]["vulnmap_version"]   = VERSION
        self.data["meta"]["vulnmap_timestamp"] = datetime.now(timezone.utc).isoformat()
        self.data["meta"]["vuln_count"]        = vuln_count
        self.data["meta"]["vulnmap_duration"]  = round(duration, 2)
        self.data["meta"]["node_count"]        = len(self.data["nodes"])
        self.data["meta"]["edge_count"]        = len(self.data["edges"])

# ══════════════════════════════════════════════════════════════════════════════
#  NUCLEI
# ══════════════════════════════════════════════════════════════════════════════

def run_nuclei(targets: list[str], g: VulnGraph, args,
               host_to_parent: dict[str, str]) -> int:
    nbin = shutil.which("nuclei")
    if not nbin:
        log("warn", "nuclei not found — skipping (install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest)")
        return 0

    log("nuclei", f"Scanning {len(targets)} targets…")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as tf:
        tf.write("\n".join(targets))
        targets_file = tf.name

    with tempfile.NamedTemporaryFile(mode="w", suffix=".jsonl", delete=False) as of:
        out_file = of.name

    cmd = [
        nbin,
        "-l",        targets_file,
        "-t",        args.nuclei_templates,
        "-severity", args.nuclei_severity,
        "-jsonl",
        "-o",        out_file,
        "-silent",
        "-nc",                    # no colour in output
        "-timeout",  "10",
        "-retries",  "1",
        "-rate-limit", "50",
    ]

    log("nuclei", f"cmd: {' '.join(cmd)}")
    if args.dry_run:
        log("nuclei", "[DRY RUN] would execute above command")
        os.unlink(targets_file)
        os.unlink(out_file)
        return 0

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if proc.returncode not in (0, 1):
            log("warn", f"nuclei exited {proc.returncode}: {proc.stderr[:300]}")
    except subprocess.TimeoutExpired:
        log("warn", "nuclei timed out")
        return 0
    except Exception as e:
        log("err", f"nuclei error: {e}")
        return 0
    finally:
        os.unlink(targets_file)

    count = 0
    if os.path.exists(out_file):
        with open(out_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    finding = json.loads(line)
                except json.JSONDecodeError:
                    continue

                template_id = finding.get("template-id", "")
                name        = finding.get("info", {}).get("name", template_id)
                severity    = norm_severity(finding.get("info", {}).get("severity", ""))
                matched_at  = finding.get("matched-at", "")
                host        = finding.get("host", "")
                description = finding.get("info", {}).get("description", "")
                reference   = finding.get("info", {}).get("reference", [])
                tags        = finding.get("info", {}).get("tags", [])
                cvss        = finding.get("info", {}).get("classification", {}).get("cvss-score", "")
                cve         = finding.get("info", {}).get("classification", {}).get("cve-id", [])
                curl_cmd    = finding.get("curl-command", "")
                extracted   = finding.get("extracted-results", [])

                sev_c = SEV_COLOR.get(severity, GY)
                log("vuln", f"  [{sev_c}{severity.upper()}{R}] {B}{name}{R}  {GY}{matched_at}{R}")

                nid = f"vuln:nuclei:{template_id}:{host}:{matched_at}"
                nid = re.sub(r'[^\w:./\-]', '_', nid)[:120]

                parent_id = _find_parent(host, host_to_parent, g)

                g.add_vuln_node(nid, name[:40], {
                    "tool":        "nuclei",
                    "template_id": template_id,
                    "severity":    severity,
                    "name":        name,
                    "matched_at":  matched_at,
                    "host":        host,
                    "description": description[:500] if description else "",
                    "references":  reference[:3] if isinstance(reference, list) else [reference],
                    "tags":        tags if isinstance(tags, list) else [tags],
                    "cvss_score":  str(cvss) if cvss else "",
                    "cve":         cve if isinstance(cve, list) else [cve],
                    "curl":        curl_cmd[:300] if curl_cmd else "",
                    "extracted":   extracted[:5] if extracted else [],
                })
                g.add_edge(parent_id, nid, f"vuln/{severity}")
                count += 1

        os.unlink(out_file)

    log("nuclei", f"Found {GN if count==0 else RD}{count}{R} findings")
    return count

# ══════════════════════════════════════════════════════════════════════════════
#  NIKTO
# ══════════════════════════════════════════════════════════════════════════════

def run_nikto_single(target: dict, g: VulnGraph, args,
                     host_to_parent: dict[str, str]) -> int:
    nbin = shutil.which("nikto")
    if not nbin:
        return 0

    url    = target["url"]
    host   = target["host"]
    port   = target["port"]
    parent = target["parent_id"]

    log("nikto", f"Scanning {url}…")

    with tempfile.NamedTemporaryFile(mode="w", suffix=".xml", delete=False) as of:
        out_file = of.name

    cmd = [
        nbin,
        "-h",       url,
        "-p",       str(port),
        "-Tuning",  args.nikto_tuning,
        "-o",       out_file,
        "-Format",  "xml",
        "-nointeractive",
        "-maxtime", "300s",
    ]

    log("nikto", f"cmd: {' '.join(cmd)}")
    if args.dry_run:
        log("nikto", "[DRY RUN]")
        os.unlink(out_file)
        return 0

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=360)
    except subprocess.TimeoutExpired:
        log("warn", f"nikto timed out on {url}")
    except Exception as e:
        log("err", f"nikto error: {e}")
        os.unlink(out_file)
        return 0

    count = 0
    if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        try:
            tree = ET.parse(out_file)
            root = tree.getroot()

            for item in root.iter("item"):
                description = item.findtext("description", "").strip()
                uri         = item.findtext("uri", "").strip()
                osvdbid     = item.findtext("osvdbid", "").strip()
                osvdblink   = item.findtext("osvdblink", "").strip()
                method      = item.findtext("method", "GET").strip()
                namelink    = item.findtext("namelink", "").strip()

                if not description:
                    continue

                # rough severity from description keywords
                severity = "info"
                dl = description.lower()
                if any(k in dl for k in ("remote code", "rce", "sql injection", "command injection")):
                    severity = "critical"
                elif any(k in dl for k in ("xss", "csrf", "traversal", "disclosure", "credential")):
                    severity = "high"
                elif any(k in dl for k in ("outdated", "vulnerable", "misconfiguration", "exposed")):
                    severity = "medium"
                elif any(k in dl for k in ("server", "header", "cookie", "information")):
                    severity = "low"

                sev_c = SEV_COLOR.get(severity, GY)
                log("vuln", f"  [{sev_c}{severity.upper()}{R}] {description[:70]}")

                full_url = f"{url}{uri}"
                nid = f"vuln:nikto:{host}:{port}:{osvdbid or hash(description) & 0xFFFFFF}"

                g.add_vuln_node(nid, description[:40], {
                    "tool":        "nikto",
                    "severity":    severity,
                    "name":        description[:120],
                    "matched_at":  full_url,
                    "host":        host,
                    "port":        port,
                    "uri":         uri,
                    "method":      method,
                    "osvdb_id":    osvdbid,
                    "osvdb_link":  osvdblink,
                    "reference":   namelink,
                    "description": description[:500],
                })
                g.add_edge(parent, nid, f"vuln/{severity}")
                count += 1

        except ET.ParseError as e:
            log("warn", f"nikto XML parse error on {url}: {e}")
        finally:
            os.unlink(out_file)

    log("nikto", f"{url} → {GN if count==0 else RD}{count}{R} findings")
    return count

def run_nikto(http_targets: list[dict], g: VulnGraph, args,
              host_to_parent: dict[str, str]) -> int:
    nbin = shutil.which("nikto")
    if not nbin:
        log("warn", "nikto not found — skipping (install: sudo apt install nikto)")
        return 0

    if not http_targets:
        log("nikto", "No HTTP/HTTPS targets found — skipping")
        return 0

    log("nikto", f"Running against {len(http_targets)} HTTP target(s)…")
    total = 0
    # nikto isn't thread-safe with temp files, run sequentially
    for t in http_targets:
        total += run_nikto_single(t, g, args, host_to_parent)
    return total

# ══════════════════════════════════════════════════════════════════════════════
#  OPENVAS / GVM
# ══════════════════════════════════════════════════════════════════════════════

# OpenVAS interaction via gvm-cli (python-gvm CLI tool)
# Requires: pip install gvm-tools  and  gvm-cli running / GVM socket accessible

def _gvm_cli(args, xml_cmd: str) -> Optional[str]:
    """Send a GMP XML command via gvm-cli and return response."""
    gbin = shutil.which("gvm-cli")
    if not gbin:
        log("warn", "gvm-cli not found (pip install gvm-tools)")
        return None

    cmd = [
        gbin,
        "--gmp-username", args.openvas_user,
        "--gmp-password", args.openvas_pass,
        "socket",
        "--xml", xml_cmd,
    ]

    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            log("warn", f"gvm-cli error: {r.stderr[:200]}")
            return None
        return r.stdout
    except subprocess.TimeoutExpired:
        log("warn", "gvm-cli timed out")
        return None
    except Exception as e:
        log("err", f"gvm-cli exception: {e}")
        return None

def _gvm_tls_cli(args, xml_cmd: str) -> Optional[str]:
    """Fallback: gvm-cli TLS mode if socket not available."""
    gbin = shutil.which("gvm-cli")
    if not gbin:
        return None
    cmd = [
        gbin,
        "--gmp-username", args.openvas_user,
        "--gmp-password", args.openvas_pass,
        "tls",
        "--hostname", args.openvas_host,
        "--port",     str(args.openvas_port),
        "--xml", xml_cmd,
    ]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else None
    except Exception:
        return None

def _gvm(args, xml_cmd: str) -> Optional[str]:
    """Try socket first, fall back to TLS."""
    r = _gvm_cli(args, xml_cmd)
    if r is None:
        r = _gvm_tls_cli(args, xml_cmd)
    return r

def _xml_attr(xml_str: str, tag: str, attr: str) -> Optional[str]:
    try:
        root = ET.fromstring(xml_str)
        el   = root if root.tag == tag else root.find(f".//{tag}")
        return el.get(attr) if el is not None else None
    except Exception:
        return None

def run_openvas(hosts: list[str], g: VulnGraph, args,
                host_to_parent: dict[str, str]) -> int:
    if not hosts:
        log("openvas", "No hosts to scan")
        return 0

    log("openvas", f"Starting GVM scan against {len(hosts)} host(s)…")

    if args.dry_run:
        log("openvas", f"[DRY RUN] would scan: {', '.join(hosts)}")
        return 0

    target_str = ", ".join(hosts)

    # ── 1. create target ──────────────────────────────────────────────────────
    target_name = f"vulnmap-{uuid.uuid4().hex[:8]}"
    create_target_xml = (
        f'<create_target>'
        f'<name>{target_name}</name>'
        f'<hosts>{target_str}</hosts>'
        f'<port_list id="33d0cd82-57c6-11e1-8ed1-406186ea4fc5"/>'  # All TCP+UDP
        f'</create_target>'
    )
    resp = _gvm(args, create_target_xml)
    if not resp:
        log("err", "OpenVAS: failed to create target")
        return 0

    target_id = _xml_attr(resp, "create_target_response", "id")
    if not target_id:
        log("err", f"OpenVAS: could not parse target ID from: {resp[:200]}")
        return 0
    log("openvas", f"Target created: {target_id}")

    # ── 2. get Full and Fast config ID ────────────────────────────────────────
    configs_resp = _gvm(args, "<get_configs/>")
    config_id    = "daba56c8-73ec-11df-a475-002264764cea"  # Full and fast (default)
    if configs_resp:
        try:
            root = ET.fromstring(configs_resp)
            for cfg in root.findall(".//config"):
                name = cfg.findtext("name", "")
                if "full and fast" in name.lower():
                    config_id = cfg.get("id", config_id)
                    break
        except Exception:
            pass
    log("openvas", f"Using scan config: {config_id}")

    # ── 3. get scanner ID (OpenVAS Default) ───────────────────────────────────
    scanners_resp = _gvm(args, "<get_scanners/>")
    scanner_id    = "08b69003-5fc2-4037-a479-93b440211c73"  # OpenVAS Default
    if scanners_resp:
        try:
            root = ET.fromstring(scanners_resp)
            for sc in root.findall(".//scanner"):
                name = sc.findtext("name", "")
                if "openvas" in name.lower():
                    scanner_id = sc.get("id", scanner_id)
                    break
        except Exception:
            pass

    # ── 4. create and start task ──────────────────────────────────────────────
    task_name = f"vulnmap-task-{uuid.uuid4().hex[:8]}"
    create_task_xml = (
        f'<create_task>'
        f'<name>{task_name}</name>'
        f'<config id="{config_id}"/>'
        f'<target id="{target_id}"/>'
        f'<scanner id="{scanner_id}"/>'
        f'</create_task>'
    )
    resp = _gvm(args, create_task_xml)
    if not resp:
        log("err", "OpenVAS: failed to create task")
        return 0

    task_id = _xml_attr(resp, "create_task_response", "id")
    if not task_id:
        log("err", f"OpenVAS: could not parse task ID")
        return 0
    log("openvas", f"Task created: {task_id}")

    # start task
    resp = _gvm(args, f'<start_task task_id="{task_id}"/>')
    if not resp:
        log("err", "OpenVAS: failed to start task")
        return 0
    log("openvas", f"Task started. Waiting (timeout: {args.openvas_timeout}s)…")

    # ── 5. poll for completion ────────────────────────────────────────────────
    start_wait = time.time()
    report_id  = None
    while True:
        time.sleep(15)
        elapsed = time.time() - start_wait
        if elapsed > args.openvas_timeout:
            log("warn", f"OpenVAS timed out after {elapsed:.0f}s — fetching partial results")
            break

        status_resp = _gvm(args, f'<get_tasks task_id="{task_id}"/>')
        if not status_resp:
            continue
        try:
            root    = ET.fromstring(status_resp)
            task_el = root.find(".//task")
            if task_el is None:
                continue
            status  = task_el.findtext("status", "")
            progress= task_el.findtext("progress", "0")
            log("openvas", f"  status={status} progress={progress}%  elapsed={elapsed:.0f}s")

            # grab report ID
            for rep in task_el.findall(".//report"):
                rid = rep.get("id")
                if rid:
                    report_id = rid

            if status in ("Done", "Stopped"):
                break
        except Exception as e:
            log("warn", f"OpenVAS poll error: {e}")
            continue

    if not report_id:
        log("err", "OpenVAS: no report ID found")
        return 0

    # ── 6. fetch report ───────────────────────────────────────────────────────
    log("openvas", f"Fetching report {report_id}…")
    report_resp = _gvm(args,
        f'<get_reports report_id="{report_id}" '
        f'filter="levels=hmlgd rows=1000 min_qod=30" '
        f'details="1"/>'
    )
    if not report_resp:
        log("err", "OpenVAS: failed to fetch report")
        return 0

    # ── 7. parse results ──────────────────────────────────────────────────────
    count = 0
    try:
        root = ET.fromstring(report_resp)
        for result in root.findall(".//result"):
            name        = result.findtext("name",        "").strip()
            description = result.findtext("description", "").strip()
            severity_raw= result.findtext("severity",    "0").strip()
            host_el     = result.find("host")
            host_ip     = host_el.text.strip() if host_el is not None and host_el.text else ""
            port_str    = result.findtext("port",        "").strip()
            nvt_el      = result.find("nvt")
            oid         = nvt_el.get("oid", "") if nvt_el is not None else ""
            cvss_base   = nvt_el.findtext("cvss_base", "") if nvt_el is not None else ""
            cves_el     = nvt_el.find("refs") if nvt_el is not None else None
            cves        = []
            if cves_el is not None:
                for ref in cves_el.findall("ref"):
                    if ref.get("type", "").upper() == "CVE":
                        cves.append(ref.get("id", ""))

            if not name:
                continue

            # map CVSS float → severity string
            try:
                cvss_f = float(severity_raw)
            except ValueError:
                cvss_f = 0.0
            if   cvss_f >= 9.0: severity = "critical"
            elif cvss_f >= 7.0: severity = "high"
            elif cvss_f >= 4.0: severity = "medium"
            elif cvss_f >  0.0: severity = "low"
            else:               severity = "info"

            sev_c = SEV_COLOR.get(severity, GY)
            log("vuln", f"  [{sev_c}{severity.upper()}{R}] {B}{name[:60]}{R}  {GY}{host_ip}:{port_str}{R}")

            nid = f"vuln:openvas:{oid}:{host_ip}:{port_str}"
            nid = re.sub(r'[^\w:./\-]', '_', nid)[:120]

            parent_id = _find_parent(host_ip, host_to_parent, g)

            g.add_vuln_node(nid, name[:40], {
                "tool":        "openvas",
                "severity":    severity,
                "name":        name,
                "matched_at":  f"{host_ip}:{port_str}",
                "host":        host_ip,
                "port":        port_str,
                "oid":         oid,
                "cvss_score":  cvss_base or str(severity_raw),
                "cve":         cves,
                "description": description[:600],
            })
            parent_id = _find_parent(host_ip, host_to_parent, g)
            g.add_edge(parent_id, nid, f"vuln/{severity}")
            count += 1

    except ET.ParseError as e:
        log("err", f"OpenVAS report parse error: {e}")

    # ── 8. clean up task + target ─────────────────────────────────────────────
    _gvm(args, f'<delete_task task_id="{task_id}" ultimate="0"/>')
    _gvm(args, f'<delete_target target_id="{target_id}" ultimate="0"/>')

    log("openvas", f"Found {GN if count==0 else RD}{count}{R} findings")
    return count

# ── parent node lookup ────────────────────────────────────────────────────────
def _find_parent(host: str, host_to_parent: dict[str, str], g: VulnGraph) -> str:
    if host in host_to_parent:
        return host_to_parent[host]
    # try stripping scheme
    clean = re.sub(r'^https?://', '', host).rstrip("/")
    if clean in host_to_parent:
        return host_to_parent[clean]
    # fallback: find root node
    for nid, node in g.nodes.items():
        if node["type"] == "root":
            return nid
    return list(g.nodes.keys())[0] if g.nodes else "root:unknown"

# ── build host→parent index ───────────────────────────────────────────────────
def build_host_index(g: VulnGraph) -> dict[str, str]:
    idx = {}
    for nid, node in g.nodes.items():
        t = node["type"]
        if t == "ip":
            idx[node["data"].get("ip", "")] = nid
        elif t in ("root", "subdomain"):
            idx[node["data"].get("fqdn", "")] = nid
        elif t == "port":
            h = node["data"].get("host", "")
            p = node["data"].get("port")
            if h and p:
                scheme = "https" if p in (443, 8443) else "http"
                sfx    = "" if p in (80, 443) else f":{p}"
                idx[f"{scheme}://{h}{sfx}"] = nid
                idx[h] = nid
    return idx

# ══════════════════════════════════════════════════════════════════════════════
#  SUMMARY
# ══════════════════════════════════════════════════════════════════════════════

def print_summary(g: VulnGraph, duration: float):
    vuln_nodes = [n for n in g.nodes.values() if n["type"] == "vuln"]
    by_sev: dict[str, list] = {s: [] for s in ("critical","high","medium","low","info","unknown")}
    for n in vuln_nodes:
        sev = n["data"].get("severity", "unknown")
        by_sev.setdefault(sev, []).append(n)

    total = len(vuln_nodes)
    print(f"""
{RD}{'─'*54}
  {B}Scan complete{R}{RD} in {duration:.1f}s
  {B}Total findings : {total}{R}""")

    for sev in ("critical","high","medium","low","info"):
        cnt = len(by_sev[sev])
        if cnt == 0:
            continue
        c = SEV_COLOR.get(sev, GY)
        bar = "█" * min(cnt, 30)
        print(f"  {c}{sev.upper():<10}{R} {B}{cnt:>4}{R}  {c}{bar}{R}")

    print(f"{RD}{'─'*54}{R}\n")

    # top 5 worst findings
    worst = sorted(vuln_nodes,
                   key=lambda n: SEV_RANK.get(n["data"].get("severity","unknown"), 0),
                   reverse=True)[:5]
    if worst:
        print(f"  {B}Top findings:{R}")
        for n in worst:
            sev = n["data"].get("severity","?")
            c   = SEV_COLOR.get(sev, GY)
            tool= n["data"].get("tool","?")
            host= n["data"].get("host","?")
            print(f"  {c}[{sev.upper()}]{R}  {n['label'][:40]:<40}  {GY}{tool} @ {host}{R}")
    print()

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="vulnmap — vulnerability scanner for netmalper graphs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("graph",                help="netmalper graph.json")
    ap.add_argument("--out",                default=None)
    ap.add_argument("--nuclei-templates",   default="cves,misconfig,default-logins,exposed-panels")
    ap.add_argument("--nuclei-severity",    default="low",
                    choices=["info","low","medium","high","critical"])
    ap.add_argument("--nikto-tuning",       default="123457b")
    ap.add_argument("--openvas-host",       default="127.0.0.1")
    ap.add_argument("--openvas-port",       type=int, default=9390)
    ap.add_argument("--openvas-user",       default="admin")
    ap.add_argument("--openvas-pass",       default=os.environ.get("OPENVAS_PASS","admin"))
    ap.add_argument("--openvas-timeout",    type=int, default=600)
    ap.add_argument("--skip-nuclei",        action="store_true")
    ap.add_argument("--skip-nikto",         action="store_true")
    ap.add_argument("--skip-openvas",       action="store_true")
    ap.add_argument("--threads",            type=int, default=4)
    ap.add_argument("--dry-run",            action="store_true")
    args = ap.parse_args()

    out_path = args.out or args.graph

    # ── load graph ────────────────────────────────────────────────────────────
    if not os.path.exists(args.graph):
        log("err", f"Graph file not found: {args.graph}")
        sys.exit(1)

    data = load_graph(args.graph)
    g    = VulnGraph(data)

    # ── collect targets ───────────────────────────────────────────────────────
    all_hosts    = g.get_all_hosts()
    http_targets = g.get_http_targets()
    host_index   = build_host_index(g)

    host_list    = [h["host"] for h in all_hosts if h["host"]]
    nuclei_urls  = [t["url"] for t in http_targets]
    # nuclei also runs against non-HTTP hosts
    nuclei_targets = list(dict.fromkeys(nuclei_urls + host_list))

    banner(args.graph, len(all_hosts))
    log("info", f"Hosts      : {len(host_list)}")
    log("info", f"HTTP targets: {len(http_targets)}  "
                f"{GY}(nikto: port 80/443/8080/8443 only){R}")
    log("info", f"Nuclei targets: {len(nuclei_targets)}")

    if args.dry_run:
        log("warn", "DRY RUN mode — no commands will be executed")

    t0 = time.time()
    total_vulns = 0

    # ── nuclei ────────────────────────────────────────────────────────────────
    if not args.skip_nuclei:
        log("info", f"{'─'*48}")
        total_vulns += run_nuclei(nuclei_targets, g, args, host_index)

    # ── nikto (conditional on HTTP ports) ────────────────────────────────────
    if not args.skip_nikto:
        log("info", f"{'─'*48}")
        total_vulns += run_nikto(http_targets, g, args, host_index)

    # ── openvas ───────────────────────────────────────────────────────────────
    if not args.skip_openvas:
        log("info", f"{'─'*48}")
        total_vulns += run_openvas(host_list, g, args, host_index)

    # ── save ──────────────────────────────────────────────────────────────────
    duration = time.time() - t0
    g.update_meta(total_vulns, duration)
    save_graph(data, out_path)

    print_summary(g, duration)

if __name__ == "__main__":
    main()
