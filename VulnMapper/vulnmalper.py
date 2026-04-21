#!/usr/bin/env python3
"""
VulnMalper v2.0  —  Vulnerability pipeline for NetMalper graphs.

Pipeline:
    NetMalper JSON
        │
        ├── httpx       → all HTTP targets       (always — tech + status)
        ├── whatweb     → all HTTP targets       (always — tech stack)
        ├── wafw00f     → all HTTP targets       (always — detects WAF)
        ├── testssl.sh  → 443 / 8443 only        (TLS config bugs)
        ├── nikto       → 80 / 443 / 8080 / 8443 (web server misconfig)
        ├── nuclei      → all HTTP targets       (CVE / misconfig templates)
        ├── wapiti      → all HTTP targets       (active XSS/SSRF/RCE/XXE/LFI)
        └── sqlmap      → only injectable-looking endpoints surfaced by
                          NetMalper (query params) OR by nuclei/nikto
                          (forms, reflected params). No blind spray.

Tools run locally when present, else via their official Docker image
(auto-fallback, `--runner auto` by default).

Pairs with: https://github.com/MKMithun2806/NetMalper

Usage:
    python3 vulnmalper.py <netmalper_graph.json> [options]
"""
from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

VERSION = "2.1.0"

# ── ANSI colors ─────────────────────────────────────────────────────────────
class C:
    R   = "\033[0m"; B = "\033[1m"; DIM = "\033[2m"
    RD  = "\033[31m"; GN = "\033[32m"; YL = "\033[33m"
    BL  = "\033[34m"; MG = "\033[35m"; CY = "\033[36m"; GY = "\033[90m"
    BG_RD = "\033[41m"

def _supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None

if not _supports_color():
    for k in list(vars(C)):
        if not k.startswith("_") and isinstance(getattr(C, k), str):
            setattr(C, k, "")

SEV_ORDER = {"critical":4, "high":3, "medium":2, "low":1, "info":0, "unknown":0}
SEV_BADGE = {
    "critical": C.BG_RD + C.B + " CRIT " + C.R,
    "high":     C.RD + C.B + " HIGH " + C.R,
    "medium":   C.YL + C.B + " MED  " + C.R,
    "low":      C.BL + " LOW  " + C.R,
    "info":     C.GY + " INFO " + C.R,
    "unknown":  C.GY + " ???? " + C.R,
}

def log(level: str, msg: str):
    tags = {
        "info": f"{C.CY}[*]{C.R}", "ok":   f"{C.GN}[+]{C.R}",
        "warn": f"{C.YL}[!]{C.R}", "err":  f"{C.RD}[x]{C.R}",
        "run":  f"{C.MG}[»]{C.R}", "skip": f"{C.GY}[~]{C.R}",
        "phase":f"{C.MG}{C.B}▶{C.R}",
    }
    print(f"{tags.get(level,'[?]')} {msg}", flush=True)

def banner():
    print(f"""{C.MG}{C.B}
 ╔══════════════════════════════════════════════════════╗
 ║   V u l n M a l p e r    v{VERSION}                       ║
 ║   fingerprint → scan → exploit-verify   pipeline     ║
 ║   httpx · whatweb · wafw00f · testssl · nikto        ║
 ║   nuclei · wapiti · sqlmap                           ║
 ║   local OR docker, auto-fallback                     ║
 ╚══════════════════════════════════════════════════════╝{C.R}
""")

# ── Data classes ────────────────────────────────────────────────────────────
@dataclass
class Finding:
    target:    str
    tool:      str
    severity:  str
    title:     str
    detail:    str = ""
    reference: str = ""
    raw:       dict = field(default_factory=dict)
    def key(self): return (self.target, self.tool, self.title.lower())

@dataclass
class WebTarget:
    url:       str
    host:      str
    port:      int
    scheme:    str
    service:   str = "http"
    product:   str = ""
    has_query: bool = False
    src_node:  str = ""
    # filled in by fingerprinting phase:
    alive:     bool = False
    status:    Optional[int] = None
    tech:      list[str] = field(default_factory=list)
    waf:       Optional[str] = None
    # injectable URLs discovered by upstream tools (nikto/nuclei) during scan:
    injectable: list[str] = field(default_factory=list)

# ── NetMalper graph parsing ─────────────────────────────────────────────────
WEB_SERVICES = {"http","https","http-proxy","https-alt","http-alt"}
WEB_PORTS    = {80,81,443,591,2082,2083,2086,2087,2095,2096,
                3000,5000,7001,7002,8000,8008,8080,8081,8088,
                8090,8443,8888,9000,9001,9090,9443}
NIKTO_PORTS  = {80,443,8080,8443}
TLS_PORTS    = {443,8443}

def _best_hostname_for_ip(ip: str, nodes: dict) -> Optional[str]:
    for n in nodes.values():
        if n["type"] in ("sub","root","cname"):
            fqdn = n["data"].get("fqdn") or n.get("label")
            if not fqdn: continue
            try:
                if socket.gethostbyname(fqdn) == ip: return fqdn
            except Exception: continue
    return None

def parse_netmalper(graph: dict):
    nodes = {n["id"]: n for n in graph.get("nodes", [])}
    meta  = graph.get("meta", {})
    targets: dict[str, WebTarget] = {}

    for n in nodes.values():
        if n["type"] != "endpoint": continue
        url = n["data"].get("url")
        if not url: continue
        p = urllib.parse.urlparse(url)
        port = p.port or (443 if p.scheme == "https" else 80)
        targets.setdefault(url, WebTarget(
            url=url, host=p.hostname or "", port=port, scheme=p.scheme,
            service=p.scheme, has_query=bool(p.query), src_node=n["id"],
        ))

    for n in nodes.values():
        if n["type"] != "port": continue
        d = n["data"]
        port = d.get("port"); svc = (d.get("service") or "").lower()
        host = d.get("host") or ""
        if not host or not port: continue
        looks_web = svc in WEB_SERVICES or port in WEB_PORTS or "http" in svc
        if not looks_web: continue
        scheme = "https" if (svc == "https" or port in (443,8443,9443)) else "http"
        host_label = _best_hostname_for_ip(host, nodes) or host
        url = f"{scheme}://{host_label}" + (f":{port}" if port not in (80,443) else "") + "/"
        targets.setdefault(url, WebTarget(
            url=url, host=host_label, port=port, scheme=scheme,
            service=svc or scheme, product=d.get("product",""),
            src_node=n["id"],
        ))
    return list(targets.values()), meta

# ── Runner layer (local + docker) ───────────────────────────────────────────
ALL_TOOLS = ["httpx","whatweb","wafw00f","testssl","nikto",
             "nuclei","wapiti","sqlmap"]

DOCKER_IMAGES = {
    "httpx":   "projectdiscovery/httpx:latest",
    "whatweb": "secsi/whatweb:latest",
    "wafw00f": "secsi/wafw00f:latest",
    "testssl": "drwetter/testssl.sh:latest",
    "nikto":   "sullo/nikto:latest",
    "nuclei":  "projectdiscovery/nuclei:latest",
    "wapiti":  "cyberwatch/wapiti:latest",
    "sqlmap":  "googlesky/sqlmap:latest",
}
# Some tools publish their binary under a different name inside the image:
DOCKER_ENTRYPOINTS = {
    # "testssl" image has /bin/bash entrypoint; we'll prepend the script name.
    # All others have sensible default entrypoints.
}
LOCAL_BINARIES = {
    "httpx":   "httpx",
    "whatweb": "whatweb",
    "wafw00f": "wafw00f",
    "testssl": "testssl.sh",
    "nikto":   "nikto",
    "nuclei":  "nuclei",
    "wapiti":  "wapiti",
    "sqlmap":  "sqlmap",
}

def have(cmd: str) -> bool:
    return shutil.which(cmd) is not None

def docker_available() -> bool:
    if not have("docker"): return False
    try:
        p = subprocess.run(["docker","info"], capture_output=True, text=True, timeout=8)
        return p.returncode == 0
    except Exception:
        return False

@dataclass
class ToolPlan:
    name:   str
    runner: str
    image:  Optional[str] = None

def plan_tools(runner_pref: str) -> dict[str, Optional[ToolPlan]]:
    docker_ok = docker_available()
    out: dict[str, Optional[ToolPlan]] = {}
    for name in ALL_TOOLS:
        bin_name  = LOCAL_BINARIES[name]
        local_ok  = have(bin_name)
        plan: Optional[ToolPlan] = None
        if runner_pref == "local":
            if local_ok: plan = ToolPlan(name, "local")
        elif runner_pref == "docker":
            if docker_ok: plan = ToolPlan(name, "docker", DOCKER_IMAGES[name])
        else:  # auto
            if local_ok:
                plan = ToolPlan(name, "local")
            elif docker_ok:
                plan = ToolPlan(name, "docker", DOCKER_IMAGES[name])
        out[name] = plan
    return out

def ensure_docker_image(image: str):
    try:
        subprocess.run(["docker","image","inspect",image],
                       capture_output=True, timeout=10, check=True)
        return True
    except subprocess.CalledProcessError:
        log("info", f"Pulling docker image: {image}")
        try:
            subprocess.run(["docker","pull",image], timeout=600, check=True)
            return True
        except Exception as e:
            log("err", f"docker pull {image} failed: {e}")
            return False
    except Exception:
        return False

def _run(cmd, timeout, stdin_data: Optional[str] = None):
    try:
        p = subprocess.run(cmd, input=stdin_data, capture_output=True,
                           text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s"
    except FileNotFoundError as e:
        return 127, "", str(e)
    except Exception as e:
        return 1, "", str(e)

def build_cmd(plan: ToolPlan, tool_args: list[str],
              mount: Optional[tuple[str,str]] = None,
              extra_docker: Optional[list[str]] = None,
              local_binary: Optional[str] = None) -> list[str]:
    """Build the final subprocess command for either runner."""
    if plan.runner == "local":
        return [local_binary or LOCAL_BINARIES[plan.name]] + tool_args
    docker = ["docker","run","--rm","-i","--network","host"]
    if mount:
        host, container = mount
        os.makedirs(host, exist_ok=True)
        docker += ["-v", f"{host}:{container}"]
    if extra_docker:
        docker += extra_docker
    docker += [plan.image]
    return docker + tool_args

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 1 — FINGERPRINTING (always runs on every HTTP target)
# ────────────────────────────────────────────────────────────────────────────
def run_httpx(targets: list[WebTarget], plan: ToolPlan, timeout: int):
    """Probe alive + fingerprint tech/server/status for every target."""
    urls = "\n".join(t.url for t in targets)
    args = ["-silent","-json","-nc","-no-color","-timeout","10",
            "-tech-detect","-status-code","-title","-server","-follow-redirects"]
    cmd  = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout, stdin_data=urls)
    by_url = {t.url: t for t in targets}
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"): continue
        try: j = json.loads(line)
        except Exception: continue
        u = j.get("url") or j.get("input") or ""
        t = by_url.get(u)
        # some httpx builds normalize trailing slashes etc.
        if not t:
            for k, v in by_url.items():
                if k.rstrip("/") == u.rstrip("/"): t = v; break
        if not t: continue
        t.alive  = True
        t.status = j.get("status_code") or j.get("status-code")
        techs    = j.get("tech") or j.get("technologies") or []
        if isinstance(techs, list): t.tech = [str(x) for x in techs]
        server   = j.get("webserver") or j.get("server") or ""
        title    = j.get("title") or ""
        detail_parts = []
        if server: detail_parts.append(f"server={server}")
        if t.tech: detail_parts.append("tech=" + ", ".join(t.tech))
        if title:  detail_parts.append(f"title={title[:80]}")
        findings.append(Finding(
            target=t.url, tool="httpx", severity="info",
            title=f"Alive ({t.status}) — {server or 'unknown server'}",
            detail=" · ".join(detail_parts), raw=j,
        ))
    return findings

def run_whatweb(t: WebTarget, plan: ToolPlan, timeout: int):
    args = ["--color=never","--log-json=-","-a","1",t.url]
    cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("["): continue
        try: arr = json.loads(line)
        except Exception: continue
        for entry in arr if isinstance(arr, list) else [arr]:
            plugins = entry.get("plugins") or {}
            names = []
            for pname, pdata in plugins.items():
                versions = (pdata or {}).get("version") or []
                if versions:
                    names.append(f"{pname} {versions[0]}")
                else:
                    names.append(pname)
            for n in names:
                if n and n not in t.tech:
                    t.tech.append(n)
            if names:
                findings.append(Finding(
                    target=t.url, tool="whatweb", severity="info",
                    title=f"Tech: {', '.join(names[:8])}" + (" …" if len(names) > 8 else ""),
                    detail=", ".join(names), raw=entry,
                ))
    return findings

def run_wafw00f(t: WebTarget, plan: ToolPlan, timeout: int):
    host_dir = f"/tmp/vulnmalper_waf_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    out_name = "waf.json"
    if plan.runner == "docker":
        container_dir = "/wrk"
        out_path = f"{container_dir}/{out_name}"
        args = [t.url, "-a", "-o", out_path, "-f", "json"]
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        out_path = os.path.join(host_dir, out_name)
        args = [t.url, "-a", "-o", out_path, "-f", "json"]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, out_name)
    detected_waf = None
    if os.path.exists(host_out):
        try:
            with open(host_out) as f:
                data = json.load(f)
            entries = data if isinstance(data, list) else [data]
            for e in entries:
                if e.get("detected") and e.get("firewall"):
                    detected_waf = e.get("firewall")
                    break
        except Exception: pass
    else:
        # fallback: parse "[+] The site X is behind Y WAF"
        m = re.search(r"behind\s+(.+?)\s+WAF", out, re.I)
        if m: detected_waf = m.group(1).strip()
    if detected_waf:
        t.waf = detected_waf
        findings.append(Finding(
            target=t.url, tool="wafw00f", severity="info",
            title=f"WAF detected: {detected_waf}",
            detail=f"Scanners downstream (sqlmap, wapiti) may be throttled or blocked by {detected_waf}.",
        ))
    else:
        findings.append(Finding(
            target=t.url, tool="wafw00f", severity="info",
            title="No WAF detected", detail="",
        ))
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 2 — SCANNING
# ────────────────────────────────────────────────────────────────────────────
def run_testssl(t: WebTarget, plan: ToolPlan, timeout: int):
    """Only called on TLS ports (443/8443)."""
    host_dir = f"/tmp/vulnmalper_tls_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    target = f"{t.host}:{t.port}"
    out_name = "tls.json"
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["--quiet","--color","0","--jsonfile",
                f"{container_dir}/{out_name}", target]
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        args = ["--quiet","--color","0","--jsonfile",
                os.path.join(host_dir, out_name), target]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, out_name)
    sev_map = {"OK":"info","INFO":"info","LOW":"low","MEDIUM":"medium",
               "HIGH":"high","CRITICAL":"critical","WARN":"low"}
    if os.path.exists(host_out):
        try:
            with open(host_out) as f:
                data = json.load(f)
            entries = data if isinstance(data, list) else data.get("scanResult", [])
            for e in entries:
                sev_raw = (e.get("severity") or "").upper()
                sev = sev_map.get(sev_raw, "info")
                if sev == "info": continue  # keep noise down
                findings.append(Finding(
                    target=t.url, tool="testssl", severity=sev,
                    title=e.get("id") or "TLS finding",
                    detail=e.get("finding") or "",
                    reference=e.get("cve") or e.get("cwe") or "",
                    raw=e,
                ))
        except Exception as ex:
            log("warn", f"testssl JSON parse failed: {ex}")
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

NIKTO_SEV_HINTS = [
    (re.compile(r"\b(rce|remote code|sql injection|sqli|shell upload|directory traversal)\b", re.I), "high"),
    (re.compile(r"\b(xss|csrf|open redirect|file inclusion|lfi|rfi|exposed)\b", re.I), "medium"),
    (re.compile(r"\b(missing|outdated|deprecated|default|insecure header)\b", re.I), "low"),
]
def _classify_nikto(text):
    for pat, sev in NIKTO_SEV_HINTS:
        if pat.search(text): return sev
    return "info"

def run_nikto(t: WebTarget, plan: ToolPlan, timeout: int):
    host_dir = f"/tmp/vulnmalper_nikto_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    out_name = "nikto.json"
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-h", t.url, "-Format","json","-output",
                f"{container_dir}/{out_name}",
                "-ask","no","-nointeractive","-maxtime", str(min(timeout, 600))]
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        args = ["-h", t.url, "-Format","json","-output",
                os.path.join(host_dir, out_name),
                "-ask","no","-nointeractive","-maxtime", str(min(timeout, 600))]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout + 30)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, out_name)
    if os.path.exists(host_out):
        try:
            with open(host_out) as f:
                data = json.load(f)
            vulns = data.get("vulnerabilities",[]) if isinstance(data,dict) else []
            for v in vulns:
                msg = v.get("msg") or v.get("message") or ""
                sev = _classify_nikto(msg + " " + str(v.get("OSVDB","")))
                u   = v.get("url","") or ""
                target = t.url + (u if u.startswith("/") else "")
                findings.append(Finding(
                    target=target, tool="nikto", severity=sev,
                    title=msg[:140] if msg else "nikto finding",
                    detail=msg,
                    reference=str(v.get("OSVDB","")) or v.get("references","") or "",
                    raw=v,
                ))
                # Feed sqlmap: any path with a query string is a candidate.
                if "?" in target and target not in t.injectable:
                    t.injectable.append(target)
        except Exception as e:
            log("warn", f"nikto JSON parse failed for {t.url}: {e}")
    if not findings and out:
        for line in out.splitlines():
            if line.startswith("+ ") and ":" in line:
                msg = line[2:].strip()
                if msg.startswith(("Target IP","Target Host","Target Port",
                                   "Start Time","End Time","Server:","Host:")):
                    continue
                findings.append(Finding(
                    target=t.url, tool="nikto",
                    severity=_classify_nikto(msg),
                    title=msg[:140], detail=msg,
                ))
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

def run_nuclei(t: WebTarget, plan: ToolPlan, severity: str, timeout: int):
    sev_chain = ["info","low","medium","high","critical"]
    keep = sev_chain[max(0, sev_chain.index(severity)):] if severity in sev_chain else sev_chain
    args = ["-u", t.url, "-jsonl","-silent","-nc",
            "-severity", ",".join(keep),
            "-timeout","10","-rl","150","-disable-update-check"]
    cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    INJ_TAGS = {"sqli","sql-injection","injection","xss","ssti","lfi","rfi"}
    for line in out.splitlines():
        line = line.strip()
        if not line.startswith("{"): continue
        try: j = json.loads(line)
        except Exception: continue
        info = j.get("info", {})
        sev  = (info.get("severity") or "unknown").lower()
        tags = set(info.get("tags") or [])
        matched = j.get("matched-at") or t.url
        findings.append(Finding(
            target=matched, tool="nuclei", severity=sev,
            title=info.get("name") or j.get("template-id") or "nuclei finding",
            detail=(info.get("description") or "").strip(),
            reference=", ".join(info.get("reference") or []),
            raw=j,
        ))
        # Feed sqlmap when nuclei points at an injection-flavored URL w/ params.
        if (tags & INJ_TAGS) and "?" in matched and matched not in t.injectable:
            t.injectable.append(matched)
    if rc != 0 and not findings and err:
        log("warn", f"nuclei: {err.strip().splitlines()[-1] if err.strip() else 'no output'}")
    return findings

WAPITI_SEV_MAP = {1:"low",2:"medium",3:"high",4:"critical",0:"info",
                  "Low":"low","Medium":"medium","High":"high",
                  "Critical":"critical","Informational":"info"}

def run_wapiti(t: WebTarget, plan: ToolPlan, timeout: int):
    host_dir = f"/tmp/vulnmalper_wapiti_{abs(hash(t.url))}"
    os.makedirs(host_dir, exist_ok=True)
    report = "report.json"
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-u", t.url, "-f","json","-o", f"{container_dir}/{report}",
                "--flush-session","--level","1",
                "--max-scan-time", str(min(timeout, 1200)), "-S","paranoid"]
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        args = ["-u", t.url, "-f","json","-o", os.path.join(host_dir, report),
                "--flush-session","--level","1",
                "--max-scan-time", str(min(timeout, 1200)), "-S","paranoid"]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout + 30)
    findings: list[Finding] = []
    host_out = os.path.join(host_dir, report)
    if os.path.exists(host_out):
        try:
            with open(host_out) as f: data = json.load(f)
            vulns = data.get("vulnerabilities", {}) or {}
            for category, items in vulns.items():
                for it in items or []:
                    lvl = it.get("level", it.get("severity", 0))
                    sev = WAPITI_SEV_MAP.get(lvl, "unknown")
                    info_ = it.get("info") or it.get("description") or ""
                    method = it.get("method") or ""
                    path   = it.get("path") or ""
                    param  = it.get("parameter") or it.get("parameter_name") or ""
                    full_url = t.url.rstrip("/") + path if path.startswith("/") else (path or t.url)
                    findings.append(Finding(
                        target=full_url, tool="wapiti", severity=sev,
                        title=f"{category}" + (f" on `{param}`" if param else ""),
                        detail=(f"{method} {path}\n{info_}").strip(),
                        raw=it,
                    ))
                    if "sql" in category.lower() and "?" in full_url and full_url not in t.injectable:
                        t.injectable.append(full_url)
        except Exception as e:
            log("warn", f"wapiti JSON parse failed for {t.url}: {e}")
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

# ────────────────────────────────────────────────────────────────────────────
#  PHASE 3 — VERIFY (sqlmap, only on endpoints upstream flagged)
# ────────────────────────────────────────────────────────────────────────────
def run_sqlmap(url: str, plan: ToolPlan, timeout: int):
    host_dir = f"/tmp/vulnmalper_sqlmap_{abs(hash(url))}"
    os.makedirs(host_dir, exist_ok=True)
    if plan.runner == "docker":
        container_dir = "/wrk"
        args = ["-u", url, "--batch","--disable-coloring",
                "--level","2","--risk","1","--smart",
                "--output-dir", container_dir,
                "--timeout","15","--retries","1","--technique","BEUSTQ"]
        cmd = build_cmd(plan, args, mount=(host_dir, container_dir))
    else:
        args = ["-u", url, "--batch","--disable-coloring",
                "--level","2","--risk","1","--smart",
                "--output-dir", host_dir,
                "--timeout","15","--retries","1","--technique","BEUSTQ"]
        cmd = build_cmd(plan, args)
    rc, out, err = _run(cmd, timeout)
    findings: list[Finding] = []
    text = out + "\n" + err
    blocks = re.findall(
        r"Parameter:\s*(.+?)\n\s*Type:\s*(.+?)\n\s*Title:\s*(.+?)\n\s*Payload:\s*(.+?)(?:\n\s*\n|\Z)",
        text, re.S,
    )
    for param, typ, title, payload in blocks:
        findings.append(Finding(
            target=url, tool="sqlmap", severity="critical",
            title=f"SQL Injection ({typ.strip()}) on `{param.strip()}`",
            detail=f"Title: {title.strip()}\nPayload: {payload.strip()}",
            reference="https://owasp.org/www-community/attacks/SQL_Injection",
        ))
    if not findings and "is not injectable" in text.lower():
        log("skip", f"sqlmap: no injectable params on {url}")
    shutil.rmtree(host_dir, ignore_errors=True)
    return findings

# ── Reporting ───────────────────────────────────────────────────────────────
def _summary(findings):
    by_sev, by_tool = {}, {}
    for f in findings:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
        by_tool[f.tool]    = by_tool.get(f.tool, 0) + 1
    return {"total": len(findings), "by_severity": by_sev, "by_tool": by_tool}

def render_console(findings, targets, meta, duration, runner_map):
    seen, uniq = set(), []
    for f in findings:
        k = f.key()
        if k in seen: continue
        seen.add(k); uniq.append(f)
    uniq.sort(key=lambda f: -SEV_ORDER.get(f.severity, 0))

    counts, by_tool = {}, {}
    for f in uniq:
        counts[f.severity] = counts.get(f.severity, 0) + 1
        by_tool[f.tool]    = by_tool.get(f.tool, 0) + 1

    line = C.GY + "─" * 64 + C.R
    print(); print(line)
    print(f"  {C.B}{C.MG}VulnMalper Report{C.R}  ·  source: {C.CY}{meta.get('target','?')}{C.R}")
    print(line)
    print(f"  Web targets scanned : {C.B}{len(targets)}{C.R}")
    print(f"  Total findings      : {C.B}{len(uniq)}{C.R}  (raw: {len(findings)})")
    print(f"  Duration            : {C.B}{duration:.1f}s{C.R}")
    print(f"  Tools used          : {C.B}{', '.join(by_tool) or 'none'}{C.R}")
    print()
    print(f"  {C.B}Severity breakdown{C.R}")
    for sev in ("critical","high","medium","low","info"):
        n = counts.get(sev, 0); bar = "█" * min(n, 40)
        col = {"critical":C.RD,"high":C.RD,"medium":C.YL,"low":C.BL,"info":C.GY}[sev]
        print(f"    {SEV_BADGE[sev]} {n:>3}  {col}{bar}{C.R}")
    print(line)
    print(f"  {C.B}Per-target fingerprint{C.R}")
    for t in targets:
        tags = []
        if t.alive: tags.append(f"{C.GN}alive {t.status}{C.R}")
        else:       tags.append(f"{C.RD}dead{C.R}")
        if t.tech:  tags.append(f"tech=[{', '.join(t.tech[:4])}{'…' if len(t.tech)>4 else ''}]")
        if t.waf:   tags.append(f"{C.YL}WAF={t.waf}{C.R}")
        if t.injectable: tags.append(f"{C.MG}injectable×{len(t.injectable)}{C.R}")
        print(f"    {C.CY}{t.url:<55}{C.R}  " + " · ".join(tags))
    print(line)

    if not uniq:
        print(f"  {C.GN}No vulnerabilities detected. Clean run.{C.R}"); print(line); return

    by_target: dict[str,list[Finding]] = {}
    for f in uniq: by_target.setdefault(f.target.split("?")[0], []).append(f)
    for tgt, fs in by_target.items():
        print()
        print(f"  {C.B}{C.CY}● {tgt}{C.R}  {C.GY}({len(fs)} findings){C.R}")
        for f in fs[:30]:
            print(f"    {SEV_BADGE[f.severity]} {C.DIM}[{f.tool}]{C.R} {f.title}")
            if f.detail and f.detail != f.title:
                first = f.detail.strip().splitlines()[0][:140]
                print(f"        {C.GY}{first}{C.R}")
            if f.reference:
                print(f"        {C.GY}↳ {f.reference[:140]}{C.R}")
        if len(fs) > 30:
            print(f"    {C.GY}… and {len(fs)-30} more (see report file){C.R}")
    print(); print(line)


def write_markdown(path, findings, targets, meta, duration, runner_map):
    summary = _summary(findings)
    L = ["# VulnMalper Report", "",
         f"- **Source target:** `{meta.get('target','?')}`",
         f"- **Generated:** {datetime.now(timezone.utc).isoformat()}",
         f"- **Web targets scanned:** {len(targets)}",
         f"- **Total findings:** {summary['total']}",
         f"- **Duration:** {duration:.1f}s",
         f"- **Runners:** " + ", ".join(f"`{k}`→{v}" for k,v in runner_map.items()),
         "", "## Target fingerprints", "",
         "| URL | Alive | Tech | WAF | Injectable |",
         "|-----|-------|------|-----|------------|"]
    for t in targets:
        L.append(f"| `{t.url}` | {t.status or 'n/a'} | "
                 f"{', '.join(t.tech[:4]) or '—'} | {t.waf or '—'} | {len(t.injectable)} |")
    L += ["", "## Severity breakdown", "",
          "| Severity | Count |", "|----------|-------|"]
    for sev in ("critical","high","medium","low","info"):
        L.append(f"| {sev.title()} | {summary['by_severity'].get(sev,0)} |")
    L += ["", "## Findings by target"]
    by_target: dict[str,list[Finding]] = {}
    for f in findings: by_target.setdefault(f.target.split("?")[0], []).append(f)
    for tgt, fs in by_target.items():
        L += ["", f"### `{tgt}`  _( {len(fs)} findings )_", "",
              "| Severity | Tool | Title |", "|----------|------|-------|"]
        fs.sort(key=lambda f: -SEV_ORDER.get(f.severity, 0))
        for f in fs:
            title = f.title.replace("|", "\\|")[:160]
            L.append(f"| **{f.severity}** | {f.tool} | {title} |")
        for f in fs:
            if f.detail or f.reference:
                L += ["", f"<details><summary>{f.severity.upper()} · {f.tool} · {f.title[:80]}</summary>", ""]
                if f.detail:    L.append("```\n" + f.detail + "\n```")
                if f.reference: L.append(f"**Reference:** {f.reference}")
                L.append("</details>")
    with open(path, "w") as f: f.write("\n".join(L))

# ── Main pipeline ──────────────────────────────────────────────────────────
def _phase(label: str):
    print()
    log("phase", f"{C.B}{label}{C.R}")

def main():
    ap = argparse.ArgumentParser(
        prog="vulnmalper",
        description="Vulnerability pipeline for NetMalper graphs.",
    )
    ap.add_argument("input", help="NetMalper JSON graph")
    ap.add_argument("--out", default=None)
    ap.add_argument("--only", default="",
                    help=f"Comma list restricting stages: {','.join(ALL_TOOLS)}")
    ap.add_argument("--runner", default="auto", choices=["auto","local","docker"])
    ap.add_argument("--severity", default="low",
                    choices=["info","low","medium","high","critical"],
                    help="Minimum severity for nuclei (default: low)")
    ap.add_argument("--threads", type=int, default=3,
                    help="Parallel per-target workers in scan phase")
    ap.add_argument("--max-targets", type=int, default=0)
    ap.add_argument("--httpx-timeout",    type=int, default=120)
    ap.add_argument("--whatweb-timeout",  type=int, default=120)
    ap.add_argument("--wafw00f-timeout",  type=int, default=120)
    ap.add_argument("--testssl-timeout",  type=int, default=600)
    ap.add_argument("--nikto-timeout",    type=int, default=600)
    ap.add_argument("--nuclei-timeout",   type=int, default=600)
    ap.add_argument("--wapiti-timeout",   type=int, default=1200)
    ap.add_argument("--sqlmap-timeout",   type=int, default=900)
    args = ap.parse_args()

    banner()

    in_path = Path(args.input)
    if not in_path.exists():
        log("err", f"Input file not found: {in_path}"); sys.exit(2)
    try:
        with open(in_path) as f: graph = json.load(f)
    except Exception as e:
        log("err", f"Failed to read NetMalper JSON: {e}"); sys.exit(2)

    targets, meta = parse_netmalper(graph)
    log("info", f"Loaded NetMalper graph for {C.B}{meta.get('target','?')}{C.R} "
                f"({len(graph.get('nodes',[]))} nodes)")
    if not targets:
        log("warn", "No web targets discovered. Nothing to scan."); sys.exit(0)
    if args.max_targets and len(targets) > args.max_targets:
        log("warn", f"Capping {len(targets)} → {args.max_targets} targets")
        targets = targets[:args.max_targets]

    # Seed injectable URLs from NetMalper's endpoint findings (already has ?params)
    for t in targets:
        if t.has_query and t.url not in t.injectable:
            t.injectable.append(t.url)

    plans = plan_tools(args.runner)
    only  = {x.strip().lower() for x in args.only.split(",") if x.strip()}
    if only:
        for name in list(plans):
            if name not in only: plans[name] = None
        log("info", f"Restricted to: {', '.join(sorted(only))}")

    parts = []
    for name in ALL_TOOLS:
        p = plans.get(name)
        parts.append(f"{name}:{C.RD}off{C.R}" if p is None
                     else f"{name}:{C.GN}{p.runner}{C.R}")
    log("info", "Tool plan: " + "  ".join(parts))

    for name, p in plans.items():
        if p and p.runner == "docker":
            ensure_docker_image(p.image)
    runner_map = {k: (v.runner if v else "off") for k, v in plans.items()}

    timeouts = {
        "httpx": args.httpx_timeout, "whatweb": args.whatweb_timeout,
        "wafw00f": args.wafw00f_timeout, "testssl": args.testssl_timeout,
        "nikto": args.nikto_timeout, "nuclei": args.nuclei_timeout,
        "wapiti": args.wapiti_timeout, "sqlmap": args.sqlmap_timeout,
    }

    all_findings: list[Finding] = []
    t0 = time.time()

    # ── PHASE 1: fingerprint ───────────────────────────────────────────────
    _phase("Phase 1 — Fingerprinting (httpx, whatweb, wafw00f)")

    if plans["httpx"]:
        log("run", f"httpx ({plans['httpx'].runner}) on {len(targets)} target(s)")
        fs = run_httpx(targets, plans["httpx"], timeouts["httpx"])
        log("ok", f"  httpx → {len(fs)} findings")
        all_findings.extend(fs)
    else:
        log("skip", "httpx unavailable — marking all targets as alive (no tech data)")
        for t in targets: t.alive = True

    def _fp_worker(t: WebTarget):
        out: list[Finding] = []
        if plans["whatweb"]:
            out.extend(run_whatweb(t, plans["whatweb"], timeouts["whatweb"]))
        if plans["wafw00f"]:
            out.extend(run_wafw00f(t, plans["wafw00f"], timeouts["wafw00f"]))
        return out

    if plans["whatweb"] or plans["wafw00f"]:
        alive = [t for t in targets if t.alive]
        log("run", f"whatweb/wafw00f on {len(alive)} alive target(s)")
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fs in ex.map(_fp_worker, alive):
                all_findings.extend(fs)

    # ── PHASE 2: scan ──────────────────────────────────────────────────────
    _phase("Phase 2 — Scanning (testssl, nikto, nuclei, wapiti)")

    def _scan_worker(t: WebTarget):
        out: list[Finding] = []
        if not t.alive:
            log("skip", f"{t.url} — dead/unreachable, skipping scan")
            return out
        # testssl only for TLS ports
        if plans["testssl"] and t.port in TLS_PORTS:
            log("run", f"testssl ({plans['testssl'].runner}) → {t.url}")
            tt = time.time()
            fs = run_testssl(t, plans["testssl"], timeouts["testssl"])
            log("ok" if fs else "skip",
                f"  testssl {round(time.time()-tt,1)}s — {len(fs)} findings")
            out.extend(fs)
        # nikto only on classic web ports
        if plans["nikto"] and t.port in NIKTO_PORTS:
            log("run", f"nikto ({plans['nikto'].runner}) → {t.url}")
            tt = time.time()
            fs = run_nikto(t, plans["nikto"], timeouts["nikto"])
            log("ok" if fs else "skip",
                f"  nikto {round(time.time()-tt,1)}s — {len(fs)} findings")
            out.extend(fs)
        # nuclei on all HTTP targets
        if plans["nuclei"]:
            log("run", f"nuclei ({plans['nuclei'].runner}) → {t.url}")
            tt = time.time()
            fs = run_nuclei(t, plans["nuclei"], args.severity, timeouts["nuclei"])
            log("ok" if fs else "skip",
                f"  nuclei {round(time.time()-tt,1)}s — {len(fs)} findings")
            out.extend(fs)
        # wapiti — active app scanner, all HTTP targets
        if plans["wapiti"]:
            log("run", f"wapiti ({plans['wapiti'].runner}) → {t.url}")
            tt = time.time()
            fs = run_wapiti(t, plans["wapiti"], timeouts["wapiti"])
            log("ok" if fs else "skip",
                f"  wapiti {round(time.time()-tt,1)}s — {len(fs)} findings")
            out.extend(fs)
        return out

    if args.threads <= 1:
        for t in targets: all_findings.extend(_scan_worker(t))
    else:
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as ex:
            for fs in ex.map(_scan_worker, targets):
                all_findings.extend(fs)

    # ── PHASE 3: sqlmap verification on curated endpoints ──────────────────
    _phase("Phase 3 — Verifying SQLi candidates (sqlmap)")

    sqli_queue: list[str] = []
    for t in targets:
        for u in t.injectable:
            if u not in sqli_queue:
                sqli_queue.append(u)

    if not plans["sqlmap"]:
        log("skip", "sqlmap unavailable — skipping phase 3")
    elif not sqli_queue:
        log("skip", "No injectable endpoints surfaced by upstream tools")
    else:
        log("info", f"{len(sqli_queue)} endpoint(s) flagged for sqlmap verification:")
        for u in sqli_queue: print(f"  {C.GY}•{C.R} {u}")
        def _sqli_worker(u):
            log("run", f"sqlmap ({plans['sqlmap'].runner}) → {u}")
            tt = time.time()
            fs = run_sqlmap(u, plans["sqlmap"], timeouts["sqlmap"])
            log("ok" if fs else "skip",
                f"  sqlmap {round(time.time()-tt,1)}s — {len(fs)} findings")
            return fs
        if args.threads <= 1:
            for u in sqli_queue: all_findings.extend(_sqli_worker(u))
        else:
            with concurrent.futures.ThreadPoolExecutor(max_workers=min(args.threads,3)) as ex:
                for fs in ex.map(_sqli_worker, sqli_queue):
                    all_findings.extend(fs)

    duration = time.time() - t0

    base = args.out
    if not base:
        stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe  = re.sub(r"[^A-Za-z0-9_.-]+", "_", meta.get("target","target"))
        base  = f"vulnmalper_{safe}_{stamp}"
    write_markdown(base + ".md", all_findings, targets, meta, duration, runner_map)

    render_console(all_findings, targets, meta, duration, runner_map)
    log("ok", f"Report written to {C.B}{base}.md{C.R}")

if __name__ == "__main__":
    main()
