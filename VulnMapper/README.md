# VulnMalper

**Vulnerability pipeline that eats [NetMalper](https://github.com/MKMithun2806/NetMalper) graphs.**

Fingerprint → Scan → Verify, with every stage feeding the next.

```
NetMalper JSON
    │
    ├── httpx        → all HTTP targets       (always — alive + tech)
    ├── whatweb      → all HTTP targets       (always — tech stack)
    ├── wafw00f      → all HTTP targets       (always — WAF detection)
    ├── testssl.sh   → port 443/8443 only     (TLS bugs)
    ├── nikto        → port 80/443/8080/8443  (web server misconfig)
    ├── nuclei       → all HTTP targets       (CVE / misconfig templates)
    ├── wapiti       → all HTTP targets       (active XSS/SSRF/RCE/XXE/LFI)
    └── sqlmap       → ONLY endpoints surfaced by upstream tools — no
                       blind spray.
```

Every tool runs **locally** if present, else via its **official Docker image** (auto-pulled).

Output: one clean **Markdown** report + a colored console summary. No JSON, no bloat.

---

## Install

### From .deb (recommended)

```bash
URL=$(curl -s https://api.github.com/repos/MKMithun2806/VulnMalper/releases/latest | grep browser_download_url | grep .deb | cut -d '"' -f 4) && \
curl -L -o vulnmalper.deb "$URL" && \
sudo apt install -y ./vulnmalper.deb && \
sudo apt-get install -f -y && \
rm -f vulnmalper.deb && \
vulnmalper --help
```

This drops `vulnmalper` on your `PATH`, a man page (`man vulnmalper`), and bash completion. Python 3.9+ is the only hard dep.

### From source

```bash
git clone https://github.com/MKMithun2806/VulnMalper
cd VulnMalper
python3 vulnmalper.py graph.json           # just run it
# or build your own .deb:
./build_deb.sh                             # needs dpkg-dev
```

### Scanner tools

You don't have to install any of them — `--runner auto` (default) will pull
Docker images for anything missing. If you want them local:

```bash
sudo apt install nikto sqlmap whatweb wafw00f
pip install wapiti3
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
git clone --depth 1 https://github.com/drwetter/testssl.sh.git \
  && sudo ln -s "$PWD/testssl.sh/testssl.sh" /usr/local/bin/testssl.sh
```

Docker images used when local binaries are missing:
`projectdiscovery/httpx`, `secsi/whatweb`, `secsi/wafw00f`,
`drwetter/testssl.sh`, `sullo/nikto`, `projectdiscovery/nuclei`,
`cyberwatch/wapiti`, `googlesky/sqlmap`.

## Usage

```bash
netmalper example.com --out example.json     # recon (NetMalper)
vulnmalper example.json                      # scan  (VulnMalper)
```

### Flags

| Flag | Effect |
|------|--------|
| `--runner auto` | **Default.** Local-first, Docker fallback, per tool. |
| `--runner local` | Skip any tool not installed locally. |
| `--runner docker` | Force Docker for every tool. |
| `--only nuclei,wapiti` | Restrict to a subset of pipeline stages. |
| `--severity medium` | Minimum severity kept from nuclei. |
| `--threads 5` | Parallel target workers. |
| `--max-targets 10` | Cap how many targets get scanned. |
| `--out NAME` | Writes `NAME.md`. Default: `vulnmalper_<target>_<ts>.md`. |
| `--httpx-timeout`, `--whatweb-timeout`, `--wafw00f-timeout`, `--testssl-timeout`, `--nikto-timeout`, `--nuclei-timeout`, `--wapiti-timeout`, `--sqlmap-timeout` | Per-tool timeouts (seconds). |

## How smart dispatch works

1. **Phase 1 — Fingerprint.** `httpx` probes liveness + tech on every URL. `whatweb` + `wafw00f` run in parallel on alive targets. Dead targets are dropped. WAF annotations are attached to each target.
2. **Phase 2 — Scan.** `testssl.sh` runs on TLS ports (443/8443) only. `nikto` runs on classic web ports (80/443/8080/8443) only. `nuclei` + `wapiti` run on every alive HTTP target. Injection-flavored URLs surfaced by these tools get queued for phase 3.
3. **Phase 3 — Verify.** `sqlmap` runs only against the curated queue — NetMalper's query-param endpoints + anything nuclei/nikto/wapiti surfaced as sqli/injection-tagged. No blind `?=` spraying.

## Building the .deb

```bash
./build_deb.sh                # reads VERSION from vulnmalper.py
./build_deb.sh 2.2.0          # override version
# → dist/vulnmalper_<version>_all.deb
```

Requires `dpkg-dev` (`sudo apt install dpkg-dev`). Optionally `fakeroot` for
clean ownership; the script auto-detects it.

## License

MIT. Pair it with NetMalper. Crush some boxes.
