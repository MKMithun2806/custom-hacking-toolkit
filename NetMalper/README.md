🕸 netmalper — Graph-Based Recon Engine

netmalper is a next-generation reconnaissance framework that maps a target’s attack surface into an interactive graph. It combines active scanning, passive discovery, and intelligent correlation to transform raw network data into actionable insights.

«From a simple scan → to a living, queryable intelligence graph.»

---

 Overview

netmalper performs deep reconnaissance on a target and outputs a structured graph representing:

- Domains & subdomains
- DNS relationships (A, CNAME chains)
- IP infrastructure
- Open ports & services
- HTTP endpoints
- OS fingerprints
- Script findings (NSE)

This graph is visualized through a custom interactive UI, enabling intuitive exploration of complex attack surfaces.

---

✨ Features

🔍 Recon Capabilities

- Hybrid scanning using  + custom socket engine
- Subdomain enumeration (wordlist-based + DNS resolution)
- DNS chain traversal (CNAME → A records)
- Port & service detection
- HTTP endpoint probing
- OS fingerprinting (when privileged)
- NSE script extraction

---

🧠 Intelligence Layer

- Graph-based data modeling (nodes + relationships)
- Automatic merging of multi-source scan results
- Structured metadata for each asset
- Extensible architecture for enrichment & correlation

---

🎨 Visualization

- Custom force-directed graph engine (no external libraries)
- Interactive node exploration
- Search & filtering
- Node-type legend and highlighting
- Detailed inspection panel
- Smooth zoom / pan / drag

---

🏗 Architecture

netmalper is designed as a modular system:

Core

- Engine: orchestrates scans and merges results
- Graph: builds and manages node-edge relationships

Scanners

- Network scanning (nmap + socket fallback)
- DNS resolution
- Subdomain enumeration
- HTTP probing

Output

- JSON graph format
- Interactive HTML viewer

---

📦 Installation

Requirements

- Python 3.10+
- (optional but recommended)

Setup

1. Clone the repository
2. Install dependencies (if extended modules are added)
3. Ensure nmap is installed and available in PATH

---

⚡ Usage

Basic Scan

Run a scan against a target:

python netmalper.py example.com

---

Advanced Options

--ports        Custom port range
--threads      Parallel socket scanning
--timeout      Probe timeout
--no-nmap      Disable nmap
--no-socket    Disable socket scanner
--no-http      Skip HTTP probing
--no-subs      Skip subdomain enumeration
--no-dns       Skip DNS resolution

---

Example

python netmalper.py example.com --ports 1-1000 --threads 50

---

📊 Output

The scan produces a JSON graph file:

example.com_graph.json

Structure:

- meta → scan metadata
- nodes → entities (domains, IPs, ports, etc.)
- edges → relationships between entities

---

🌐 Visualization

Open the viewer:

1. Launch netmalper_viewer.html
2. Drag & drop the generated JSON file
3. Explore the graph interactively

---

🧩 Node Types

- root → primary target
- subdomain → discovered subdomains
- ip → resolved IP addresses
- port → open ports
- service → detected services
- endpoint → HTTP paths
- cname → DNS aliases
- dns_record → DNS entries
- os_guess → OS fingerprint
- nse_finding → script results

---

🔄 How It Works

1. Resolve target → DNS + subdomains
2. Map infrastructure → IPs
3. Scan ports → nmap + socket
4. Enrich services → versions + scripts
5. Probe HTTP → endpoints
6. Merge into graph → nodes + edges
7. Visualize → interactive UI

---

🧠 Design Goals

- Clarity over noise — visualize relationships, not just data
- Extensibility — plug in new scanners & enrichers
- Performance — parallel scanning + efficient merging
- Usability — intuitive graph exploration

---

🔐 Security & Ethics

This tool is intended for:

- Authorized penetration testing
- Bug bounty reconnaissance
- Personal infrastructure analysis

⚠️ Do not scan systems without permission.

---

🛣 Roadmap (v3 “God Mode”)

- Graph database integration (Neo4j)
- Continuous monitoring & diffing
- Risk scoring engine
- Vulnerability correlation (CVE mapping)
- Advanced query language
- Web-based dashboard
- AI-assisted analysis

---

🤝 Contributing

Contributions are welcome:

- New scanners
- Performance improvements
- UI enhancements
- Bug fixes

---

📜 License

MIT License (recommended)

---

💬 Final Note

netmalper is more than a scanner — it’s a recon intelligence platform designed to make complex attack surfaces understandable.

---
