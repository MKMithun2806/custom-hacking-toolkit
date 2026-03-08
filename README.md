# 🛠️ Custom Hacking Toolkit

![License](https://img.shields.io/badge/license-MIT-red.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20FlipperZero-black.svg)
![Status](https://img.shields.io/badge/version-1.0.0--beta-orange)

A collection of security tools, network scanners, and BadUSB payloads designed for penetration testing and educational exploration. Built and curated by **Mithun Krish**.

> **Disclaimer:** This toolkit is for educational purposes and authorized penetration testing only. Usage against systems without prior consent is illegal.

---

## 📂 Project Structure

### 📡 NSE Scanners
Custom Nmap Scripting Engine (NSE) scripts for advanced network reconnaissance and vulnerability detection.
* Port auditing
* Service version detection
* Vulnerability surface mapping

### 💻 REM Scripts (Remote Execution & Payloads)
This folder contains automated scripts for hardware-based attacks using the **Flipper Zero** (BadUSB).

#### 1. Reverse Shell Flipper
A PowerShell-based reverse shell payload that bypasses standard UI notifications by spoofing a Logitech hardware ID.
* **Payload:** Base64 Encoded PowerShell
* **Target:** Windows 10/11
* **Features:** Hidden window style, bypassed execution policies, and automated "Run" dialog cleanup.

#### 2. RickRoll-flipper
The ultimate ASCII-based prank.
* **Method:** Streams Rick Astley directly to the terminal via `curl`.
* **Impact:** Maximized window, forced focus, and persistent ASCII animation.

---

## 🚀 Getting Started

### Using the BadUSB Payloads
1.  Copy the `.txt` files from the `REM Scripts` directory to your Flipper Zero SD card:
    `SD Card -> badusb/`
2.  On your listener machine (for the Reverse Shell), start Netcat:
    ```bash
    nc -lvnp 8080
    ```
3.  Connect the Flipper to the target machine and execute the script.

### Using NSE Scanners
To use the custom scanners in this repo with Nmap:
```bash
nmap --script ./NSE-Scanners/your-script.nse <target-ip>
