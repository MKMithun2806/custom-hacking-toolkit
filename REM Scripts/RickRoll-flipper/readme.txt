# 🕺 ASCII Rickroll (BadUSB)
**Author:** Mithun Krish  
**Platform:** Windows  
**Payload:** ASCII-art stream of Rick Astley's "Never Gonna Give You Up"

## 🛠️ How it Works
1. **HID Spoofing:** Mimics a Logitech USB Keyboard to avoid "Device Setup" notifications.
2. **Execution:** Opens the Run dialog (`Win + R`) and executes a PowerShell command.
3. **The Trick:** It launches a maximized PowerShell window and uses `curl` to stream the ASCII animation from `ascii.live`.

## 🚀 Usage
1. Connect Flipper Zero to the target PC via USB.
2. Navigate to `BadUSB` -> `rickroll_ascii.txt`.
3. Press **Run**.
4. **Listener Note:** No listener is required for this; it is a purely client-side "visual" prank.

## ⚠️ Requirements
* Target must have internet access (to reach `ascii.live`).
* Target must be running Windows 10 or 11 (for native `curl` support).