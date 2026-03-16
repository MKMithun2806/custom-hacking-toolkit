let gui = require("gui");
let keyboard = require("keyboard");
let serial = require("serial");

// --- CONFIGURATION ---
// Your specific n8n webhook (Local IP)
const WEBHOOK_BASE = "http://192.168.1.15:5678/webhook/Watchdog-flipper?target=";
const BAUD_RATE = 115200; // Standard Marauder Baud
// ---------------------

function triggerMarauder(target) {
    // 1. Setup Serial Connection to the WiFi Dev Board (GPIO Pins)
    // "lpuart" is the standard serial port for Flipper GPIO
    serial.setup("lpuart", BAUD_RATE);

    // 2. Format the command for Marauder
    // We append the target to your specific URL
    let fullUrl = WEBHOOK_BASE + target;
    let command = "http get " + fullUrl + "\r\n";

    console.log("Watchdog firing: " + command);
    
    // 3. Send the command to the ESP32
    serial.write(command);

    // 4. Show the "Watchdog" Success Popup
    gui.messageBox.show({
        title: "WATCHDOG ACTIVE",
        text: "Target: " + target + "\nSignal sent to n8n.",
        buttons: ["OK"]
    });

    // Cleanup serial
    serial.end();
}

function main() {
    // This opens the Flipper's native text input screen
    keyboard.text(100, "", (target) => {
        if (target && target.length > 0) {
            triggerMarauder(target);
        } else {
            console.log("No target entered. Aborting.");
        }
    });
}

// Start the app logic
main();
