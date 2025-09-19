# 🕵️‍♂️ An Unusual Sighting — HTB Play CTF Write-up

## 📝 Challenge Description
As the preparations come to an end, and The Fray draws near each day,
our newly established team has started work on refactoring the new CMS application for the competition.
However, after some time we noticed that a lot of our work mysteriously has been disappearing!
We managed to extract the SSH Logs and the Bash History from our dev server in question.
The faction that manages to uncover the perpetrator will have a massive bonus come the competition!

**Note:**
- Operating hours: 09:00–19:00
- All timestamps in logs are real timestamps.

We are provided with:
- `sshd.log` — server SSH login log
- `bash_history.txt` — command history from the compromised machine

Our mission is to reconstruct the attacker's activity, answer the forensic questions, and finally retrieve the flag.

## 📍 Step 1 — Finding the SSH server
We are given a nc connection to verify answers:
```
nc 94.237.122.241 58980
```

The first question asks:
**What is the IP Address and Port of the SSH Server (IP:PORT)**

Looking through `sshd.log`, we notice connection logs such as:
```
[2024-02-13 11:29:50] Accepted password for root from 100.107.36.130 port 2221 ssh2
```

This reveals the real SSH server:
✅ **Answer**
```
100.107.36.130:2221
```

## ⏰ Step 2 — First successful login
We now want to find the very first successful SSH login.

Searching for `Accepted password` in the `sshd.log`:
```bash
grep "Accepted password" sshd.log | sort | head -n 1
```

We get:
```
[2024-02-13 11:29:50] Accepted password for root from 100.81.51.199 port 63172 ssh2
```

✅ **Answer**
```
2024-02-13 11:29:50
```

## 🌒 Step 3 — Unusual login (outside working hours)
We are told the company (Korp) works between 09:00–19:00.
Any login outside that time is suspicious.

We can find such logins with:
```bash
grep "Accepted password" sshd.log
```

Among them, this stands out:
```
[2024-02-19 04:00:14] Accepted password for root from 2.67.182.119 port 60071 ssh2
```

04:00 is well before operating hours — this is our attacker.

✅ **Answer**
```
2024-02-19 04:00:14
```

## 🔑 Step 4 — Attacker's public key fingerprint
Attackers often add their SSH public key to maintain persistence.

We can find key-based login attempts using:
```bash
grep "Accepted publickey" sshd.log
```

We see an entry linked to the attacker's IP `2.67.182.119` showing:
```
[2024-02-19 04:02:00] Accepted publickey for root from 2.67.182.119 ... ssh2: RSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```

✅ **Answer**
```
OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```

## 💻 Step 5 — First command after logging in
Let's move to `bash_history.txt` and check commands around 04:00:
```
[2024-02-19 04:00:18] whoami
[2024-02-19 04:00:20] uname -a
[2024-02-19 04:00:40] cat /etc/passwd
...
```

The first command immediately after the login:

✅ **Answer**
```
whoami
```

## 🧨 Step 6 — Final command before logout
Still following the same timeline, the commands executed by the attacker are:
```
[2024-02-19 04:10:02] tar xvf latest.tar.gz
[2024-02-19 04:12:02] shred -zu latest.tar.gz
[2024-02-19 04:14:02] ./setup
```

This `./setup` is the last one before the attacker left.

✅ **Answer**
```
./setup
```

## 🏁 Step 7 — Retrieving the flag
Once all answers are submitted correctly, the challenge reveals the flag:
```
nc 94.237.122.241 58980
```

🟢 After answering all prompts, we receive:
```
[+] Here is the flag: HTB{***********************}
```
(Hidden intentionally — solve it yourself 😉).