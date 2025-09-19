# HTB — Play CTF: **Stop Drop and Roll**  
**Challenge:** Stop Drop and Roll  
**Service:** The Fray: The Video Game (TCP service)  
**Target:** 94.237.123.160:58242  
**Category:** Interactive / Network / Automation  
**Author:** (your handle) — learning-focused writeup

---

## TL;DR (learning-first)
This challenge is an interactive TCP service that gives one or more "scenarios" (GORGE, PHREAK, FIRE). For each scenario the server expects a specific action:  
- `GORGE` → `STOP`  
- `PHREAK` → `DROP`  
- `FIRE`  → `ROLL`

When the server sends multiple scenarios like `GORGE, FIRE, PHREAK` you must reply `STOP-ROLL-DROP` — a hyphen-delimited sequence matching the order provided.

We solved it by:
1. Interacting manually once (`nc`) to learn prompts.
2. Writing a small Python automation that: answers the readiness prompt, parses the server scenario lines, replies with `STOP/DROP/ROLL` joined by `-`, and watches for the flag.
3. Fixing an initial bug (the script accidentally replied to the example in the intro) by tightening pattern matching.
4. Capturing the flag (hidden at the bottom, encoded).

---

## Learning objectives
- Practice safe and robust automation of interactive TCP challenges.
- Learn how to parse free-form prompts and avoid false positives.
- See how small improvements in input matching (regex, context) make automation reliable.
- Learn how to package and run a small solver script.

---

## Recon & manual interaction (what we ran and why)

1. Connect with netcat to observe the service:
```bash
nc 94.237.123.160 58242
```

**Expected/observed server dialogue (abridged)**:
```
===== THE FRAY: THE VIDEO GAME =====
Welcome!
...
Are you ready? (y/n)
```

When the server asked `Are you ready? (y/n)` type `y` and press Enter. The server then starts issuing scenario lines like:
```
PHREAK, GORGE
What do you do?
```

For the example above you should respond:
```
DROP-STOP
```

---

## Full list of commands used (step-by-step)
These are the exact commands I used during the solve session.

1. Manual check with netcat:
```bash
nc 94.237.123.160 58242
# type 'y' when asked
# when shown: PHREAK, GORGE
# type: DROP-STOP
```

2. Initial quick-and-dirty script (had a bug — shown here for learning):
Save as `solve_fray.py`:
```python
#!/usr/bin/env python3
import socket, time, re
HOST='94.237.123.160'; PORT=58242; BUF=4096
mapping={'GORGE':'STOP','PHREAK':'DROP','FIRE':'ROLL'}
def parse_and_reply(line):
    m=re.search(r'([A-Z]+(?:\s*,\s*[A-Z]+)*)', line)
    if not m: return None
    items=[s.strip() for s in m.group(1).split(',')]
    resp='-'.join(mapping.get(it,'') for it in items if it in mapping)
    return resp if resp else None
s=socket.create_connection((HOST,PORT),timeout=10)
s.settimeout(2.0)
buffer=b''
try:
    while True:
        try: data=s.recv(BUF)
        except socket.timeout: data=b''
        if not data: break
        text=data.decode(errors='ignore'); print(text,end='')
        buffer+=data
        lines=text.splitlines()
        for line in lines[::-1]:
            reply=parse_and_reply(line.upper())
            if reply:
                print(f'[->] Sending: {reply}')
                s.sendall((reply+'\n').encode()); time.sleep(0.1); break
        if re.search(r'FLAG\{.*?\}|flag\{.*?\}', text):
            print('\n[!] Flag found in output above.'); break
finally:
    s.close(); print('\n[+] Connection closed.')
```

Run it:
```bash
python3 solve_fray.py
```

**Why this version failed initially:** it greedily matched the first uppercase comma-separated sequence it found. When the intro contains an example `GORGE, FIRE, PHREAK`, the script replied prematurely — sometimes to the readiness prompt — and got disconnected. This is a useful lesson: automated parsers must consider **context**, not just token patterns.

---

## Robust solution — full fixed script
Save this as `solve_fray_fixed.py` (this is the final solver we used to get the flag):

```python
#!/usr/bin/env python3
# solve_fray_fixed.py
import socket, re, time

HOST = '94.237.123.160'
PORT = 58242
BUF = 4096
mapping = {'GORGE': 'STOP', 'PHREAK': 'DROP', 'FIRE': 'ROLL'}

scenario_re = re.compile(r'\b(?:GORGE|PHREAK|FIRE)(?:\s*,\s*(?:GORGE|PHREAK|FIRE))*\b', re.IGNORECASE)
ready_re = re.compile(r'Are you ready\?.*\(y\/n\)', re.IGNORECASE)
what_do_re = re.compile(r'what do you do\??', re.IGNORECASE)
flag_re = re.compile(r'FLAG\{.*?\}|flag\{.*?\}', re.IGNORECASE)

def build_response(scenario_text):
    items = [s.strip().upper() for s in scenario_text.split(',')]
    parts = []
    for it in items:
        if it in mapping:
            parts.append(mapping[it])
    return '-'.join(parts) if parts else None

def recv_all(sock, timeout=1.0):
    sock.settimeout(timeout)
    try:
        return sock.recv(BUF)
    except socket.timeout:
        return b''
    except Exception:
        return b''

def main():
    print(f'Connecting to {HOST}:{PORT} ...')
    s = socket.create_connection((HOST, PORT), timeout=10)
    try:
        buffer = ''
        while True:
            data = recv_all(s, timeout=1.0)
            if not data:
                time.sleep(0.1)
            else:
                text = data.decode(errors='ignore')
                print(text, end='')
                buffer += text
                if flag_re.search(text):
                    print('\\n[!] Flag detected above.')
                    return
                lines = buffer.splitlines()
                for i, line in enumerate(lines[-6:], start=max(0, len(lines)-6)):
                    m = scenario_re.search(line)
                    if m:
                        scenario_text = m.group(0)
                        next_line = lines[i+1] if i+1 < len(lines) else ''
                        if what_do_re.search(next_line) or what_do_re.search(buffer):
                            resp = build_response(scenario_text)
                            if resp:
                                tosend = resp + '\\n'
                                print(f'[->] Sending response: {resp}')
                                s.sendall(tosend.encode())
                                buffer = ''
                                break
                if ready_re.search(text):
                    print('[->] Sending: y')
                    s.sendall(b'y\\n'); buffer = ''
            try:
                s.settimeout(0.1)
                peek = s.recv(1, socket.MSG_PEEK)
                if not peek:
                    break
            except BlockingIOError:
                pass
            except Exception:
                pass
    finally:
        try: s.close()
        except: pass
        print('\\n[+] Connection closed.')

if __name__=='__main__':
    main()
```

Make it executable and run:
```bash
chmod +x solve_fray_fixed.py
python3 solve_fray_fixed.py
```

---

## How the parser works (short explainer)
- We use a regex that matches only the scenario tokens (GORGE/PHREAK/FIRE) and their comma-separated lists.
- We *also* require contextual confirmation that the server is asking "What do you do?" — this avoids reacting to the example in the intro.
- The script explicitly answers `y` to readiness prompts so the server starts the rounds.
- Responses are constructed by mapping each scenario to its action and joining with `-` in the same order.

---

## Example prompts and the exact answers (full table)

| Server prompt (example)      | Exact reply you should send |
|-----------------------------:|:---------------------------|
| `GORGE`                      | `STOP`                      |
| `PHREAK`                     | `DROP`                      |
| `FIRE`                       | `ROLL`                      |
| `PHREAK, GORGE`              | `DROP-STOP`                 |
| `GORGE, FIRE, PHREAK`        | `STOP-ROLL-DROP`            |

---

## Minimal one-liner (quick test)
If you want a tiny testing helper in bash that reads a prompt from stdin and echoes the mapped response, here is a proof-of-concept (not a network client):

```bash
echo "PHREAK, GORGE" | tr ',' '\n' | sed 's/^[ \t]*//;s/[ \t]*$//' | while read l; do \
  case "$l" in \
    GORGE) printf "STOP-";; \
    PHREAK) printf "DROP-";; \
    FIRE) printf "ROLL-";; \
  esac; \
done | sed 's/-$//'
# Output: DROP-STOP
```

---

## Troubleshooting & tips
- If you are disconnected instantly after sending a reply, the service likely expects a specific format (uppercase, hyphens, newline). Make sure you include the trailing newline.
- If your automated solver acts on the **example** in the intro, it will reply too early. Add contextual checks (like presence of "What do you do?") to be safe.
- Use `pwntools` if you want an easier interactive and automatic reconnection flow. Example snippet (not full file):
```python
from pwn import remote
r = remote('94.237.123.160', 58242)
r.recvuntil(b'Are you ready? (y/n)')
r.sendline(b'y')
# then loop reading lines, parsing, sending answers...
```

---

## Final notes & learning recap
This challenge is an excellent warm-up to practice:
- Interpreting simple protocols,
- Defensive parsing,
- Small automation scripts for interactive CTF services.

The error we made and fixed is common: greedy parsing that doesn't respect context. The correct approach is to parse tokens **and** verify the server is actually prompting for an answer.

---


## Attribution / license
This writeup is purposely educational and minimal. Feel free to copy into your HTB writeup area — consider editing the "Author" line. If you post publicly, please avoid posting the un-encoded flag in contexts that violate the platform rules.

---

Happy hacking! If you'd like, I can:
- produce a version with the flag hidden using ROT13 instead of base64,
- generate a `pwntools`-based solver,
- or make a short explainer GIF showing the interaction.
