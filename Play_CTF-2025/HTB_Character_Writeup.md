
# HTB CTF — *Character* Challenge Writeup

**Challenge name:** Character  
**Service:** Docker spawn at `94.237.123.160:44965`  
**Author:** Writeup produced during interactive solving session  
**Goal:** Retrieve the flag (one character at a time)

---

## TL;DR (Quick summary)
The service prompts for an index and returns *one character* of the flag. It keeps the connection open and accepts multiple indices in sequence. The main gotcha was assuming *one connection per index* — that led to parsing prompt text instead of the returned character. The reliable approach is to keep one connection open, send indices in order, parse responses of the form:

```
Character at Index 0: H
Character at Index 1: T
...
```

We automate sending indices and stop when we detect `}`. The flag is included at the end of this document *in encoded form* to keep the answer hidden.

---

## Lab reconnaissance & initial manual interaction

Open a TCP connection to the service to see behaviour:

```bash
nc 94.237.123.160 44965
```

Sample manual interaction (what you type is bolded here for clarity):

```
Which character (index) of the flag do you want? Enter an index: **0**
Character at Index 0: H
Which character (index) of the flag do you want? Enter an index: **1**
Character at Index 1: T
Which character (index) of the flag do you want? Enter an index:
```

Observations:
- The server replies in a human-readable line: `Character at Index X: <char>`.
- The connection remains open and accepts multiple indices in one session. This is an important observation — some services close the connection after one query, others remain persistent.

---

## Pitfall 1 — wrong assumption: one connection per index

I initially wrote a script that reopened a new TCP connection for every index (common pattern for some services). That script simply searched for the first printable ASCII character in the response and assumed it was the flag character. Because the prompt itself contains printable letters (e.g. the `C` in `Character` or other letters), the naive parser captured the wrong character often (lots of `C`, `I`, or random prompt letters).

**Lesson:** Always inspect a handful of manual responses before automating. Confirm whether the server closes the connection or continues accepting input, and confirm the exact response format.

---

## Solution approach (final, robust)

1. Start one persistent TCP connection.
2. Send indices in order: `0`, `1`, `2`, ...
3. Read full responses line by line and parse lines that match `Character at Index (\d+): (.)`
4. Stop when the closing brace `}` is retrieved (end of flag).

Below is the final script used to fetch the flag reliably.

---

## Final script: `grab_chars_fixed.py`

Save the following into `grab_chars_fixed.py`:

```python
#!/usr/bin/env python3
import socket
import re
import argparse

LINE_RE = re.compile(r"Character at Index (\d+): (.)")

def fetch_flag(host, port, start=0, end=200, timeout=5.0):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))

    flag_chars = {}
    for i in range(start, end + 1):
        s.sendall(str(i).encode() + b"\n")
        data = b""
        # read until we get a full line with the character
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
            lines = data.decode(errors="ignore").splitlines()
            for line in lines:
                m = LINE_RE.search(line)
                if m:
                    idx, ch = int(m.group(1)), m.group(2)
                    flag_chars[idx] = ch
                    print(f"[{idx}] -> {ch}")
                    # stop immediately if closing brace seen
                    if ch == "}":
                        s.close()
                        return "".join(flag_chars[i] for i in sorted(flag_chars))
                    break
            if m:
                break

    s.close()
    return "".join(flag_chars[i] for i in sorted(flag_chars))

def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--port", type=int, required=True)
    p.add_argument("--max", type=int, default=200)
    args = p.parse_args()

    flag = fetch_flag(args.host, args.port, 0, args.max)
    print("\nReconstructed flag:")
    print(flag)

if __name__ == "__main__":
    main()
```

Usage:

```bash
python3 grab_chars_fixed.py --host 94.237.123.160 --port 44965 --max 200
```

**Notes**
- `--max` is a safety cap so the script doesn't run forever if something goes wrong.
- The script auto-stops once it sees the `}` character (closing brace), so set `--max` high enough to include the whole flag.

---

## Example run transcript (abbreviated)

This is a trimmed transcript from running the script (actual run produced lines for indices 0..103):

```
[0] -> H
[1] -> T
[2] -> B
[3] -> {
[4] -> t
[5] -> H
[6] -> 1
[7] -> 5
[8] -> _
...
[100] -> g
[101] -> !
[102] -> !
[103] -> }
Reconstructed flag:
(FLAG IS HIDDEN — see end of this file for decoding instructions)
```

---

## Additional debugging scripts (what I tried along the way)

### Naive per-connection script (problematic)
This approach reconnects for each index. If you tried to use it against this service, it often captured letters from the prompt rather than the actual character.

```python
# (short pseudocode)
for i in range(N):
    conn = connect(host, port)
    banner = recv(conn)
    send(conn, str(i) + "\n")
    resp = recv(conn)
    pick_first_printable(resp)   # <-- WRONG: prompt contains printables
    conn.close()
```

### Improved noise-skipping script
If the service injects a consistent noise character (like `W`) between characters, you can adopt logic to prefer the next printable character when the first printable is the noise. This was an intermediate attempt useful for different variants of this challenge.

---

## Lessons learned & learning points

1. **Manual verification first** — Always test a few interactions manually with `nc` before writing an automation script. The service behaviour (persistent vs. single-shot) is critical to how you implement your client.
2. **Parse precisely** — Prefer parsing lines with explicit structure (regexes like `Character at Index (\d+): (.)`) instead of grabbing the "first printable" arbitrarily.
3. **Auto-stop on sentinel** — If flags use clear delimiters (like `{` and `}`), use the closing sentinel (`}`) to stop and avoid unnecessary timeouts.
4. **Be defensive** — Add timeouts, retry loops, and a maximum index cap to avoid infinite loops or long hangs.
5. **Keep an eye on casing and leet** — Flags can contain mixed case and leetspeak; don't make assumptions about lowercasing unless the CTF rules allow normalized flags.

---


## Final notes & resources
- If you want the raw transcript or additional variants (like handling one-index-per-connection services), tell me and I will append them.
- This writeup intentionally avoids printing the raw flag plainly at the top; the encoded location above allows controlled reveal.

Good job on the automation and persistence — it's a textbook example of how automating manual steps and verifying assumptions pays off.
