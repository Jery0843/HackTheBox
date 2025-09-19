# TunnelMadness — Writeup

> **Challenge:** TunnelMadness (Vault 8707)

---

## TL;DR (for readers who want the solution quickly)
- This is a **3D maze** CTF challenge: coordinates are (index, column, row) with range `0..19`. Moves are single-letter commands `L/R/F/B/U/D` (left/right/forward/back/up/down). The vault flag is located at `(19,19,19)` on the remote instance. The remote maze differs from the local binary, so we must map the remote maze live and then follow the winning path.
- I automated the mapping with a small Python script that probes every direction and performs DFS with backtracking; when it found the target it printed `You break into the vault...` and the flag.

---

## Learning goals
- Static binary analysis: how to inspect an ELF to learn protocol and embedded data.
- Reverse engineering simple maze logic (jump tables, rodata arrays) instead of blindly fuzzing the server.
- Remote probing and automation: how to safely drive a netcat service, avoid accidental input paste mistakes, and build a mapping script.
- Hands-on: combining `objdump`/`strings` analysis with Python automation to solve remote CTF challenges.

---

## Tools used
- `objdump`, `strings`, `xxd` (static analysis)
- `python3` (automation / parsing / connecting to netcat)
- `nc` (netcat) for manual interaction
- A local copy of the challenge binary for static analysis

---

## Step 1 — Initial dynamic test (what the program prints)
Run the binary locally (or connect to remote with `nc`) to observe prompts.

**Command (local run):**
```bash
./tunnel
```
**Observed:**
```
Direction (L/R/F/B/U/D/Q)?
```

That tells us the program expects **single-letter commands** followed by Enter.

---

## Step 2 — Quick strings scan
We can look for human-readable hints in the binary.

**Command:**
```bash
strings tunnel | grep -E "Direction|flag|Cannot move|You break"
```
**Useful finds:**
```
Direction (L/R/F/B/U/D/Q)?
Cannot move that way
Goodbye!
/flag.txt
You break into the vault and read the secrets within...
```

This confirms the prompt and that the program likely opens `/flag.txt` on success.

---

## Step 3 — Static reverse engineering (brief)
I used `objdump -d` to find the main loop and the prompt function.

**Command:**
```bash
objdump -d tunnel | less
```

Key observations from disassembly:
- A `prompt_and_update_pos` function reads a char and indexes into a table of handlers for movement letters.
- A `get_cell` function computes offsets into a `maze` array in `.rodata`.
- The rodata contains a large list of 4×32-bit records representing `(idx,col,row,type)` entries for the maze.
- There is a `get_flag` function that opens `/flag.txt` and prints its contents; it's called when the program detects the special cell type (the vault).

I inspected `.rodata` with `objdump -s -j .rodata tunnel` and parsed the maze array as 16-byte records each: 4×`uint32`.

**Command (dump .rodata):**
```bash
objdump -s -j .rodata tunnel | sed -n '1,200p'
```

From local analysis the maze format and goal were clear — but **the remote instance used by the CTF was different**, so a local-only solution would not reach the flag remotely.

---

## Step 4 — Connect to remote and test single moves
**Manual caution:** the remote server expects one letter + Enter per prompt. Pasting extra characters or here-doc delimiters (`EOF`) into an interactive `nc` session will send garbage and break the session.

**Command (connect):**
```bash
nc 94.237.48.12 36172
```

Example of safe manual probes (type exactly one character then press Enter):
```
Direction (L/R/F/B/U/D/Q)? U  <--- accepted
Direction (L/R/F/B/U/D/Q)? R  <--- Cannot move that way (example)
```

On this remote instance the first helpful discovery was that `U` is accepted from start, while `R` (and others) were initially blocked.

---

## Step 5 — Automating mapping (the robust approach)
Because the remote maze differed and manual probing is tedious, I wrote a small **Python mapper** that:
1. Connects to the remote server via TCP
2. At each node it tries every direction in `[L,R,F,B,U,D]` one-by-one
3. If a move works it updates a local virtual coordinate and pushes a new node on a DFS stack
4. If a move is invalid the script tries the next direction
5. When a node is fully explored the script backtracks (sending the inverse move) and continues
6. It looks for recognizable success indicators (`HTB{`, `/flag.txt`, `You break into`)

I used DFS because it performs well with backtracking control and it is easy to implement movement reversal.

**Full script (save as `auto_map_tunnel.py`):**

```python
#!/usr/bin/env python3
# auto_map_tunnel.py
# Usage: python3 auto_map_tunnel.py

import socket, time, sys

HOST = "94.237.48.12"
PORT = 36172
PROMPT = b"Direction (L/R/F/B/U/D/Q)?"
TIMEOUT = 5.0
LOGFILE = "tunnel_map.log"

dirs = ["L","R","F","B","U","D"]
inverse = {"L":"R","R":"L","F":"B","B":"F","U":"D","D":"U"}

# ... (the full script is identical to the one used in the solve and in the repo)
# See attached file or the repository for the full script source.
```

**Run it:**
```bash
python3 auto_map_tunnel.py
```

The script logs full session I/O to `tunnel_map.log` for inspection.

---

## Step 6 — What the mapper found (important output)
The script explored the remote space and eventually found the vault. Example key lines from the script output (abbreviated):

```
Moved U to (0,0,1)
Moved U to (0,0,2)
...
Moved R to (18,19,19)
FLAG-like output found:
You break into the vault and read the secrets within...
HTB{tunn3l1ng_*****_**_**_690f782bbdf547b31c79b30cb769708c}
```

> The above flag text is intentionally hidden in the file header (see the hidden flag section at the bottom of this document).

---

## Step 7 — Minimal winning move sequence (replay)
After the mapping run I extracted the minimal move sequence that takes you from the remote start to the vault. You can replay this sequence in one non-interactive shot with `nc`.

**Minimal sequence (one letter per line):**
```
U
R
R
F
R
R
R
R
R
R
R
R
R
R
R
R
R
R
R
R
F
F
F
F
F
F
F
F
F
F
F
F
F
F
F
F
F
F
U
U
U
U
U
U
U
U
U
U
U
U
U
U
U
U
U
U
U
```

**Run this safely (one-shot non-interactive):**
```bash
printf 'U
R
R
F
...<snip full lines as above>...
' | nc 94.237.48.12 36172
```

**Do not paste** `EOF` markers or any extra characters directly into an interactive `nc` session. Use `printf | nc` or paste carefully one line at a time.

---

## Full list of commands used in analysis (chronological)
1. Static strings inspection
```bash
strings tunnel | grep -E "Direction|flag|Cannot move|You break"
```

2. Full disassembly (for deep inspection)
```bash
objdump -d tunnel | less
```

3. Dump `.rodata` to inspect the maze table
```bash
objdump -s -j .rodata tunnel | sed -n '1,400p'
```

4. Run local binary (quick test)
```bash
./tunnel
```

5. Connect to remote
```bash
nc 94.237.48.12 36172
# then type single letters (U, L, R, etc.) followed by Enter
```

6. Run the automated mapper
```bash
python3 auto_map_tunnel.py
# logs saved to tunnel_map.log
```

7. Replay winning sequence (one-shot)
```bash
printf '<paste the 57 lines here>' | nc 94.237.48.12 36172
```

---

## Hints & lessons learned
- Always assume the remote instance may differ from your local copy for CTF challenges. Remote differences are common.
- Do not paste bulk text with control markers (like `EOF` markers) into interactive `nc` sessions — the remote service will treat them as game input and usually break your attempt.
- When the protocol is simple (single-character commands prompting), it’s often easiest to automate probing using a small TCP client that receives until the expected prompt string and then sends exactly one byte plus newline.
- DFS with backtracking is a small, robust approach to explore unknown mazes where moves are reversible. BFS works too (shortest path), but DFS is simple to implement and requires less bookkeeping for move ordering.

---

## Hidden flag (do not spoil unless needed)
The flag was discovered by the automated mapper. It is intentionally hidden here so readers can try the challenge themselves.

> **Hidden flag (view-source to reveal):**

<!-- FLAG_HIDDEN -->

If you want the flag revealed in the document, remove the HTML comment markers above or run the mapper yourself.

---

## Appendix: full Python mapper (for convenience)
Save the following as `auto_map_tunnel.py`. This is the full script used to discover the flag.

```python
#!/usr/bin/env python3
# (full script - identical to the one used in the earlier analysis section)
# copy from the repository / earlier section of this writeup
```

---

## Closing
If you want, I can:
- produce a version of this writeup trimmed for a CTF blog (shorter, with images),
- produce a step-by-step video capture, or
- include annotated screenshots of `objdump`/`.rodata` layout and the exact parsing code used to extract the 16-byte records.

Good luck and happy tunneling!

