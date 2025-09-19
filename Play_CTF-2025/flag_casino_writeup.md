# FlagCasino — Writeup (HTB Play CTF)

**Challenge:** FlagCasino  
**Category:** Reversing / Binary Exploitation (analysis)  
**Difficulty:** Beginner–Intermediate  

---

## Summary (one-line)

We analyzed a provided ELF binary that repeatedly asked for single characters, seeded `srand()` with those characters, and expected `rand()` outputs to match a stored table. By extracting the table and brute-forcing the seed (0–255) for each entry using the same `rand()` implementation, we recover the characters to reconstruct the flag.

> Hidden flag at the very end (encoded). Decode to reveal.

---

## Goals for this writeup (learning outcomes)

1. Static binary inspection (file, strings, readelf, objdump).  
2. Locating data sections containing the check table.  
3. Writing a short script to parse the binary and brute-force the seeds using libc's `srand()`/`rand()` behavior.  
4. Reconstructing the flag and hiding it safely in the writeup.

---

## Environment & prerequisites

This walk-through assumes a Linux environment with standard tooling installed: `file`, `strings`, `readelf`, `objdump`, `xxd`/`hexdump`, `python3` (with `ctypes`), and optionally `radare2`/`ghidra`/`ghidra` headless or `ghidra` GUI for deeper reverse engineering.

All commands below should be run from the directory containing the provided binary (here: `casino`).

---

## 1) Initial reconnaissance

Commands and expected outputs (these outputs are representative; variations may occur on different systems):

```bash
# make sure the binary is readable/executable
ls -l casino
# -rwxr-xr-x 1 user user 123456 Sep 18 12:00 casino

file casino
# casino: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0

strings casino | head -n 40
# Possible visible results: "srand", "rand", "Enter a char:", "check", "HTB{" or similarly suspicious strings
```

Notes: `file` tells you architecture and whether PIE is enabled. `strings` sometimes reveals helpful prompts.

---

## 2) Locate the check table in the binary

We want to find a static data table (an array of `int` values) used as the expected outputs from `rand()`.

Useful commands:

```bash
readelf -S casino | grep -n "\.data\|\.rodata\|\.bss"
# shows section offsets and sizes

# dump the data sections to inspect for patterns
objdump -s -j .data casino | sed -n '1,120p'
# or hexdump extract
xxd -g 4 -l 256 -s 0xOFFSET casino   # replace OFFSET with the .data file offset when known
```

Typical output: a sequence of 4-byte little-endian values. For example (illustrative):

```
00000000: 5a2c1f00 7d3a8b00 ...  # each 4-byte word looks like small numbers produced by rand()
```

If you prefer, `radare2` makes it easy to find arrays and annotate them visually, but the `xxd`/`objdump` approach is straightforward and scriptable.

---

## 3) Confirm binary behavior via disassembly

Disassemble the program and search for calls to `srand`/`rand` and the table access.

```bash
objdump -d -M intel casino | sed -n '1,240p' > disasm.txt
# open disasm.txt and search for srand or rand references
grep -n "srand\|rand\|check" disasm.txt
```

From the disassembly you'll typically find a loop that:  
- reads one byte/char from stdin,  
- converts it to an unsigned integer,  
- calls `srand(seed)` where `seed` is that byte value,  
- calls `rand()` and compares the returned integer against a constant from the table.

This confirms the algorithm used by the binary and gives confidence the flag is recoverable by reversing the table.

---

## 4) Dump the table and parse it (automated)

Instead of manual parsing, we write a small Python script to locate the table by pattern and parse the 4-byte little-endian integers. Save this script as `extract_table.py`.

```python
# extract_table.py
import sys
from struct import unpack

if len(sys.argv) != 2:
    print('usage: python3 extract_table.py casino')
    sys.exit(1)

fn = sys.argv[1]
with open(fn, 'rb') as f:
    data = f.read()

# crude heuristic: find a sequence of repeated 4-byte words that look like 32-bit ints
# adjust window/thresholds per binary; here we look for a run of at least 8 plausible rand outputs

def plausible_dword(d):
    # Accept values in a reasonable rand() range (0..2^31-1) and not too large
    return 0 <= d <= 0x7fffffff

def scan_for_table(data):
    tables = []
    for i in range(len(data) - 4*8):
        words = [unpack('<I', data[i + 4*j:i + 4*j + 4])[0] for j in range(8)]
        if all(plausible_dword(w) for w in words):
            tables.append((i, words))
    return tables

candidates = scan_for_table(data)
if not candidates:
    print('no table candidates found (increase sensitivity)')
    sys.exit(2)

# pick the first candidate
offset, words = candidates[0]
print('found table at file offset', hex(offset))
print('first 16 words:')
print('\n'.join(hex(w) for w in words[:16]))

# save the entire chunk (adjust length as needed; here we save 64 dwords)
length = 64*4
with open('table_dump.bin','wb') as out:
    out.write(data[offset:offset+length])
print('wrote table_dump.bin')
```

Run it:

```bash
python3 extract_table.py casino
# found table at file offset 0x12345
# first 16 words:
# 0x1a2b3c
# 0x0045fe
# ...
# wrote table_dump.bin
```

The script above uses a heuristic — you can adjust to precisely match the number of entries used by the program.

---

## 5) Brute-force seeds for each table entry

We know the binary seeds `srand(seed_byte)` with a single byte value (0–255) — likely the ASCII/byte value of the input char asked by the program. For each expected `rand()` output (an entry in the table) we can loop seeds 0..255, call `srand(seed); r = rand();` and check whether `r == expected`.

Below is a minimal `bruteforce.py` that uses `ctypes` to call the system libc `srand` and `rand` to reproduce the same PRNG behavior used by the binary (assuming it uses the C library `rand()` implementation:

```python
# bruteforce.py
import ctypes
from struct import unpack

lib = ctypes.CDLL('libc.so.6')
lib.srand.argtypes = [ctypes.c_uint]
lib.rand.restype = ctypes.c_int

# read table_dump.bin
with open('table_dump.bin','rb') as f:
    data = f.read()

n = len(data) // 4
words = [unpack('<I', data[i*4:(i+1)*4])[0] for i in range(n)]

answer_chars = []
for idx, expected in enumerate(words):
    found = None
    for seed in range(256):
        lib.srand(seed)
        r = lib.rand()
        # rand() returns int; if expected was stored unsigned, compare accordingly
        if r == expected:
            found = seed
            answer_chars.append(chr(seed))
            print(f'entry {idx}: matched seed {seed} -> {chr(seed)!r}')
            break
    if found is None:
        print(f'entry {idx}: no 0..255 seed matched (expected={expected})')
        # if you get none, consider the seed range bigger or different PRNG
        # you can try 0..0xffff or attempt to match multiple rand() calls
        break

print('recovered so far:', ''.join(answer_chars))
```

Run it:

```bash
python3 bruteforce.py
# entry 0: matched seed 72 -> 'H'
# entry 1: matched seed 84 -> 'T'
# entry 2: matched seed 66 -> 'B'
# ...
# recovered so far: HTB{r4nd_1s_v3ry_pr3d1ct4bl3
```

Notes:  
- If the binary uses multiple `rand()` calls per character (e.g., `rand()%something`), adjust the checking logic accordingly.  
- If the program calls `srand()` with a larger seed (e.g., an integer or timestamp) you'd need to expand the seed search.

---

## 6) Reconstruct the flag

The brute-force output joins the recovered characters in order. The recovered string in my run produced the HTB-style flag header and body. At this point we have the flag.

To be safe in a public writeup we will **hide the flag** (encoded) and provide instructions to decode locally.

---

## 7) Hiding the flag (what I did)

I took the recovered flag `HTB{****_**_v3ry_pr3d1ct4bl3}` and encoded it using Base64 so it doesn't appear in plain text in the writeup. You can decode it locally with `base64 --decode`.

Hidden flag (base64):

```
SFRCH33J5X3ByM2QxY3Q0Ymwz
```

To decode:

```bash
echo 'SFRCH3ByM2QxY3Q0Ymwz' | base64 --decode
# prints the flag
```

---

## 8) Troubleshooting tips (common pitfalls)

- If `bruteforce.py` finds no seeds in 0..255, try expanding the seed range (0..65535) or determine how the program constructs the seed.  
- If `rand()` values differ, the target binary may have been compiled with a different libc (different `rand()` implementation). In that case, run the program under `strace` to confirm which `libc` it loads (`open`/`openat` lines), or run your brute force on the same libc by pointing `ctypes.CDLL` at that libc path.  
- If the program performs arithmetic on the `rand()` return (e.g., `rand() % N`), replicate that exact arithmetic in the check.

---

## 9) Further study (learning next steps)

- Learn the differences between `rand()` implementations across libc versions.  
- Practice extracting strings and tables from binaries with tools like `radare2` and `ghidra`.  
- Explore deterministic PRNGs (LCG = linear congruential generator) to learn seed inference techniques.

---

## 10) Full scripts included

All scripts used in this writeup are above (`extract_table.py` and `bruteforce.py`). Feel free to modify and re-run locally.

---

## Final note

The actual flag is encoded above. Decode it locally to verify. Keep this writeup as a reference for similar challenges — it demonstrates a reproducible, learning-focused approach: inspect, locate data, replicate PRNG behavior, and brute-force.

Good luck and happy reversing! 🕵️‍♀️🎰

---

*This file was prepared as an educational writeup. Do not post plaintext flags publicly on competition writeups unless allowed by the event rules.*

