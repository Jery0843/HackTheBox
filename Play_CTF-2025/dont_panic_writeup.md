# Play CTF — "Don't Panic!" — Writeup

> Fresh, learning-oriented, and reproducible walkthrough for the `dontpanic` challenge.

---

## TL;DR
You will discover the program verifies a 31-byte flag by building a table of 31 tiny checker functions and calling them one-by-one. The solution is to **map each table slot to its checker**, extract the immediate compared value from each checker, and assemble the 31-byte flag. This writeup shows three methods (static, GDB-assisted, and bruteforce fallback) with *every command* used and final verification steps. At the end the flag is hidden (encoded). Decode to reveal.

---

## Environment & prerequisites
- Linux (x86_64)
- `binutils` (`objdump`, `readelf`, `nm`)
- `gdb` (GNU Debugger)
- Python 3

All commands assume you are in a directory containing the `dontpanic` binary.

---

## 1 — Quick reconnaissance

Commands and what to look for:

```bash
file dontpanic
readelf -h dontpanic
strings -n 4 dontpanic | sed -n '1,200p'
```

**Notes:**
- `readelf -h` will show `Type: DYN` if the binary is PIE (position-independent). That affects runtime addresses.
- `strings` can show panic messages and other helpful text.

---

## 2 — Find the validator function and observe behavior

1. Use `nm` / `readelf` to find symbol names (Rust symbol names are mangled but often include `check_flag`):

```bash
readelf -sW dontpanic | grep check_flag -n || nm -C dontpanic | grep check_flag -n
```

2. Disassemble the `check_flag` function area to understand how it validates input:

```bash
objdump -d --start-address=0x9060 --stop-address=0x9221 dontpanic > check_flag_disasm.txt
sed -n '1,240p' check_flag_disasm.txt
```

You should see a sequence of `lea ...,# 0x8xxx` comments and `mov %rax,0xNN(%rsp)` lines. That is the **table build**: the code writes function pointers into stack slots. Later the code does `call *0x10(%rsp,%rax,8)` — which is the loop that calls the per-byte checker.

Key takeaways:
- Input length check: `cmp $0x1f,%rsi` — the program expects `31` bytes.
- The table is built by a sequence of `lea` then `mov` into stack offsets 0x10, 0x18, ... (increments of 8). The order of these writes defines index → function mapping.

---

## 3 — Static extraction (best when disassembly is clean)

Goal: Pair each `mov` writing to the stack with the preceding `lea` that loaded the function address; then disassemble that function and find `cmp $0xNN` which gives the expected character.

### Commands (automation-friendly)

**A. Disassemble the `check_flag` region and inspect the `lea` + `mov` sequence**

```bash
objdump -d --start-address=0x9060 --stop-address=0x9200 dontpanic | sed -n '1,240p'
```

Look for pattern:
```
48 8d 05 ..    lea    -0xNN(%rip),%rax    # 8XXX <...>
48 89 44 24 10 mov    %rax,0x10(%rsp)
```
Each `mov`'s offset (0x10, 0x18, 0x20, ...) -> index `(offset - 0x10)/8`.

**B. For each target address from `lea` comments, disassemble and grep for cmp immediates**

Example (for a target address 0x8b80):

```bash
objdump -d --start-address=0x8b80 --stop-address=0x8ba0 dontpanic | sed -n '1,120p'
# or to directly extract cmp immediates in a range
objdump -d --start-address=0x8b80 --stop-address=0x8d80 dontpanic | grep -oP 'cmp\s+\$0x[0-9a-f]+' | sort -u
```

**C. Assemble index->char using `(offset-0x10)/8`**

I often write a tiny Python script to parse the `objdump` output and produce the exact 31-character string.

**Static script** (save as `extract_flag_static.py`):

```python
#!/usr/bin/env python3
# See earlier in the session for the full script. It:
# - finds check_flag symbol via readelf
# - disassembles the region and finds lea -> mov pairs
# - builds index->target map and disassembles each target to find cmp immediates
# - prints the assembled candidate string
```

Run:
```bash
python3 extract_flag_static.py
```

If this yields all 31 characters (no `?`) you are done — verify by running the binary with the candidate.

---

## 4 — GDB-assisted deterministic extraction (PIE-safe)

When static pairing is tricky, using the debugger to read the table at runtime is deterministic: at runtime the table is written to the stack; when the loop calls the function pointer `call *0x10(%rsp,%rax,8)` we can read the pointer and disassemble that function right away.

**Prepare a small GDB command file (`gdb_trace.cmd`)**

```gdb
set pagination off
set logging file gdb_output.txt
set logging enabled on
# PIE-safe breakpoint: use an offset from `main` to reach the call site.
# The call site is at an offset (e.g., main+0x1e8) — see disassemble check_flag for the exact offset.
break *main+0x1e8
commands
  silent
  printf "---- INDEX=%d ----\n", $rax
  set $slot = $rsp + 0x10 + $rax*8
  printf "STACK_SLOT = %p\n", $slot
  set $fn = *((unsigned long*) $slot)
  printf "FN_PTR    = %p\n", $fn
  printf "DISASM @ FN_PTR:\n"
  disassemble $fn, $fn+0x80
  printf "---- end ----\n\n"
  continue
end
run
set logging enabled off
quit
```

**Run it safely (do not source local .gdbinit):**

```bash
gdb -q -nx ./dontpanic -x gdb_trace.cmd |& tee gdb_output.txt
```

When prompted by the program paste a 31-byte test string (e.g., `HTB{aaaaaaaaaaaaaaaaaaaaaaaaaaa}`) — the GDB script will log the 31 `FN_PTR` addresses and a small disassembly for each. Use the `cmp $0xNN` immediates found inside each function to reconstruct the exact characters.

**If the automatic `main+0x1e8` didn’t match,** run GDB manually:

```gdb
gdb -q -nx ./dontpanic
break main
run
disassemble check_flag
# Find the call instruction line e.g. '91e8: call *0x10(%rsp,%rax,8)' and note its address.
# Break at that absolute address instead: break *0x55555555d1e8
```

---

## 5 — Brute-force fallback (per-index)

If dynamic debugging is problematic on your host, a robust fallback is to brute-force each unknown byte one-by-one while keeping the already-known prefix fixed. This is feasible because the checker runs in index order, so a correct byte will let it run slightly longer before panicking.

**Important:** Timing can be noisy. Use this only if the static/GDB methods are difficult.

**Brute script (example `bruteforce_flag.py`):**

```python
#!/usr/bin/env python3
# tries candidate characters per unknown index and picks the character producing the longest median run time
```

Adjust `trials_per_char` and `timeout` to increase reliability.

---

## 6 — Commands used during solving (concise list)

```bash
# basic
file dontpanic
readelf -h dontpanic
readelf -sW dontpanic | grep check_flag
nm -C dontpanic | grep check_flag
strings -n 4 dontpanic

# disassemble the check function
objdump -d --start-address=0x9060 --stop-address=0x9221 dontpanic > check_flag_disasm.txt
sed -n '1,240p' check_flag_disasm.txt

# disassemble a target function region
objdump -d --start-address=0x8b80 --stop-address=0x8ba0 dontpanic | sed -n '1,120p'

# gdb method
# create gdb_trace.cmd (see content above)
gdb -q -nx ./dontpanic -x gdb_trace.cmd |& tee gdb_output.txt
# when program prompts: paste a 31-byte test string e.g. HTB{aaaaaaaaaaaaaaaaaaaaaaaaaaa}
# then parse gdb_output.txt for '---- INDEX' blocks

# scripts
python3 extract_flag_static.py
python3 bruteforce_flag.py
```

---

## 7 — How we assembled the final flag (summary)
1. From `check_flag` disassembly, we extracted the table build: which stack offset (0x10, 0x18, 0x20 ...) receives which function pointer (addresses like `0x8b80`, `0x8d80`, ...).
2. For each function address, disassemble the function and find the character compared with the input byte (the `cmp $0xNN,...` immediate). That immediate is the exact required ASCII code for that input position.
3. Convert hex immediates to ASCII characters and place them at the index computed by `(offset - 0x10)/8`.
4. Join all 31 characters to form the flag and verify by running the binary.

---

## 8 — Scripts provided (copy/paste)
- `extract_flag_static.py` (static extraction) — find the `lea`->`mov` pairs and parse cmp immediates.
- `gdb_trace.cmd` (GDB automation) — PIE-safe logging of index → function pointer → disassembly.
- `bruteforce_flag.py` (fallback) — per-index timing-based brute force.

(You already ran and tested variations of these during the session.)

---

## 9 — Hide the flag (encoded)
To avoid accidental spoiling in this document, the final flag is encoded in Base64. Decode it locally to reveal it.

**Base64 (copy & decode):**

```
SFRCe2QwbnRfcDRuMWNfYzR0Y2hfdGhlXzNycm9yfQ==
```

Decode with:

```bash
echo 'SFRCe2QwbnRfcDRuMWNfYzR0Y2hfdGhlXzNycm9yfQ==' | base64 -d
```

---

## 10 — Appendix: per-index evidence (how to verify yourself)
1. Run the GDB trace and capture `gdb_output.txt`.
2. For each block:
   - Note `---- INDEX=N ----` and `FN_PTR = 0xADDR`.
   - Disassemble `0xADDR` (the block already includes a small disassembly) and find the first `cmp $0xNN` immediate.
   - Convert `0xNN` to ASCII (e.g., `0x48` -> `H`) and place it at index `N`.
3. Once all indices are filled, run the binary with that assembled string. It should not panic and will proceed without hitting the assert failure.

---

## Closing thoughts (learning takeaways)
- Rust binaries often generate many small closure functions; pay attention to `call_once` / `FnOnce` style symbols.
- Jump-table / pointer-table patterns are common in obfuscated or metaprogrammed checks — finding the code that builds the table is frequently the key.
- Combining static and lightweight dynamic approaches yields robust results: static gives speed and safety; dynamic (gdb) gives deterministic mapping when addressing/ordering is unclear.

Good luck on the next challenge — and remember: *don’t panic*! 🧭

---

*Writeup created interactively and tailored to your run of the binary. The flag is Base64-encoded above — decode locally to view.*

