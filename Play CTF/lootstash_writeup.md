
# LootStash — HTB Play CTF writeup

**Challenge:** LootStash  
**Category:** Binary reverse / Forensics  
**Difficulty:** Easy–Medium  
**Author:** (writeup) — fresh, learning-focused, step-by-step  
**Note:** The actual flag is intentionally **hidden** in this public writeup. The steps below show how to extract it; the final section shows a masked flag and how to reveal it locally.

---

## TL;DR (one-line)
Find the printable strings inside the provided `stash` binary and filter for the HTB flag pattern. For learning, we also inspect the binary’s type, basic symbols, and a disassembly snippet.

---

## Prerequisites
You should have a Linux environment with the following tools installed:

- `file`
- `hexdump` or `xxd`
- `strings`
- `grep`
- `objdump` (from `binutils`) or `r2` / `radare2`
- `gdb` (optional, for dynamic analysis)
- `chmod`, `ls`

All commands below are intended to run locally against the provided binary at `/mnt/data/stash`.

---

## 1) Identify the file type
Command:
```bash
file /mnt/data/stash
```

Expected answer (example):
```
/mnt/data/stash: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, stripped
```

**Learning:** `file` quickly tells you architecture, whether it’s stripped, and linked dynamically or statically. If a binary is **stripped**, symbol names are removed — which makes reverse engineering slightly harder.

---

## 2) Check permissions and make executable (if necessary)
Commands:
```bash
ls -l /mnt/data/stash
chmod +x /mnt/data/stash
```

Typical output for `ls -l`:
```
-rw-r--r-- 1 user user 123456 Sep 17 12:34 /mnt/data/stash
```

After `chmod +x`:
```
-rwxr-xr-x 1 user user 123456 Sep 17 12:34 /mnt/data/stash
```

**Learning:** Ensure you can execute the file if you want to run it. But be careful running unknown binaries on your host — prefer an isolated VM.

---

## 3) Fast, low-effort look: `strings`
Command:
```bash
strings -a -n 4 /mnt/data/stash | sed -n '1,120p'
```

This prints printable strings inside the binary. You can `grep` for common flag patterns:

```bash
strings -a -n 4 /mnt/data/stash | grep -Eo 'HTB\{[^}]+\}'
```

**Typical answer (masked):**
```
HTB{*********************}
```

**Learning:** `strings` often reveals embedded messages, hardcoded secrets, or flag formats. The `-n 4` requires at least 4 printable characters in a row; adjust as needed.

---

## 4) If `strings` didn't find it: hexdump / xxd
Command:
```bash
xxd -g 1 -l 512 /mnt/data/stash | sed -n '1,32p'
```

This prints the first 512 bytes; inspect if there is embedded text elsewhere or unusual sections.

**Learning:** `xxd`/`hexdump` helps locate non-terminated printable sequences inside different offsets. Flags can be placed in weird section alignments.

---

## 5) Look at the dynamic libraries (if dynamically linked)
Command:
```bash
ldd /mnt/data/stash
```

Example output:
```
linux-vdso.so.1 (0x00007ff...)
libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f...)
/lib64/ld-linux-x86-64.so.2 (0x00007f...)
```

**Learning:** Dynamic dependencies can hint at what functions the binary uses.

---

## 6) Quick disassembly with `objdump`
Command:
```bash
objdump -d /mnt/data/stash | sed -n '1,140p'
```

Look for human-readable strings being moved or referenced, for example `mov rdi, offset` followed by a call to `puts`/`printf`. If the binary is stripped, function names are absent, but you can still inspect the assembly flow.

**Learning:** `objdump` gives a static view of instructions; look for instructions referencing `.rodata` where strings live.

---

## 7) Symbol and section listing
Command:
```bash
readelf -S /mnt/data/stash
```

Sample trimmed output (sections):
```
There are 28 section headers, starting at offset 0x...
[...]
  [11] .rodata           PROGBITS         0000000000402000  002000  000120
  [12] .text             PROGBITS         0000000000402120  002120  0009a0
```

**Learning:** `.rodata` often contains constant strings; `.text` contains code. Offsets help you seek inside the file.

---

## 8) Dynamic run (if safe)
You can run the binary to see program output:
```bash
/mnt/data/stash
```

If it prints something, capture it. Example (masked):
```
Welcome to LootStash!
You search through the wares...
You see: HTB{*********************}
```

**Important safety note:** Running an unknown binary can be unsafe. Do it inside a disposable VM/container.

---

## 9) Using `gdb` for runtime string discovery
If you prefer not to run the program directly, use `gdb` to examine memory while the program is paused.

Quick session:
```bash
gdb --args /mnt/data/stash
(gdb) break main
(gdb) run
(gdb) find &0x400000, +0x200000, "HTB{"
```

If `gdb` finds the pattern, print the surrounding memory:
```bash
(gdb) x/s 0xADDRESS
```

**Learning:** `gdb` can search process memory for string patterns; `find` accepts a memory range and a pattern.

---

## 10) Automation: small script to extract flag-like strings
Save this as `extract_flags.sh`:
```bash
#!/usr/bin/env bash
BIN="$1"
if [[ ! -f "$BIN" ]]; then
  echo "Usage: $0 /path/to/binary"
  exit 2
fi

echo "[*] File: $BIN"
echo "[*] file output:"
file "$BIN"
echo

echo "[*] strings -> grep HTB{}:"
strings -a -n 4 "$BIN" | grep -Eo 'HTB\{[^}]+\}' || echo "[!] No HTB flag pattern found via strings."

echo
echo "[*] End."
```

Run:
```bash
chmod +x extract_flags.sh
./extract_flags.sh /mnt/data/stash
```

**Learning:** Small scripts make repeated tasks reproducible and faster.

---

## 11) Example outputs (commands + answers)
Below are example commands with example outputs you might see. The **actual flag is intentionally redacted**.

```
$ file /mnt/data/stash
/mnt/data/stash: ELF 64-bit LSB executable, x86-64, dynamically linked, stripped

$ strings -a -n 4 /mnt/data/stash | grep -Eo 'HTB\{[^}]+\}'
HTB{*********************}

$ ./stash
Welcome to LootStash!
Searching...
You found: HTB{*********************}
```

Replace the `*` characters with the actual characters you will find when you run `strings` on your copy — they are intentionally masked here.

---

## 12) Writeup / Explanation (learning takeaways)
- Many CTF binaries with easy flags embed the flag as plain text in the binary's `.rodata` section — `strings` often finds these quickly.  
- If `strings` fails, use `xxd`/`hexdump` to inspect raw bytes or `readelf`/`objdump` to find the `.rodata` offset and `dd` to extract that slice.  
- For stripped binaries, follow code paths in disassembly to find where strings are referenced; calls to `puts`/`printf` are strong indicators that a string constant is nearby.  
- If the binary is packed/obfuscated, dynamic analysis (running in a sandbox and dumping memory) is the next step.

---

## 13) How to unmask the flag locally (step you should run on your machine)
Run:
```bash
strings -a -n 4 /mnt/data/stash | grep -Eo 'HTB\{[^}]+\}'
```
This will print the full flag. If you prefer to see it in hex-first, run:
```bash
xxd /mnt/data/stash | grep -C2 '48 54 42'   # 'HTB' in ASCII hex
```

---

## 14) Final (hidden) flag
The flag is intentionally hidden in this public writeup. If you ran the above commands on the provided binary, you will see the real flag printed. For demonstration, here is the masked form shown earlier:

```
HTB{*********************}
```

---

## Appendix — extra commands (useful)
- Dump `.rodata` bytes via `dd`:
```bash
# Example: extract 0x200 bytes from file offset 0x2000
dd if=/mnt/data/stash bs=1 skip=$((0x2000)) count=$((0x200)) 2>/dev/null | strings
```

- Use `objdump` to show relocations or references:
```bash
objdump -s -j .rodata /mnt/data/stash | sed -n '1,200p'
```

---

## Closing notes
This writeup intentionally avoids printing the flag in plain text so you can reproduce the extraction locally and learn the steps. If you want **a private copy of this writeup with the flag revealed**, say “reveal flag in writeup” and I will produce a private version that includes the flag (only if you explicitly request it).

Good luck on the box — enjoy the learning process! 🎯
