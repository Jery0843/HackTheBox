# Silicon Data Sleuthing — Writeup (fresh, hands-on, learning first)

Short version up front: this writeup shows step-by-step how I extracted useful secrets from the provided `chal_router_dump.bin` firmware image (OpenWrt router image). Every command I ran is included so you can reproduce the exercise. Read the **Lessons learned** section at the end — it contains tips that turn repeated mistakes into reliable methods.

---

## 0) What you were given
- Firmware image: `chal_router_dump.bin` (provided by the challenge)
- Docker spawn / challenge service: `94.237.48.12:43803` (used to validate answers interactively)
- Goal: inspect the firmware and answer many specific questions (OpenWrt version, kernel, root hash, PPPoE creds, Wi-Fi, port redirects, …)

---

## 1) Initial reconnaissance: check structure with `binwalk`

Command:
```bash
binwalk chal_router_dump.bin
```

Important output snippets (relevant offsets):
```
1572864   0x180000   uImage header ... image name: "MIPS OpenWrt Linux-5.15.134"
1578636   0x18168C   LZMA compressed data ...
4375240   0x42C2C8   Squashfs filesystem, little endian, version 4.0, compression:xz
8126464   0x7C0000   JFFS2 filesystem, little endian
```

**Why this matters:** `binwalk` tells you where the kernel, squashfs (rootfs), and JFFS2 overlay live. These offsets let you carve and extract the filesystems that actually contain the config files you need.

---

## 2) Extract filesystem(s)

Preferred (automatic) extraction:
```bash
binwalk -e chal_router_dump.bin
# This creates a folder like _chal_router_dump.bin.extracted
cd _chal_router_dump.bin.extracted
```

If you prefer manual carving:
```bash
# carve the SquashFS at the offset shown by binwalk (4375240)
dd if=../chal_router_dump.bin of=extracted_squashfs.bin bs=1 skip=4375240

# optionally inspect:
file extracted_squashfs.bin
strings extracted_squashfs.bin | head -n 40

# then unsquash (install squashfs-tools if needed)
sudo apt install squashfs-tools xz-utils -y
unsquashfs -d squashfs-root extracted_squashfs.bin
```

To carve and inspect the JFFS2 overlay (if present):
```bash
# carve jffs2 region at offset 8126464 (from binwalk)
dd if=../chal_router_dump.bin of=extracted_jffs2.bin bs=1 skip=8126464
# For readability you can try jefferson to unpack jffs2:
pip3 install jefferson
jefferson extracted_jffs2.bin > jffs2_contents.txt
```

---

## 3) Find the OpenWrt release vs kernel (common riddle)
- The firmware contains kernel string: `MIPS OpenWrt Linux-5.15.134` (this is the Linux kernel version).
- **OpenWrt release** is *not* the kernel version. You need to map kernel ↔ OpenWrt release.

How I derived them:

**Kernel version**
```text
MIPS OpenWrt Linux-5.15.134
```
Answer: **`5.15.134`**

**OpenWrt release**
- Kernel 5.15.134 corresponds to **OpenWrt 23.05.0** (common mapping for that kernel build).
Answer: **`23.05.0`**

(When answering the challenge prompt they wanted the release `23.05.0` — not the kernel number. Then they asked for kernel later and expected `5.15.134`.)

---

## 4) Locate the root account hash

I searched the extracted files for shadow/passwd entries.

Commands used:
```bash
# quick grep inside the extracted directory
cd _chal_router_dump.bin.extracted
grep -R --line-number '^root:' . 2>/dev/null

# or search possible overlays:
find . -type f -iname shadow -o -iname passwd -print -exec sed -n '1,3p' {} \;
```

Key findings (exact file locations and lines):
```
squashfs-root-0/etc/shadow:1:root:::0:99999:7:::
squashfs-root/etc/shadow:1:root:::0:99999:7:::
# BUT a hashed root line existed in jffs2 overlay:
jffs2-root/work/work/#32:1:root:$1$YfuRJudo$cXCiIJXn9fWLIt8WY2Okp1:19804:0:99999:7:::
```

**So the correct `root:` shadow line (the one the challenge accepted) was:**
```
root:$1$YfuRJudo$cXCiIJXn9fWLIt8WY2Okp1:19804:0:99999:7:::
```

**Notes & why this looked odd at first**
- The SquashFS contained `root::...` (no hash) — this is the default / initial state.
- The JFFS2 overlay (writable overlay) contained the actual populated `shadow` entry (the functioning password hash). Always remember overlays can override rootfs defaults.

---

## 5) PPPoE credentials (username & password)

Search strategy:
```bash
# Grep the extracted tree for ppp/pppoe or username/secret patterns
grep -R --line-number -i "username\|pppoe\|chap-secrets\|authname" . 2>/dev/null
# Inspect likely config files (OpenWrt uses /etc/config/network and maybe /etc/ppp/chap-secrets)
sed -n '1,200p' jffs2-root/work/work/#4/network
```

Found `jffs2-root/work/work/#4/network` contained the PPPoE configuration:

```
config interface 'wan'
    option device 'wan'
    option proto 'pppoe'
    option username 'yohZ5ah'
    option password 'ae-h+i$i^Ngohroorie!bieng6kee7oh'
    option ipv6 'auto'
```

**Answer (PPPoE username):** `yohZ5ah`  
**Answer (PPPoE password):** `ae-h+i$i^Ngohroorie!bieng6kee7oh`

Also checked `chap-secrets` locations if present (but in our case the PPPoE credentials were in the `network` UCI file).

---

## 6) Wi-Fi details (SSID and password)

Search:
```bash
# Look at the wireless config in JFFS2 overlay:
sed -n '1,200p' jffs2-root/work/work/#4/wireless
```

Extract:
```
config wifi-iface 'default_radio0'
    option ssid 'VLT-AP01'
    option encryption 'sae-mixed'
    option key 'french-halves-vehicular-favorable'

config wifi-iface 'default_radio1'
    option ssid 'VLT-AP01'
    option key 'french-halves-vehicular-favorable'
```

**WiFi SSID:** `VLT-AP01`  
**WiFi password:** `french-halves-vehicular-favorable`

---

## 7) Firewall port redirections — WAN → LAN (the asked question)

Search:
```bash
# Find redirect definitions in firewall config inside the extracted tree
grep -R "config redirect" -n jffs2-root/work/work/#* 2>/dev/null
# or show the block
sed -n '120,160p' jffs2-root/work/work/#b
```

The `config redirect` block from `jffs2-root/work/work/#b` contained:
```
config redirect
    option name 'DB'
    option src 'wan'
    option src_dport '1778'
    option dest_ip '192.168.1.184'
    option dest_port '5881'

config redirect
    option name 'WEB'
    option src 'wan'
    option src_dport '2289'
    option dest_ip '192.168.1.119'
    option dest_port '9889'

config redirect
    option name 'NAS'
    option src 'wan'
    option src_dport '8088'
    option dest_ip '192.168.1.166'
    option dest_port '4431'
```

**The challenge explicitly asked:** *What are the 3 WAN ports that redirect traffic from WAN -> LAN (numerically sorted, comma separated)*.  
Those are the `src_dport` values (WAN-facing ports) — sorted numerically:

**Answer:** `1778,2289,8088`

(If you submit the `dest_port` list you’ll get it wrong — many people trip on that distinction.)

---

## 8) Everything we submitted and its result (challenge Q&A recap)

- What version of OpenWrt runs on the router?  
  **Answer:** `23.05.0` — (challenge accepted)

- What is the Linux kernel version?  
  **Answer:** `5.15.134` — (challenge accepted)

- Hash of root account (whole line):  
  **Answer:** `root:$1$YfuRJudo$cXCiIJXn9fWLIt8WY2Okp1:19804:0:99999:7:::` — (challenge accepted)

- PPPoE username:  
  **Answer:** `yohZ5ah` — (accepted)

- PPPoE password:  
  **Answer:** `ae-h+i$i^Ngohroorie!bieng6kee7oh` — (accepted)

- WiFi SSID:  
  **Answer:** `VLT-AP01` — (accepted)

- WiFi password:  
  **Answer:** `french-halves-vehicular-favorable` — (accepted)

- The 3 WAN ports that redirect traffic from WAN -> LAN (numerically sorted):  
  **Answer:** `1778,2289,8088` — (accepted)

---

## 9) Where each item was found (quick index)
- Kernel string: inside `uImage` header / binwalk output (offset 1572864) → shows `MIPS OpenWrt Linux-5.15.134`.
- OpenWrt release: inferred from kernel → `23.05.0`.
- `root:` hash: `jffs2-root/work/work/#32` (overlay) → `root:$1$YfuRJudo$cXCiIJXn9fWLIt8WY2Okp1:...`.
- PPPoE credentials: `jffs2-root/work/work/#4/network`.
- Wi-Fi config: `jffs2-root/work/work/#4/wireless`.
- Port forwards: `jffs2-root/work/work/#b` (firewall `config redirect` blocks).

---

## 10) Extra useful commands (cheat sheet)

```bash
# Inspect firmware structure
binwalk chal_router_dump.bin

# Auto extract
binwalk -e chal_router_dump.bin
cd _chal_router_dump.bin.extracted

# Carve squashfs manually if needed (replace offset)
dd if=../chal_router_dump.bin of=extracted_squashfs.bin bs=1 skip=4375240
file extracted_squashfs.bin
unsquashfs -d squashfs-root extracted_squashfs.bin

# Carve jffs2 region for overlay
dd if=../chal_router_dump.bin of=extracted_jffs2.bin bs=1 skip=8126464
pip3 install jefferson
jefferson extracted_jffs2.bin > jffs2_contents.txt

# Search extracted tree
grep -R --line-number -i "root:\|shadow\|\$1\$\|\$6\$" . 2>/dev/null
grep -R --line-number -i "pppoe\|username\|password" . 2>/dev/null
grep -R --line-number -i "wifi\|ssid\|key\|psk" . 2>/dev/null
grep -R --line-number -i "config redirect\|src_dport\|dest_port" . 2>/dev/null

# Show a file
sed -n '1,200p' path/to/file
```

---

## 11) Lessons learned — practical tips
1. **Always look at overlays** (JFFS2, UBI, etc.). The writable overlay often contains runtime settings (passwords, user modifications) while the read-only squashfs contains defaults.
2. **Distinguish kernel vs OpenWrt release** — challenge authors will test you on both. Kernel = `uname -r` style string; OpenWrt release is e.g. `21.02.x`, `22.03.x`, `23.05.x`.
3. **`src_dport` vs `dest_port`** — when questions ask “WAN ports that redirect traffic from WAN -> LAN,” they mean the **WAN-facing** ports (`src_dport`), not the internal `dest_port`.
4. **Search compressed blobs** — images may contain LZMA/XZ/GZIP sections pointing to config archives (binwalk, strings + decompress attempts help).
5. **Keep your grep patterns broad but refine** — start with `pppoe|username|password|ssid|shadow` then narrow to the file once you find a candidate.

---

## 12) The flag (hidden)

The challenge produced the final flag. You asked to **hide** it in the writeup. I will **not** paste the plaintext flag directly; instead I’m providing it **Base64 encoded** so it is hidden on sight but trivially decodable if needed.

**Flag (Base64-encoded):**
```
SFRCe1kwdSd2M19tNHNEwbiEhX2VkOGFkNWJjZTkxNTA3Yzc1MmRjOTVjNGMxYjFjNmZifQ==
```

If you want to reveal it locally, run:
```bash
echo 'SFRCe1kwdSd2M19tNHN0M3IzZkOGFkNWJjZTkxNTA3Yzc1MmRjOTVjNGMxYjFjNmZifQ=='   | base64 -d
```

---

## 13) Closing notes
- This challenge is a great test of firmware forensics fundamentals: carving fs partitions, understanding OpenWrt file layout, and tracing overlays for live credentials.
- If you want, I can produce a pared-down one-page cheat sheet (commands only), or generate a small script that automates the extraction + grep steps (so you can feed other firmware images through the same pipeline).

Congrats on finishing the challenge — you earned it! 🎉
