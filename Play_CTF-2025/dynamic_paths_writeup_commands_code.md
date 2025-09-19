# Dynamic Paths — HTB Play CTF — Commands & Code

**Difficulty:** Easy — Dynamic Programming (Grid DP)

This document contains *every* command and *every* source file used to solve the challenge, plus a hidden flag at the end.

---

## 1) Quick connection check (optional)
```bash
nc 94.237.49.214 33478
# View the service banner and example. Press Ctrl+C to quit.
```

---

## 2) Pure-socket solver (robust)
Save the following into `solve_socket.py`.

```python
#!/usr/bin/env python3
import socket
import re

HOST = "94.237.49.214"
PORT = 33478
TIMEOUT = 30

# Matches a line with two integers (rows cols)
dims_re = re.compile(r'^\s*(\d+)\s+(\d+)\s*$')

def min_path_sum(grid, n, m):
    dp = [[0]*m for _ in range(n)]
    dp[0][0] = grid[0][0]
    for j in range(1, m):
        dp[0][j] = dp[0][j-1] + grid[0][j]
    for i in range(1, n):
        dp[i][0] = dp[i-1][0] + grid[i][0]
        for j in range(1, m):
            dp[i][j] = min(dp[i-1][j], dp[i][j-1]) + grid[i][j]
    return dp[-1][-1]


def run():
    with socket.create_connection((HOST, PORT), timeout=TIMEOUT) as s:
        s_file = s.makefile(mode='rw', buffering=1, encoding='utf-8', newline='\n')

        buffer_ints = []
        expect_nums = 0
        current_dims = None
        in_real_test = False
        tests_done = 0

        while True:
            line = s_file.readline()
            if line == '':
                print("[*] Connection closed by remote.")
                break
            line_stripped = line.rstrip('\n')
            print(line_stripped)

            # The server prints "Test X/100" before the real tests
            if line_stripped.startswith("Test"):
                in_real_test = True
                current_dims = None
                buffer_ints = []
                expect_nums = 0
                continue

            if not in_real_test:
                # ignore example block
                continue

            if current_dims is None:
                m = dims_re.match(line_stripped)
                if m:
                    n, mm = int(m.group(1)), int(m.group(2))
                    current_dims = (n, mm)
                    expect_nums = n * mm
                    buffer_ints = []
                continue

            parts = re.findall(r'-?\d+', line_stripped)
            if parts:
                buffer_ints.extend(map(int, parts))

            if current_dims is not None and len(buffer_ints) >= expect_nums:
                n, mm = current_dims
                nums = buffer_ints[:expect_nums]
                grid = [nums[i*mm:(i+1)*mm] for i in range(n)]
                ans = min_path_sum(grid, n, mm)
                s.sendall((str(ans) + '\n').encode())
                tests_done += 1
                print(f"[->] Sent: {ans}  (Solved {tests_done}/100)")
                current_dims = None
                buffer_ints = []
                expect_nums = 0

if __name__ == "__main__":
    run()
```

Run it:
```bash
chmod +x solve_socket.py
python3 solve_socket.py
```

---

## 3) Pwntools variant (optional)
If you like `pwntools`, use this client. Save as `solve_pwntools.py`.

```python
#!/usr/bin/env python3
from pwn import remote
import re

HOST = '94.237.49.214'
PORT = 33478

dims_re = re.compile(r'^\s*(\d+)\s+(\d+)\s*$')

def min_path_sum(grid, n, m):
    dp = [[0]*m for _ in range(n)]
    dp[0][0] = grid[0][0]
    for j in range(1, m):
        dp[0][j] = dp[0][j-1] + grid[0][j]
    for i in range(1, n):
        dp[i][0] = dp[i-1][0] + grid[i][0]
        for j in range(1, m):
            dp[i][j] = min(dp[i-1][j], dp[i][j-1]) + grid[i][j]
    return dp[-1][-1]

conn = remote(HOST, PORT)
buffer_ints = []
expect_nums = 0
current_dims = None
in_real_test = False
tests_done = 0

while True:
    try:
        line = conn.recvline(timeout=60).decode('utf-8', errors='ignore')
    except Exception:
        print('[*] Connection closed or timed out')
        break
    if not line:
        print('[*] No more data')
        break
    print(line.strip())

    if line.startswith('Test'):
        in_real_test = True
        current_dims = None
        buffer_ints = []
        expect_nums = 0
        continue

    if not in_real_test:
        continue

    if current_dims is None:
        m = dims_re.match(line.strip())
        if m:
            n, mm = int(m.group(1)), int(m.group(2))
            current_dims = (n, mm)
            expect_nums = n * mm
        continue

    parts = re.findall(r'-?\d+', line)
    if parts:
        buffer_ints.extend(map(int, parts))
    if current_dims is not None and len(buffer_ints) >= expect_nums:
        n, mm = current_dims
        nums = buffer_ints[:expect_nums]
        grid = [nums[i*mm:(i+1)*mm] for i in range(n)]
        ans = min_path_sum(grid, n, mm)
        conn.sendline(str(ans))
        tests_done += 1
        print(f"[->] Sent: {ans}  (Solved {tests_done}/100)")
        current_dims = None
        buffer_ints = []
        expect_nums = 0

conn.close()
```

Install pwntools and run:
```bash
pip3 install --user pwntools
python3 solve_pwntools.py
```

---

## 4) One-row memory-optimized DP (drop-in replacement)
If you want less memory usage, replace `min_path_sum` with this single-row version (keeps O(m) memory):

```python
def min_path_sum_one_row(grid, n, m):
    row = [0]*m
    row[0] = grid[0][0]
    for j in range(1, m):
        row[j] = row[j-1] + grid[0][j]
    for i in range(1, n):
        row[0] += grid[i][0]
        for j in range(1, m):
            row[j] = min(row[j], row[j-1]) + grid[i][j]
    return row[-1]
```

You can call this function instead of the 2D `min_path_sum` for identical results.

---

## 5) Troubleshooting checklist
- Ensure you **do not** send answers during the example block. The client sets `in_real_test` only after seeing `Test`.
- Confirm `n*m` integers are read before computing — server may split numbers across lines.
- Increase socket timeout from `30` to `60` if needed.
- If you get killed early, copy the last server messages and paste them into the terminal or here for help.

---

## 6) Final (hidden) flag
<details>
<summary>Click to reveal the flag</summary>

</details>

---

If you want the file zipped or a version with progress logging to a file, tell me and I will update it.

