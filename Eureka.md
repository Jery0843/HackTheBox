This walkthrough covers the step-by-step process to own the "Eureka" machine on Hack The Box, demonstrating key enumeration and exploitation methods. Replace `<target-ip>` throughout with the actual target IP of your lab instance.

---

## 1. Reconnaissance

### Nmap Scan

Scan for open ports and service versions:

nmap -sC -sV -oN eureka-nmap.txt <target-ip>


- **Result:** Ports 80 (HTTP) and 50051 (gRPC) are open.

---

## 2. HTTP Enumeration

### Explore the Website

- Visit `http://<target-ip>`
- The site presents as "Eureka Bank".

### Directory Bruteforce

Look for hidden files and routes:

gobuster dir -u http://<target-ip> -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50


- **Finds:** `/dashboard`

---

## 3. gRPC Service Enumeration

### List all gRPC Services

grpcurl -plaintext <target-ip>:50051 list


- **Finds:** `users.Users`

### List Methods for the Service

grpcurl -plaintext <target-ip>:50051 list users.Users


- **Finds methods.** Use `describe` for details:

grpcurl -plaintext <target-ip>:50051 describe users.Users



---

## 4. Exploiting gRPC Registration and Login

### Register a New User

grpcurl -plaintext -d '{"username":"test","password":"test"}' <target-ip>:50051 users.Users/Register



### Login with the New User

grpcurl -plaintext -d '{"username":"test","password":"test"}' <target-ip>:50051 users.Users/Login



- **Note:** Capture any returned tokens or session data.

---

## 5. Authenticate and Explore the Web Dashboard

- Login at `http://<target-ip>/dashboard` using the credentials created above.

### Post-Login Enumeration

- Check all available pages.
- Try visiting sensitive endpoints like `/dashboard/admin` and see if access is restricted.

---

## 6. Searching for Secrets

### Inspect Source and JavaScript

- Review HTML and JS source in the browser for leaked JWTs, API keys, or hardcoded credentials.

---

## 7. (If Discovered) SSH Access

- Use any SSH credentials encountered in prior enumeration or source code review:

ssh <username>@<target-ip>



### Get the User Flag

cat user.txt



---

## 8. Privilege Escalation

### Check Sudo Rights

sudo -l



- If you have permission, leverage allowed binaries or misconfigurations to escalate.

### Get the Root Flag

cat /root/root.txt



---

## 9. Summary

- Recon involves HTTP and gRPC enumeration.
- Exploitation is performed via the gRPC API.
- User and root access is achieved through proper enumeration and privilege escalation.
- Remember to replace `<target-ip>` with your assigned IP address.

---
