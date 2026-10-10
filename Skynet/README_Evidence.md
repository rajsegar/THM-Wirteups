# Skynet evidence package

**Assessment date:** 10 October 2026  
**Lab:** TryHackMe Skynet; target `10.80.151.179`  
**Provenance:** Evidence supplied in the conversation, not collected independently by the report author.

## Files

- `Skynet_Writeup_GitHub.md` — portfolio-ready Markdown report with relative screenshot links.
- `evidence/terminal-session-original.txt` — user-uploaded pasted terminal transcript, unchanged.
- `evidence/squirrelmail-login-original.png` — user-uploaded browser screenshot, unchanged.
- `evidence/squirrelmail-inbox-original.png` — user-uploaded browser screenshot, unchanged.
- `evidence/supplementary-conversation-excerpts.txt` — curated excerpts from typed chat messages, **not** a raw system export.
- `evidence/manifest.sha256` — cryptographic hashes of the 4 evidence materials listed above.

## Verification boundary

The uploaded terminal file directly shows successful Hydra authentication, the Cuppa local file read containing the user flag, and an HTTP GET for hosted shell.php. Conversation messages additionally show a `www-data@skynet` prompt, a writable web directory, the backup script, and staged tar filenames. The attempt did not produce a recorded SUID binary or a root flag capture. **Do not label the root stage confirmed.**

## Contents and intended use

Authorized, educational TryHackMe lab only. Screenshots use temporary lab addresses. The write-up includes lab passwords and a user flag, so readers should understand that the walkthrough contains spoilers.
