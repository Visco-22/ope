# userwatch

userwatch watches your Linux machine in real time and alerts you when someone does something suspicious. It monitors who logs in, what commands get run with elevated privileges, whether any new accounts appear, and whether anyone tries to kill your scored services.

---

## How to run it

```bash
sudo bash userwatch.sh
```

Run it as root. Leave it running in a terminal — it prints alerts as they happen. Stop it with `Ctrl+C`.

If you try to start it twice, it will tell you it's already running and show you the process ID.

---

## What it watches

**Logins and logouts** — every few seconds it checks who is logged in. When someone new appears or disappears, it prints a line immediately.

**Auth log** — it reads the system authentication log in the background. It catches:
- Every sudo command (and classifies it)
- Failed sudo / su attempts
- Anyone using `su` to switch to root or another user
- SSH logins (accepted and failed)
- FTP and SMB login attempts (accepted and failed)

**Running processes** — every few seconds it scans all running processes. If a process is running as root but was started by a different user, that gets flagged. Known attack tools (Metasploit, Sliver, Saprus C2, etc.) are always flagged regardless.

**New accounts** — if a new user account appears in `/etc/passwd` after startup, it's flagged immediately.

**Filesystem artifacts** — checks for known red team drop locations: `/etc/.redteam/`, executables sitting in `/dev/shm`, and any new files added to `/etc/cron.d/` after the script started.

---

## Alert colors

| Color | Label | What it means |
|---|---|---|
| Red | `[REDTEAM]` | Active attack in progress — shells, credential theft, backdoors, firewall tampering |
| Yellow | `[SCORING]` | Something that will break your score — service killed, data destroyed, system rebooted |
| Cyan | `[OTHER]` | Someone is poking around — running recon commands, listing users, checking network state |
| Green | `[LOGIN]` | A login was accepted — SSH, FTP, or SMB. Not an alert, just informational |
| Cyan | `[LOGOUT]` | A terminal session ended |

The person running userwatch is never alerted on.

If the same attack repeats rapidly (like a password brute force), userwatch only prints once every 30 seconds per attacker so the screen doesn't flood. Every single event is still written to the log file.

---

## Files it creates

| File | What's in it |
|---|---|
| `user_report.txt` | Snapshot of all accounts, root UIDs, sudo rights, and active sessions — written at startup |
| `userActivity/<user>.txt` | Everything that user did, one file per account |
| `SCORING-Users.txt` | Human accounts (normal login accounts) found when the script started |
| `REDTEAM-Users.txt` | Accounts that triggered a REDTEAM alert or were created while the script was running |
| `userwatch.log` | Full record of every event — never filtered, never rate-limited |
| `userwatch.pid` | The process ID of the running script |

---

## services.txt

This file lists the services that are actually scored in the competition. When userwatch sees a command that names one of these services alongside words like `stop`, `kill`, or `disable`, it escalates the alert to `[SCORING]` — even if the command wouldn't normally match that tier.

Edit this file to add or remove services. One name per line, lines starting with `#` are ignored.

Default services: apache2, nginx, php-fpm, sshd, vsftpd, smbd, nmbd, bind9, named, mysql, mariadb, postgresql.

---

## What triggers REDTEAM

- Opening a shell back to an attacker's machine (reverse shell)
- Downloading and running files from the internet
- Sending files off the machine to another host
- Reading `/etc/shadow` or private SSH keys
- Adding users, changing passwords, editing sudoers
- Turning off the firewall or disabling SELinux/AppArmor
- Installing persistence (crontab edits, bashrc changes, new systemd services, PAM files)
- Modifying SSH config, DNS zone files, or database user accounts
- Running a debugger or process tracer against another process
- Creating web shells

## What triggers SCORING

- Stopping, disabling, or masking a service with `systemctl` or `service`
- Killing processes with `pkill`, `killall`, or `kill -N`
- Running `shutdown`, `reboot`, `halt`, or `poweroff`
- Wiping data with `rm -rf`, `dd`, `mkfs`, or `fdisk`
- Overwriting or deleting web content in `/var/www/`
- Wiping cron jobs with `crontab -r`

---

## Tuning

| Setting | Where | Default |
|---|---|---|
| How often it scans | `POLL_INTERVAL` near top of script | 3 seconds |
| Brute-force rate limit | `BRUTE_FORCE_WINDOW` near top of script | 30 seconds |
| Scored services list | `services.txt` | See above |
