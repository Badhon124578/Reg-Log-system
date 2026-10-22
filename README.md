# Secure Access Console

A fully terminal-based account registration and login application. It provides
user account management, password recovery, local JSON storage, and a protected
administrator console. It does not start a web server or require a browser.

## Run it

```bash
python main.py
```

On first run, the terminal prompts you to choose an administrator username and
password. Admin passwords are hidden while typing, must be at least 12
characters, and are stored as salted PBKDF2-HMAC-SHA256 hashes. Existing admin
records from older versions must be replaced through this setup before admin
login is enabled.

User passwords are also entered without terminal echo. The admin console locks
after three unsuccessful login attempts for five minutes and lets the
administrator change their password after authenticating. Older supported
password hashes are upgraded to the current PBKDF2 work factor after a
successful login.

## Features

- Registration and login with email or phone number
- Password recovery with a key shown when the account is registered
- Profile updates and password-confirmed account deletion
- Admin user summary, account listing, and account deletion
- Searchable, paginated administrator user directory
- Administrator account deactivation/reactivation and login-lockout clearing
- Security report for credential hashes, duplicate identities, and storage permissions
- Bounded audit-log search and private CSV export
- Private account backups with structural validation and rollback before restore
- Local activity log and lockout after repeated user login failures
- Atomic JSON writes and restrictive local storage permissions
- Terminal-safe input handling and no GUI or web interface

## Data and security

The application stores account and session data under `data/`. On POSIX
systems, it restricts the data directory to the current user and account,
session, and activity files to owner-only access. Keep this directory private
and make backups before removing or migrating it.

Administrator backups are stored under `data/` with owner-only permissions on
POSIX systems. A backup contains password hashes and account recovery keys.
Restoring a backup replaces the current account and administrator records, and
the application requires a separate rollback backup before it proceeds. Keep
backups and audit CSV exports private, and remove old copies when they are no
longer needed.

This project is intended for local educational use, not as a production
authentication service. Local file permissions do not protect data from
another process running as the same operating-system user.

## Tests

Run the standard-library test suite with:

```bash
python -m unittest discover -s tests -v
```
