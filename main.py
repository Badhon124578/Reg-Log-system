#!/usr/bin/env python3
"""Advanced Registration and Login System.

This project is a modernized console-based authentication application designed to
provide a safe, user-friendly, and reliable workflow for registering, logging in,
updating profiles, and deleting accounts. It replaces the original fragile script
with a more robust architecture, stronger validation, file-backed persistence,
activity logging, and an admin panel.

Key objectives:
- Support clean registration with validation
- Secure password storage using PBKDF2-HMAC-SHA256
- persistent storage via JSON files
- account lockout after repeated failures
- profile management and account deletion
- audit logging and admin monitoring
- resilient terminal behavior when no TTY is available
"""

from __future__ import annotations

import csv
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import tempfile
import time
from collections import Counter, deque
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

APP_NAME = "Secure Access Console"
APP_VERSION = "2.0.0"

DATA_DIR = Path(__file__).resolve().parent / "data"
USERS_FILE = DATA_DIR / "users.json"
ACTIVITY_LOG = DATA_DIR / "activity.log"
SESSION_FILE = DATA_DIR / "session.json"
PASSWORD_HASH_ITERATIONS = 600_000
LEGACY_PASSWORD_HASH_ITERATIONS = 120_000
ADMIN_CREDENTIAL_VERSION = 1
MAX_PASSWORD_HASH_ITERATIONS = 2_000_000
ADMIN_MAX_FAILED_ATTEMPTS = 3
ADMIN_LOCKOUT_MINUTES = 5
MAX_AUDIT_RESULTS = 500
MAX_USER_PAGE_SIZE = 10

FEATURES = [
    "Account registration with validation",
    "Strong password verification",
    "Duplicate account protection",
    "Delete-key recovery workflow",
    "Password reset support",
    "Profile updates",
    "Admin panel with user listing",
    "Activity logging",
    "Input sanitization",
    "Safe terminal handling",
    "File-backed persistence",
    "Account lockout prevention",
    "User-friendly menu system",
    "Graceful error handling",
    "Multi-step wizard for onboarding",
    "Time-based audit records",
    "Security best-practice guidance",
    "Recovery workflows",
    "Session tracking",
    "Operational resilience",
    "Searchable administrator user directory",
    "Administrator account access controls",
    "Bounded audit history review and private CSV export",
    "Validated account backups with rollback protection",
    "Account-store security diagnostics",
]

SECURITY_TIPS = [
    "Use a unique password never reused on other sites.",
    "Keep your recovery key in a safe password manager or secure note.",
    "Enable the admin panel only when you trust the local environment.",
    "Do not share your account details with anyone.",
    "Review activity logs regularly to detect suspicious behavior.",
    "Use strong passwords with uppercase, lowercase, numbers, and symbols.",
    "Change your password after any security incident or suspicious login.",
    "Never write secrets into source-controlled environment files.",
]

HELP_TOPICS = [
    "Registration: create a new account with validated personal data.",
    "Login: sign in using your phone number and password.",
    "Profile: view and update your stored details.",
    "Delete: permanently remove your account after confirmation.",
    "Admin: review accounts and system activity when authorized.",
    "Reset: recover an account using a verified recovery key.",
    "Status: confirm whether the app is storing data correctly.",
    "Support: follow the secure login workflows designed for local use.",
    "Audit: administrators can search recent activity events.",
    "Backup: administrators can create private account-store snapshots.",
]

COMMON_ERRORS = [
    "Field cannot be empty.",
    "Please enter a valid phone number.",
    "Please enter a valid email address.",
    "Password must be at least 8 characters long.",
    "Passwords do not match.",
    "That phone number is already registered.",
    "Your account has been locked. Please wait a bit and try again.",
    "You entered an invalid choice. Please try again.",
    "Recovery key is invalid or already in use.",
    "Account not found. Please check your details and try again.",
]

ASCII_BANNER = r"""
     ___    _   _   ___   ___   ___   ___   _____   ___   ___   ___   ___
    / _ \  | | | | / _ \ / _ \ / _ \\ / _ \ /  ___| / _ \\ / _ \\ / _ \\ / _ \
   / /_\ \ | |_| |/ /_\ \\ \/ / / /_\ \\ / /_\\\ \___ \ / /_\ \\ / /_\ \\ / /_\\
   |  _  | |  _  ||  _  |\  / / /_\\ \\ \/ /|\___ \\|  _  ||  _  ||  _  |
   | | | | | | | || | | |/ / / /_\\ \\  / /  ___) || | | || | | || | | |
   |_| |_| |_| |_||_| |_/_/ /_/   \_\/_/  |_____/ |_| |_||_| |_||_| |_|
"""

ADMIN_HELP_TEXT = """
Administrative Notes:
- Local data files are stored in the project's /data folder.
- Admin mode is designed for a trusted local environment.
- Activity logs record successful and failed login events.
- All stored account data remains in JSON format for clarity and portability.
- Administrators should use the built-in listing and validation commands instead of editing data files directly.
- Backups contain password hashes and recovery keys and must be kept private.
- Restore always requires confirmation and creates a rollback snapshot first.
- CSV audit exports contain account activity metadata and are owner-only on POSIX systems.
"""

INFO_BLOCK = """
System Overview
1. Users can register with identity information, phone number, and password.
2. Passwords are hashed with PBKDF2-HMAC-SHA256 before being stored.
3. Recovery keys are generated and saved alongside the account record.
4. All actions are logged to an activity file for auditing.
5. Admin mode allows operational monitoring without manual file editing.
6. The app is intentionally built for local practice and educational use.
7. Admin security reports summarize storage and account credential health.
8. Admin backup tools validate data before restoration and preserve a rollback copy.
9. Audit review supports keyword filtering and bounded result counts.
"""

REFERENCE_GUIDE = """
System Reference Guide

Section A: Registration Workflow
A1. A user opens the application and selects "Register account".
A2. The program asks for first name, last name, email, and phone number.
A3. Input fields are checked for emptiness, invalid syntax, and duplicate records.
A4. Password creation is validated with minimum length and complexity rules.
A5. A recovery key is generated and displayed once for safekeeping.
A6. The user account is saved to JSON storage and a log entry is written.

Section B: Login Workflow
B1. The user enters a phone number or email and password.
B2. The app locates the account and validates the password hash.
B3. Failed password attempts are counted and account lockout begins after three consecutive failures.
B4. Successful logins update the last_login timestamp and session metadata.
B5. Logged-in users can view their profile, update personal details, or deactivate their account.

Section C: Password Recovery
C1. The user selects "Recover password" from the main menu.
C2. The application matches the identifier to an existing account.
C3. The user provides their recovery key to confirm ownership.
C4. The user enters and confirms a new password that meets security rules.
C5. Password hash is refreshed and the account lockout state is cleared.

Section D: Admin Mode
D1. The administrator creates a unique username and password during first-run setup.
D2. Admin passwords are hidden in the terminal and hashed before they are stored.
D3. The console locks admin login for five minutes after three failed attempts.
D4. The admin can change their password after confirming the current password.
D5. The system exposes summary data, a user list, and account deletion controls.
D6. Admin functions should only be used in a trusted local environment.
D7. Admins can search the user directory and disable or reactivate accounts.
D8. Admins can clear a user's failed-login lockout without changing credentials.
D9. Admins can review a bounded set of audit records and create a private CSV export.
D10. Account backups are stored in the private data folder and include recovery keys.
D11. Restoring a backup validates its structure and creates a rollback copy first.

Section E: Security Notes
E1. Keep recovery keys separate from the main password.
E2. Do not reuse the same password across websites.
E3. Use a password manager when storing account access details.
E4. Local JSON storage is not encrypted; protect the data directory and backups.
E5. Ensure the `data` directory is protected from unauthorized modification.

Section F: Troubleshooting
F1. If the app clears the screen unexpectedly, it is likely running in a non-tty environment.
F2. If login fails, confirm that the phone number and password match exactly.
F3. If account lockout triggers, wait five minutes before retrying.
F4. If a profile update fails, validate the phone number, email, and uniqueness rules.
F5. If the app cannot read storage, review the `data` folder and ensure JSON files are not corrupted.

Section G: Operational Best Practices
G1. Back up the `data/` folder before making changes to the production environment.
G2. Review log entries on a regular schedule to detect suspicious sign-ins.
G3. Add custom validation rules when the user base grows beyond the initial educational scope.
G4. Keep the application updates simple and deterministic for testing and debugging.
G5. Use clear, consistent naming conventions to prevent confusion between accounts and admin records.

Example records:
- User A: Jane Doe, jane@example.com, +15550199
- User B: John Smith, john@example.com, +15554567
- The administrator chooses a username and password during first-run setup.

Scenario checklist:
- New account registration with valid data
- New account registration with duplicate phone number
- Login with correct password
- Login with incorrect password repeated three times
- Password recovery using a valid key
- Account deletion requiring password confirmation
- Admin listing of all registered users
- User profile update to change email and phone number
- Main menu exit flow and safe shutdown

Additional system reminders:
- Review logs after every smoke test.
- Never hardcode production secrets into the repository.
- Keep the `data` folder writable only for the current local actor.
- Use a password manager to avoid accidental reuse of weak credentials.
- Do not expose the recovery key to an untrusted user or support channel.
- Validate edge cases such as empty input, duplicate records, and timeout-based lockouts.
- Add new tests whenever the registration logic changes.
- Keep help text in sync with the main menu options to reduce user confusion.
- Prefer clear messages over silent failure when an operation cannot complete.
- Always confirm destructive actions with explicit password or recovery-key verification.
"""


def safe_input(prompt: str) -> str:
    """Return a prompt answer without crashing if no TTY is attached."""
    try:
        return input(prompt)
    except EOFError:
        print("\nInput stream closed. Returning to the previous menu.")
        return ""
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting safely.")
        raise SystemExit(0)


def safe_secret(prompt: str) -> str:
    """Read a password without echoing it to the terminal."""
    try:
        return getpass.getpass(prompt)
    except EOFError:
        print("\nInput stream closed. Returning to the previous menu.")
        return ""
    except KeyboardInterrupt:
        print("\nKeyboard interrupt received. Exiting safely.")
        raise SystemExit(0)


def clear_screen() -> None:
    """Clear the terminal safely when possible. Avoid crashing in non-tty mode."""
    if sys.stdout is not None and hasattr(sys.stdout, "isatty") and sys.stdout.isatty():
        if os.name == "nt":
            os.system("cls")
        else:
            os.system("clear")


def now_iso() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def log_event(message: str) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    safe_message = sanitize_terminal_text(message)
    with open(ACTIVITY_LOG, "a", encoding="utf-8") as log_file:
        log_file.write(f"[{now_iso()}] {safe_message}\n")
    restrict_permissions(ACTIVITY_LOG, 0o600)


def sanitize_terminal_text(value: Any) -> str:
    """Remove terminal control characters before displaying untrusted stored text."""
    return "".join(
        character if character.isprintable() and character not in "\r\n" else " "
        for character in str(value)
    )


def is_password_hash_well_formed(stored_hash: Any) -> bool:
    """Check stored hash metadata without attempting a password verification."""
    if not isinstance(stored_hash, str):
        return False
    try:
        if stored_hash.startswith("pbkdf2_sha256$"):
            algorithm, rounds, salt, digest = stored_hash.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            iterations = int(rounds)
            if not LEGACY_PASSWORD_HASH_ITERATIONS <= iterations <= MAX_PASSWORD_HASH_ITERATIONS:
                return False
            return bool(
                re.fullmatch(r"[0-9a-fA-F]{32}", salt)
                and re.fullmatch(r"[0-9a-fA-F]{64}", digest)
            )
        else:
            salt, digest = stored_hash.split("$", 1)
        return bool(salt and re.fullmatch(r"[0-9a-fA-F]{64}", digest))
    except (ValueError, TypeError):
        return False


def is_legacy_password_hash(stored_hash: Any) -> bool:
    """Identify a valid pre-versioned hash that still uses the legacy work factor."""
    if not isinstance(stored_hash, str) or stored_hash.startswith("pbkdf2_sha256$"):
        return False
    return is_password_hash_well_formed(stored_hash)


def password_needs_rehash(stored_hash: Any) -> bool:
    """Detect legacy or lower-cost password hashes for upgrade after successful login."""
    if is_legacy_password_hash(stored_hash):
        return True
    if not is_password_hash_well_formed(stored_hash):
        return False
    try:
        _, rounds, _, _ = stored_hash.split("$", 3)
        return int(rounds) < PASSWORD_HASH_ITERATIONS
    except (TypeError, ValueError):
        return False


def validate_account_store(data: Any) -> Tuple[bool, str]:
    """Validate the outer account-store shape before it is persisted or restored."""
    if not isinstance(data, dict):
        return False, "The account store must be a JSON object."
    users = data.get("users")
    admin = data.get("admin")
    if not isinstance(users, list):
        return False, "The account store must contain a users list."
    if admin is not None and not isinstance(admin, dict):
        return False, "The administrator record must be an object or null."
    for index, user in enumerate(users, start=1):
        if not isinstance(user, dict):
            return False, f"User record {index} is not an object."
        if not user.get("id") or not user.get("email") or not user.get("phone"):
            return False, f"User record {index} is missing a required identity field."
        if not is_password_hash_well_formed(user.get("password_hash")):
            return False, f"User record {index} has an invalid password hash."
    if admin is not None and not is_password_hash_well_formed(admin.get("password_hash")):
        return False, "The administrator record has an invalid password hash."
    return True, ""


def read_audit_events(limit: int = 100, keyword: str = "") -> List[str]:
    """Return the newest matching audit records, with a bounded memory footprint."""
    if not isinstance(limit, int) or not 1 <= limit <= MAX_AUDIT_RESULTS:
        raise ValueError(f"Audit result limit must be between 1 and {MAX_AUDIT_RESULTS}.")
    if not ACTIVITY_LOG.exists():
        return []

    matches: deque[str] = deque(maxlen=limit)
    normalized_keyword = keyword.strip().casefold()
    try:
        with ACTIVITY_LOG.open("r", encoding="utf-8") as log_file:
            for line in log_file:
                event = sanitize_terminal_text(line.rstrip("\r\n"))
                if not normalized_keyword or normalized_keyword in event.casefold():
                    matches.append(event)
    except OSError as error:
        raise RuntimeError(f"Unable to read activity log at {ACTIVITY_LOG}.") from error
    except UnicodeError as error:
        raise RuntimeError(f"Activity log at {ACTIVITY_LOG} is not valid UTF-8.") from error
    return list(reversed(matches))


def export_audit_events(keyword: str = "") -> Path:
    """Write a private CSV export to the application data directory."""
    events = read_audit_events(limit=MAX_AUDIT_RESULTS, keyword=keyword)
    export_name = (
        f"activity-export-{datetime.now().strftime('%Y%m%d-%H%M%S')}-"
        f"{secrets.token_hex(4)}.csv"
    )
    export_path = DATA_DIR / export_name
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    restrict_permissions(DATA_DIR, 0o700)
    try:
        descriptor = os.open(
            export_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as export_file:
            writer = csv.writer(export_file)
            writer.writerow(("timestamp", "event"))
            for event in reversed(events):
                timestamp, separator, message = event.partition("] ")
                if separator and timestamp.startswith("["):
                    timestamp = timestamp[1:]
                else:
                    timestamp, message = "", event
                if message.lstrip().startswith(("=", "+", "-", "@", "\t")):
                    message = "'" + message
                writer.writerow((timestamp, message))
            export_file.flush()
            os.fsync(export_file.fileno())
    except OSError as error:
        raise RuntimeError(f"Unable to export activity log to {export_path}.") from error
    return export_path


def list_data_backups() -> List[Path]:
    """List application-generated backups without accepting caller-supplied paths."""
    if not DATA_DIR.exists():
        return []
    return sorted(
        (
            path
            for path in DATA_DIR.glob("backup-users-*.json")
            if path.is_file() and path.resolve().parent == DATA_DIR.resolve()
        ),
        reverse=True,
    )


def create_data_backup() -> Path:
    """Create a uniquely named, owner-only snapshot of the account store."""
    payload = load_users()
    valid, reason = validate_account_store(payload)
    if not valid:
        raise RuntimeError(f"Current account data cannot be backed up: {reason}")
    backup_path = DATA_DIR / (
        f"backup-users-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(4)}.json"
    )
    write_json_atomically(backup_path, payload)
    return backup_path


def load_validated_backup(backup_path: Path) -> Dict[str, Any]:
    """Load a backup only when it is a direct child of the private data directory."""
    data_root = DATA_DIR.resolve()
    resolved_path = backup_path.resolve()
    if resolved_path.parent != data_root or not resolved_path.name.startswith("backup-users-"):
        raise ValueError("The selected backup is outside the application backup directory.")
    try:
        payload = json.loads(resolved_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Unable to read backup file {resolved_path.name}.") from error
    valid, reason = validate_account_store(payload)
    if not valid:
        raise ValueError(f"Backup file is invalid: {reason}")
    return payload


def storage_file_mode(path: Path) -> str:
    """Describe a storage file's access mode without assuming POSIX permissions."""
    if not path.exists():
        return "missing"
    if os.name == "nt":
        return "platform-managed"
    try:
        return f"{path.stat().st_mode & 0o777:04o}"
    except OSError:
        return "unavailable"


def restrict_permissions(path: Path, mode: int) -> None:
    if os.name != "nt":
        path.chmod(mode)


def ensure_storage() -> None:
    DATA_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)
    restrict_permissions(DATA_DIR, 0o700)
    if not USERS_FILE.exists() or USERS_FILE.stat().st_size == 0:
        store_was_empty = USERS_FILE.exists()
        save_users({"users": [], "admin": None})
        if store_was_empty:
            log_event("Empty account data store initialized; administrator setup is required.")
        else:
            log_event("Customer data store initialized.")
    if not SESSION_FILE.exists():
        write_json_atomically(SESSION_FILE, {"last_user": None})


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PASSWORD_HASH_ITERATIONS,
    )
    return f"pbkdf2_sha256${PASSWORD_HASH_ITERATIONS}${salt}${digest.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        if stored_hash.startswith("pbkdf2_sha256$"):
            algorithm, rounds, salt, digest_hex = stored_hash.split("$", 3)
            if algorithm != "pbkdf2_sha256":
                return False
            iterations = int(rounds)
        else:
            salt, digest_hex = stored_hash.split("$", 1)
            iterations = LEGACY_PASSWORD_HASH_ITERATIONS
        if not LEGACY_PASSWORD_HASH_ITERATIONS <= iterations <= MAX_PASSWORD_HASH_ITERATIONS:
            return False
        derived = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            salt.encode("utf-8"),
            iterations,
        )
        return hmac.compare_digest(derived.hex(), digest_hex)
    except (ValueError, TypeError, AttributeError):
        return False


def load_users() -> Dict[str, Any]:
    ensure_storage()
    try:
        data = json.loads(USERS_FILE.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as error:
        raise RuntimeError(f"Unable to read account storage at {USERS_FILE}.") from error
    if (
        not isinstance(data, dict)
        or not isinstance(data.get("users"), list)
        or data.get("admin") is not None
        and not isinstance(data.get("admin"), dict)
    ):
        raise RuntimeError(f"Account storage at {USERS_FILE} has an invalid format.")
    return data


def save_users(data: Dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    write_json_atomically(USERS_FILE, data)


def write_json_atomically(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_path = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=2)
            file.flush()
            os.fsync(file.fileno())
        restrict_permissions(Path(temporary_path), 0o600)
        os.replace(temporary_path, path)
        restrict_permissions(path, 0o600)
    finally:
        if os.path.exists(temporary_path):
            os.unlink(temporary_path)


def normalize_phone(value: str) -> str:
    digits = re.sub(r"\D", "", value)
    return digits


def validate_phone(value: str) -> bool:
    digits = normalize_phone(value)
    return len(digits) >= 10 and digits.isdigit()


def validate_email(value: str) -> bool:
    pattern = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$"
    return bool(re.fullmatch(pattern, value.strip()))


def validate_password(password: str) -> Tuple[bool, str]:
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one number."
    if not re.search(r"[^A-Za-z0-9]", password):
        return False, "Password must contain at least one special character."
    return True, ""


def validate_admin_password(password: str, username: str) -> Tuple[bool, str]:
    if len(password) < 12:
        return False, "Admin password must be at least 12 characters long."
    if username.casefold() in password.casefold():
        return False, "Admin password must not contain the admin username."
    return validate_password(password)


def generate_recovery_key() -> str:
    return secrets.token_urlsafe(12).replace("-", "").upper()[:12]


def get_user_by_phone(phone_number: str) -> Optional[Dict[str, Any]]:
    data = load_users()
    phone = normalize_phone(phone_number)
    for user in data.get("users", []):
        if normalize_phone(user.get("phone", "")) == phone:
            return user
    return None


def get_user_by_email(email: str) -> Optional[Dict[str, Any]]:
    data = load_users()
    target = email.strip().lower()
    for user in data.get("users", []):
        if user.get("email", "").strip().lower() == target:
            return user
    return None


def find_user_by_identifier(identifier: str) -> Optional[Dict[str, Any]]:
    for lookup in (identifier, normalize_phone(identifier)):
        user = get_user_by_phone(lookup) if lookup and lookup.isdigit() else get_user_by_email(identifier)
        if user:
            return user
    return None


def update_session(last_user: Optional[str]) -> None:
    write_json_atomically(SESSION_FILE, {"last_user": last_user})


def print_wait(message: str = "Processing your request...", duration: float = 0.8) -> None:
    print(message)
    time.sleep(duration)


def print_banner() -> None:
    print(ASCII_BANNER)
    print(f"{APP_NAME}  |  Version {APP_VERSION}")
    print("=" * 72)
    print("A secure local account management system for registration, login, and profile workflows.")
    print("=" * 72)


def print_feature_panel() -> None:
    print("\nCore Features")
    print("-" * 40)
    for idx, item in enumerate(FEATURES, start=1):
        print(f"{idx:02d}. {item}")
    print("-" * 40)


def print_security_panel() -> None:
    print("\nSecurity Guidance")
    print("-" * 40)
    for idx, tip in enumerate(SECURITY_TIPS, start=1):
        print(f"{idx:02d}. {tip}")
    print("-" * 40)


def print_help_panel() -> None:
    print("\nQuick help")
    print("-" * 40)
    for idx, topic in enumerate(HELP_TOPICS, start=1):
        print(f"{idx:02d}. {topic}")
    print("-" * 40)


def print_common_errors() -> None:
    print("\nCommon validation messages")
    print("-" * 40)
    for idx, message in enumerate(COMMON_ERRORS, start=1):
        print(f"{idx:02d}. {message}")
    print("-" * 40)


def print_admin_help() -> None:
    print(ADMIN_HELP_TEXT)


def print_info_block() -> None:
    print(INFO_BLOCK)


def print_reference_guide() -> None:
    print(REFERENCE_GUIDE)


def prompt_non_empty(message: str) -> str:
    while True:
        value = safe_input(message).strip()
        if value:
            return value
        print("Field can't be empty.")


def prompt_choice(message: str, valid: List[str]) -> str:
    while True:
        value = safe_input(message).strip().lower()
        if value in {item.lower() for item in valid}:
            return value
        print("Invalid choice. Please try again.")


def prompt_yes_no(message: str) -> bool:
    while True:
        answer = safe_input(message).strip().lower()
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False
        print("Please answer with Y or N.")


class AccountManager:
    """Handles account registration, login, profile operations, and admin features."""

    def __init__(self) -> None:
        ensure_storage()
        self.data = load_users()

    def save(self) -> None:
        save_users(self.data)

    def get_user_list(self) -> List[Dict[str, Any]]:
        return self.data.get("users", [])

    def find_user(self, identifier: str) -> Optional[Dict[str, Any]]:
        email = identifier.strip().lower()
        phone = normalize_phone(identifier)
        for user in self.get_user_list():
            if phone and normalize_phone(user.get("phone", "")) == phone:
                return user
            if user.get("email", "").strip().lower() == email:
                return user
        return None

    def admin_setup_required(self) -> bool:
        admin = self.data.get("admin")
        return (
            not isinstance(admin, dict)
            or admin.get("credential_version") != ADMIN_CREDENTIAL_VERSION
            or not admin.get("username")
            or not admin.get("password_hash")
        )

    def setup_admin_credentials(self) -> bool:
        print("\nInitial administrator setup")
        print("Choose a unique username and a strong password of at least 12 characters.")
        username = safe_input("Admin username (3-32 letters, numbers, ., _, or -): ").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.-]{3,32}", username):
            print("Username must be 3-32 characters and use only letters, numbers, '.', '_' or '-'.")
            return False

        password = safe_secret("Admin password: ")
        confirmation = safe_secret("Confirm admin password: ")
        if not password or password != confirmation:
            print("Passwords are empty or do not match.")
            return False
        valid, reason = validate_admin_password(password, username)
        if not valid:
            print(reason)
            return False

        self.data["admin"] = {
            "username": username,
            "password_hash": hash_password(password),
            "credential_version": ADMIN_CREDENTIAL_VERSION,
            "failed_attempts": 0,
            "locked_until": None,
            "created_at": now_iso(),
        }
        self.save()
        log_event("Administrator credentials configured.")
        print("Administrator setup complete.")
        return True

    def is_admin_credentials(self, username: str, password: str) -> bool:
        admin = self.data.get("admin", {})
        if self.admin_setup_required():
            return False
        username_matches = hmac.compare_digest(
            str(admin.get("username", "")).encode("utf-8"),
            username.encode("utf-8"),
        )
        password_matches = verify_password(password, admin.get("password_hash", ""))
        return username_matches and password_matches

    def admin_login(self) -> bool:
        if self.admin_setup_required():
            print("Administrator credentials must be set up before logging in.")
            return False
        print("\nAdmin login")
        username = safe_input("Admin username: ").strip()
        password = safe_secret("Admin password: ")
        if not password:
            print("Password cannot be empty.")
            return False

        admin = self.data["admin"]
        locked_until_value = admin.get("locked_until")
        if locked_until_value:
            try:
                locked_until = datetime.strptime(locked_until_value, "%Y-%m-%d %H:%M:%S")
            except (TypeError, ValueError):
                locked_until = datetime.now() + timedelta(minutes=ADMIN_LOCKOUT_MINUTES)
                admin["locked_until"] = locked_until.strftime("%Y-%m-%d %H:%M:%S")
                admin["failed_attempts"] = 0
                self.save()
                log_event("Malformed administrator lockout timestamp; temporary lockout enforced.")
                print(f"Admin login is temporarily locked for {ADMIN_LOCKOUT_MINUTES} minutes.")
                return False
            current_time = datetime.now()
            if locked_until > current_time:
                remaining = int((locked_until - current_time).total_seconds())
                print(f"Admin login is temporarily locked. Please wait {remaining} seconds.")
                return False
            admin["locked_until"] = None
            admin["failed_attempts"] = 0

        if self.is_admin_credentials(username, password):
            if password_needs_rehash(admin.get("password_hash")):
                admin["password_hash"] = hash_password(password)
            admin["failed_attempts"] = 0
            admin["locked_until"] = None
            self.save()
            log_event(f"Admin login succeeded for user '{username}'.")
            print("Admin login successful.")
            return True
        try:
            failed_attempts = int(admin.get("failed_attempts", 0))
        except (TypeError, ValueError):
            failed_attempts = ADMIN_MAX_FAILED_ATTEMPTS - 1
        if failed_attempts < 0:
            failed_attempts = ADMIN_MAX_FAILED_ATTEMPTS - 1
        admin["failed_attempts"] = failed_attempts + 1
        if admin["failed_attempts"] >= ADMIN_MAX_FAILED_ATTEMPTS:
            admin["failed_attempts"] = 0
            admin["locked_until"] = (
                datetime.now() + timedelta(minutes=ADMIN_LOCKOUT_MINUTES)
            ).strftime("%Y-%m-%d %H:%M:%S")
            print(
                f"Too many failed attempts. Admin login is locked for "
                f"{ADMIN_LOCKOUT_MINUTES} minutes."
            )
        self.save()
        log_event(f"Admin login failed for user '{username}'.")
        if not admin.get("locked_until"):
            print(
                "Admin login failed. Remaining attempts: "
                f"{ADMIN_MAX_FAILED_ATTEMPTS - admin['failed_attempts']}"
            )
        return False

    def change_admin_password(self) -> bool:
        admin = self.data.get("admin", {})
        current_password = safe_secret("Current admin password: ")
        if not verify_password(current_password, admin.get("password_hash", "")):
            print("Current password verification failed.")
            return False

        new_password = safe_secret("New admin password: ")
        confirmation = safe_secret("Confirm new admin password: ")
        if not new_password or new_password != confirmation:
            print("Passwords are empty or do not match.")
            return False
        valid, reason = validate_admin_password(new_password, admin.get("username", ""))
        if not valid:
            print(reason)
            return False
        admin["password_hash"] = hash_password(new_password)
        admin["failed_attempts"] = 0
        admin["locked_until"] = None
        self.save()
        log_event("Administrator password changed.")
        print("Admin password changed successfully.")
        return True

    def register_user(self) -> bool:
        print("\nRegistration Form")
        first_name = prompt_non_empty("First name: ")
        last_name = prompt_non_empty("Last name: ")
        email = prompt_non_empty("Email: ")
        phone = prompt_non_empty("Phone number: ")

        if not validate_email(email):
            print("Invalid email address. Please provide a valid e-mail, for example name@example.com.")
            return False
        normalized_phone = normalize_phone(phone)
        if not validate_phone(phone):
            print("Please enter a valid phone number with at least 10 digits.")
            return False
        if get_user_by_phone(normalized_phone):
            print("This phone number is already registered.")
            return False
        if get_user_by_email(email):
            print("This email address is already in use.")
            return False

        password = safe_secret("Password: ")
        confirm_password = safe_secret("Confirm password: ")
        if not password or not confirm_password:
            print("Password fields cannot be empty.")
            return False
        if password != confirm_password:
            print("Passwords do not match.")
            return False

        valid, reason = validate_password(password)
        if not valid:
            print(reason)
            return False

        recovery_key = generate_recovery_key()
        user = {
            "id": secrets.token_hex(8),
            "first_name": first_name.title(),
            "last_name": last_name.title(),
            "email": email.strip().lower(),
            "phone": normalized_phone,
            "password_hash": hash_password(password),
            "recovery_key": recovery_key,
            "created_at": now_iso(),
            "last_login": None,
            "failed_attempts": 0,
            "locked_until": None,
            "is_active": True,
            "role": "user",
            "status": "active",
        }
        self.data.setdefault("users", []).append(user)
        self.save()
        log_event(f"User registered successfully: {user['email']} ({user['phone']})")
        print("\nRegistration successful!\n")
        print(f"Full name: {first_name.title()} {last_name.title()}")
        print(f"Phone: {normalized_phone}")
        print(f"Email: {email.strip().lower()}")
        print(f"Recovery key: {recovery_key}")
        print("Please store the recovery key safely. It can be used later for account recovery.")
        return True

    def login_user(self) -> Optional[Dict[str, Any]]:
        print("\nLogin Form")
        identifier = prompt_non_empty("Enter your phone number or email: ")
        password = safe_secret("Password: ")
        if not identifier or not password:
            print("Field cannot be empty.")
            return None

        user = self.find_user(identifier)
        if not user:
            log_event(f"Login failed: account not found for '{identifier}'.")
            print("Account not found. Please check your details and try again.")
            return None

        if not user.get("is_active", True):
            print("This account is inactive. Please contact an administrator.")
            return None

        locked_until_value = user.get("locked_until")
        if locked_until_value:
            try:
                locked_until = datetime.strptime(locked_until_value, "%Y-%m-%d %H:%M:%S")
            except ValueError:
                user["locked_until"] = None
                locked_until = None
            if locked_until and locked_until > datetime.now():
                remaining = locked_until - datetime.now()
                print(f"This account is temporarily locked. Please wait {int(remaining.total_seconds())} seconds.")
                return None
            user["locked_until"] = None
            user["failed_attempts"] = 0
            self.save()

        if verify_password(password, user.get("password_hash", "")):
            if password_needs_rehash(user.get("password_hash")):
                user["password_hash"] = hash_password(password)
            user["failed_attempts"] = 0
            user["locked_until"] = None
            user["last_login"] = now_iso()
            self.save()
            update_session(user.get("email"))
            log_event(f"Successful login: {user.get('email')}")
            return user

        user["failed_attempts"] = int(user.get("failed_attempts", 0)) + 1
        if user["failed_attempts"] >= 3:
            lock_until = datetime.now() + timedelta(minutes=5)
            user["locked_until"] = lock_until.strftime("%Y-%m-%d %H:%M:%S")
            user["failed_attempts"] = 0
            self.save()
            log_event(f"Account locked: {user.get('email')}.")
            print("Too many failed attempts. This account has been locked for 5 minutes.")
        else:
            self.save()
            print(f"Incorrect password. Remaining attempts: {3 - user['failed_attempts']}")
        return None

    def reset_password(self) -> bool:
        print("\nPassword Recovery")
        identifier = prompt_non_empty("Enter your phone number or email: ")
        user = self.find_user(identifier)
        if not user:
            print("Account not found.")
            return False

        recovery_key = safe_input("Enter your recovery key: ").strip()
        if recovery_key != user.get("recovery_key"):
            print("Recovery key does not match this account.")
            log_event(f"Password recovery failed for '{user.get('email')}'.")
            return False

        new_password = safe_secret("Enter your new password: ")
        confirm_password = safe_secret("Confirm your new password: ")
        if not new_password or not confirm_password:
            print("Password field cannot be empty.")
            return False
        if new_password != confirm_password:
            print("Passwords do not match.")
            return False

        valid, reason = validate_password(new_password)
        if not valid:
            print(reason)
            return False

        user["password_hash"] = hash_password(new_password)
        user["failed_attempts"] = 0
        user["locked_until"] = None
        self.save()
        log_event(f"Password reset completed for '{user.get('email')}'.")
        print("Password reset successful.")
        return True

    def view_profile(self, user: Dict[str, Any]) -> None:
        print("\nProfile Overview")
        print("-" * 40)
        print(f"Name: {user.get('first_name')} {user.get('last_name')}")
        print(f"Email: {user.get('email')}")
        print(f"Phone: {user.get('phone')}")
        print(f"Role: {user.get('role', 'user')}")
        print(f"Created at: {user.get('created_at')}")
        print(f"Last login: {user.get('last_login') or 'Not yet'}")
        print(f"Account status: {user.get('status', 'active')}")
        print("-" * 40)

    def update_profile(self, user: Dict[str, Any]) -> bool:
        print("\nUpdate profile")
        print("Select a field to update:")
        print("1. First name")
        print("2. Last name")
        print("3. Email")
        print("4. Phone")
        print("5. Cancel")

        choice = safe_input("Choice: ").strip()
        if choice == "5":
            print("No changes made.")
            return False

        if choice == "1":
            new_value = prompt_non_empty("New first name: ")
            user["first_name"] = new_value.title()
        elif choice == "2":
            new_value = prompt_non_empty("New last name: ")
            user["last_name"] = new_value.title()
        elif choice == "3":
            new_value = prompt_non_empty("New email: ")
            if not validate_email(new_value):
                print("Invalid email address.")
                return False
            if get_user_by_email(new_value) and get_user_by_email(new_value).get("id") != user.get("id"):
                print("This email is already in use.")
                return False
            user["email"] = new_value.strip().lower()
        elif choice == "4":
            new_value = prompt_non_empty("New phone number: ")
            if not validate_phone(new_value):
                print("Invalid phone number.")
                return False
            normalized = normalize_phone(new_value)
            if get_user_by_phone(normalized) and get_user_by_phone(normalized).get("id") != user.get("id"):
                print("This phone number is already registered.")
                return False
            user["phone"] = normalized
        else:
            print("Invalid field selection.")
            return False

        self.save()
        log_event(f"Profile updated for '{user.get('email')}'.")
        print("Profile updated successfully.")
        return True

    def delete_account(self, user: Dict[str, Any]) -> bool:
        print("\nDelete account")
        print("This action permanently removes your access and saved profile information.")
        confirm = prompt_yes_no("Do you want to continue? (Y/N): ")
        if not confirm:
            print("Account deletion cancelled.")
            return False

        password = safe_secret("Enter your password to confirm deletion: ")
        if not verify_password(password, user.get("password_hash", "")):
            print("Password verification failed. Account deletion cancelled.")
            return False

        recovery_key = safe_input("Enter your recovery key: ").strip()
        if recovery_key != user.get("recovery_key"):
            print("Recovery key mismatch. Account deletion cancelled.")
            return False

        self.data["users"] = [entry for entry in self.get_user_list() if entry.get("id") != user.get("id")]
        self.save()
        log_event(f"Account deleted: {user.get('email')}")
        print("Your account has been deleted successfully.")
        return True

    def list_users(self) -> None:
        users = self.get_user_list()
        if not users:
            print("No users available.")
            return
        print("\nRegistered users")
        print("-" * 80)
        for index, user in enumerate(users, start=1):
            name = sanitize_terminal_text(
                f"{user.get('first_name')} {user.get('last_name')}"
            )
            email = sanitize_terminal_text(user.get("email", ""))
            phone = sanitize_terminal_text(user.get("phone", ""))
            status = sanitize_terminal_text(user.get("status", "active"))
            print(
                f"{index:02d}. {name} | "
                f"Email: {email} | Phone: {phone} | Status: {status}"
            )
        print("-" * 80)

    def user_summary(self) -> None:
        users = self.get_user_list()
        print(f"Total users: {len(users)}")
        active_count = sum(1 for user in users if user.get("status") == "active")
        inactive_count = sum(1 for user in users if user.get("status") != "active")
        print(f"Active: {active_count}")
        print(f"Inactive: {inactive_count}")

    def delete_user_by_admin(self) -> None:
        print("\nDelete user by admin")
        identifier = prompt_non_empty("Enter phone or email of the user to remove: ")
        user = find_user_by_identifier(identifier)
        if not user:
            print("No matching user found.")
            return
        confirmation = prompt_yes_no(f"Delete {user.get('email')}? (Y/N): ")
        if not confirmation:
            print("Deletion cancelled.")
            return
        self.data["users"] = [entry for entry in self.get_user_list() if entry.get("id") != user.get("id")]
        self.save()
        log_event(f"Admin removed user: {user.get('email')}")
        print("User removed successfully.")

    def browse_users(self) -> None:
        """Show a bounded, searchable user directory without exposing credentials."""
        users = self.get_user_list()
        if not users:
            print("No users available.")
            return

        query = safe_input("Optional name, email, phone, or status filter: ").strip().casefold()
        filtered_users = [
            user
            for user in users
            if not query
            or query
            in " ".join(
                str(user.get(field, ""))
                for field in ("first_name", "last_name", "email", "phone", "status")
            ).casefold()
        ]
        if not filtered_users:
            print("No users match that filter.")
            return

        page_count = (len(filtered_users) + MAX_USER_PAGE_SIZE - 1) // MAX_USER_PAGE_SIZE
        page = 0
        while True:
            start = page * MAX_USER_PAGE_SIZE
            end = min(start + MAX_USER_PAGE_SIZE, len(filtered_users))
            print(f"\nUser directory -- page {page + 1} of {page_count}")
            print("-" * 88)
            for index, user in enumerate(filtered_users[start:end], start=start + 1):
                name = sanitize_terminal_text(
                    f"{user.get('first_name', '')} {user.get('last_name', '')}"
                ).strip()
                state = "active" if user.get("is_active", True) else "inactive"
                locked = " | locked" if user.get("locked_until") else ""
                print(
                    f"{index:04d}. {name or 'Unnamed'} | "
                    f"{sanitize_terminal_text(user.get('email', 'No email'))} | "
                    f"{sanitize_terminal_text(user.get('phone', 'No phone'))} | "
                    f"{state}{locked}"
                )
            print("-" * 88)
            if page_count == 1:
                return

            action = safe_input(
                "Enter N for next page, P for previous page, or Q to return: "
            ).strip().casefold()
            if action == "q":
                return
            if action == "n" and page + 1 < page_count:
                page += 1
            elif action == "p" and page > 0:
                page -= 1
            else:
                print("Choose an available page action.")

    def manage_user_access(self) -> bool:
        """Change a user's active state or clear that user's login lockout."""
        print("\nManage user access")
        identifier = prompt_non_empty("Enter the user's phone number or email: ")
        user = self.find_user(identifier)
        if user is None:
            print("No matching user found.")
            return False

        email = str(user.get("email", "unknown"))
        active = bool(user.get("is_active", True))
        print(f"Account: {email}")
        print(f"Current access: {'active' if active else 'inactive'}")
        print("1. Deactivate account")
        print("2. Reactivate account")
        print("3. Clear login lockout")
        print("4. Cancel")
        choice = safe_input("Choose an action: ").strip()

        if choice == "1":
            if active and prompt_yes_no(f"Deactivate {email}? (Y/N): "):
                user["is_active"] = False
                user["status"] = "inactive"
                self.save()
                log_event(f"Admin deactivated user account: {email}")
                print("Account deactivated. The user's password and recovery key were not changed.")
                return True
        elif choice == "2":
            if not active and prompt_yes_no(f"Reactivate {email}? (Y/N): "):
                user["is_active"] = True
                user["status"] = "active"
                self.save()
                log_event(f"Admin reactivated user account: {email}")
                print("Account reactivated.")
                return True
        elif choice == "3":
            if user.get("locked_until") or user.get("failed_attempts", 0):
                if prompt_yes_no(f"Clear login lockout for {email}? (Y/N): "):
                    user["locked_until"] = None
                    user["failed_attempts"] = 0
                    self.save()
                    log_event(f"Admin cleared login lockout for user: {email}")
                    print("Login lockout cleared.")
                    return True
            else:
                print("This account has no recorded login lockout.")
                return False
        elif choice == "4":
            print("No changes made.")
            return False
        else:
            print("Invalid action.")
            return False
        print("No changes made.")
        return False

    def admin_security_report(self) -> None:
        """Report account-store health without printing passwords or recovery keys."""
        users = self.get_user_list()
        valid_users = [user for user in users if isinstance(user, dict)]
        malformed_records = len(users) - len(valid_users)
        email_counts = Counter(
            str(user.get("email", "")).strip().casefold()
            for user in valid_users
            if user.get("email")
        )
        phone_counts = Counter(
            normalize_phone(str(user.get("phone", "")))
            for user in valid_users
            if user.get("phone")
        )
        malformed_hashes = sum(
            1
            for user in valid_users
            if not is_password_hash_well_formed(user.get("password_hash"))
        )
        legacy_hashes = sum(
            1
            for user in valid_users
            if is_legacy_password_hash(user.get("password_hash"))
        )
        duplicate_emails = sum(1 for count in email_counts.values() if count > 1)
        duplicate_phones = sum(1 for count in phone_counts.values() if count > 1)
        inactive = sum(1 for user in valid_users if not user.get("is_active", True))
        locked = sum(1 for user in valid_users if user.get("locked_until"))
        admin = self.data.get("admin") or {}

        print("\nAdministrator security report")
        print("-" * 52)
        print(f"Account records: {len(users)}")
        print(f"Malformed user records: {malformed_records}")
        print(f"Inactive accounts: {inactive}")
        print(f"Accounts with a lockout timestamp: {locked}")
        print(f"Password hashes needing attention: {malformed_hashes}")
        print(
            "Admin password hash: "
            f"{'valid format' if is_password_hash_well_formed(admin.get('password_hash')) else 'invalid or missing'}"
        )
        print(f"Duplicate email groups: {duplicate_emails}")
        print(f"Duplicate phone groups: {duplicate_phones}")
        print(
            "Admin credential state: "
            f"{'configured' if not self.admin_setup_required() else 'setup required'}"
        )
        print(
            "Admin lockout: "
            f"{admin.get('locked_until') or 'not locked'}"
        )
        print(f"Account data permissions: {storage_file_mode(USERS_FILE)}")
        print(f"Activity log permissions: {storage_file_mode(ACTIVITY_LOG)}")
        print(f"Private backup files: {len(list_data_backups())}")
        if legacy_hashes:
            print(
                f"Legacy user password hashes awaiting automatic upgrade: {legacy_hashes}"
            )
        if malformed_hashes:
            print("Review affected accounts before relying on their stored credentials.")
        print("-" * 52)

    def review_audit_log(self) -> None:
        """Display a bounded, newest-first slice of the activity log."""
        keyword = safe_input("Optional keyword filter (Enter for all events): ").strip()
        limit_input = safe_input(
            f"Maximum events to show (1-{MAX_AUDIT_RESULTS}, default 50): "
        ).strip()
        try:
            limit = 50 if not limit_input else int(limit_input)
            events = read_audit_events(limit=limit, keyword=keyword)
        except ValueError as error:
            print(f"Invalid audit search: {error}")
            return
        except RuntimeError as error:
            print(error)
            return
        if not events:
            print("No matching audit events.")
            return
        print(f"\nLatest {len(events)} matching audit event(s)")
        print("-" * 88)
        for event in events:
            print(event)
        print("-" * 88)

    def export_audit_log(self) -> Optional[Path]:
        """Export the bounded audit history to an owner-only CSV file."""
        keyword = safe_input("Optional keyword filter (Enter for all events): ").strip()
        try:
            export_path = export_audit_events(keyword)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Audit export failed: {error}")
            return None
        log_event("Administrator exported the activity log.")
        print(f"Private audit export created: {export_path.name}")
        print("The export contains account activity metadata; keep it protected.")
        return export_path

    def create_admin_backup(self) -> Optional[Path]:
        """Create a private account-store backup after explicit confirmation."""
        if not prompt_yes_no("Create a private backup of accounts and credentials? (Y/N): "):
            print("Backup cancelled.")
            return None
        try:
            backup_path = create_data_backup()
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Backup failed: {error}")
            return None
        log_event("Administrator created an account data backup.")
        print(f"Private backup created: {backup_path.name}")
        print("Backups contain password hashes and recovery keys; protect and limit their retention.")
        return backup_path

    def restore_admin_backup(self) -> bool:
      
        backups = list_data_backups()
        if not backups:
            print("No application backups are available.")
            return False
        print("\nAvailable account backups")
        for index, backup in enumerate(backups, start=1):
            modified = datetime.fromtimestamp(backup.stat().st_mtime).strftime(
                "%Y-%m-%d %H:%M:%S"
            )
            print(f"{index}. {backup.name} | created {modified}")
        selection = safe_input("Enter a backup number or Q to cancel: ").strip().casefold()
        if selection == "q":
            return False
        try:
            backup_index = int(selection) - 1
            if not 0 <= backup_index < len(backups):
                print("Backup selection is outside the available range.")
                return False
            restored_data = load_validated_backup(backups[backup_index])
        except (OSError, ValueError, RuntimeError) as error:
            print(f"Backup restore validation failed: {error}")
            return False

        if not prompt_yes_no(
            "Replace all current accounts and admin credentials with this backup? (Y/N): "
        ):
            print("Restore cancelled.")
            return False
        if not prompt_yes_no(
            "Create a rollback backup of the current data before restoring? (Y/N): "
        ):
            print("Restore cancelled; a rollback backup is required.")
            return False
        try:
            rollback_path = create_data_backup()
            save_users(restored_data)
        except (OSError, RuntimeError, ValueError) as error:
            print(f"Restore failed: {error}")
            return False
        self.data = restored_data
        log_event(
            f"Administrator restored account data from {backups[backup_index].name}; "
            f"rollback saved as {rollback_path.name}."
        )
        print("Account data restored. The rollback copy remains available in the data directory.")
        return True

    def manage_admin_backups(self) -> bool:
        """Offer explicit backup creation, inspection, and restore actions."""
        while True:
            print("\nAccount backup management")
            print("1. Create a backup")
            print("2. List backups")
            print("3. Restore a backup")
            print("4. Return")
            choice = safe_input("Choose an action: ").strip()
            if choice == "1":
                self.create_admin_backup()
            elif choice == "2":
                backups = list_data_backups()
                if not backups:
                    print("No application backups are available.")
                else:
                    print(f"{len(backups)} private backup(s):")
                    for backup in backups:
                        print(f"- {backup.name} ({backup.stat().st_size} bytes)")
            elif choice == "3":
                if self.restore_admin_backup():
                    return True
            elif choice == "4":
                return False
            else:
                print("Invalid choice.")
            if choice in {"1", "2", "3"}:
                safe_input("Press Enter to continue...")

    def admin_dashboard(self) -> None:
        print("\nAdmin Dashboard")
        while True:
            print("1. View user summary")
            print("2. List users")
            print("3. Delete user")
            print("4. Change admin password")
            print("5. Security guidance")
            print("6. Help")
            print("7. Logout")
            print("8. Search and browse users")
            print("9. Manage user access")
            print("10. Security report")
            print("11. Review activity log")
            print("12. Export activity log")
            print("13. Account backup and restore")
            choice = safe_input("Select an option: ").strip()
            if choice == "1":
                self.user_summary()
            elif choice == "2":
                self.list_users()
            elif choice == "3":
                self.delete_user_by_admin()
            elif choice == "4":
                self.change_admin_password()
            elif choice == "5":
                print_security_panel()
            elif choice == "6":
                print_admin_help()
            elif choice == "7":
                print("Logged out of admin mode.")
                return
            elif choice == "8":
                self.browse_users()
            elif choice == "9":
                self.manage_user_access()
            elif choice == "10":
                self.admin_security_report()
            elif choice == "11":
                self.review_audit_log()
            elif choice == "12":
                self.export_audit_log()
            elif choice == "13":
                if self.manage_admin_backups():
                    print("Administrator session ended because credentials were restored.")
                    return
            else:
                print("Invalid option. Please try again.")
            if choice != "13":
                print("\nPress Enter to continue...")
                safe_input("")
                clear_screen()


class AuthConsoleApp:
    def __init__(self) -> None:
        self.manager = AccountManager()

    def main_menu(self) -> None:
        while True:
            if self.manager.admin_setup_required() and not self.manager.setup_admin_credentials():
                print("Admin setup was not completed. Run the application again to retry.")
                return
            clear_screen()
            print_banner()
            print("Main Menu")
            print("-" * 40)
            print("1. Register account")
            print("2. Login")
            print("3. Recover password")
            print("4. View features")
            print("5. View security tips")
            print("6. Admin login")
            print("7. System info")
            print("8. Reference guide")
            print("9. Exit")
            print("-" * 40)
            choice = safe_input("Select an option: ").strip()

            if choice == "1":
                clear_screen()
                self.manager.register_user()
                self.pause()
            elif choice == "2":
                clear_screen()
                user = self.manager.login_user()
                if user:
                    self.user_dashboard(user)
                self.pause()
            elif choice == "3":
                clear_screen()
                self.manager.reset_password()
                self.pause()
            elif choice == "4":
                clear_screen()
                print_feature_panel()
                self.pause()
            elif choice == "5":
                clear_screen()
                print_security_panel()
                self.pause()
            elif choice == "6":
                clear_screen()
                if self.manager.admin_login():
                    self.manager.admin_dashboard()
                self.pause()
            elif choice == "7":
                clear_screen()
                print_info_block()
                print_help_panel()
                print_common_errors()
                self.pause()
            elif choice == "8":
                clear_screen()
                print_reference_guide()
                self.pause()
            elif choice == "9":
                log_event("Application exited by user request.")
                print("Goodbye! Thank you for using the Secure Access Console.")
                break
            else:
                print("Invalid option. Please choose from the menu.")
                self.pause()

    def user_dashboard(self, user: Dict[str, Any]) -> None:
        while True:
            clear_screen()
            print(f"Welcome, {user.get('first_name')} {user.get('last_name')}!")
            print("User Dashboard")
            print("-" * 40)
            print("1. View profile")
            print("2. Update profile")
            print("3. Delete account")
            print("4. Security tips")
            print("5. Help")
            print("6. Logout")
            print("-" * 40)
            choice = safe_input("Choose an action: ").strip()

            if choice == "1":
                self.manager.view_profile(user)
                self.pause()
            elif choice == "2":
                self.manager.update_profile(user)
                self.pause()
            elif choice == "3":
                if self.manager.delete_account(user):
                    print("Returning to the main menu.")
                    return
                self.pause()
            elif choice == "4":
                print_security_panel()
                self.pause()
            elif choice == "5":
                print_help_panel()
                self.pause()
            elif choice == "6":
                print("You have logged out.")
                log_event(f"User logout: {user.get('email')}")
                return
            else:
                print("Invalid option. Please try again.")
                self.pause()

    def pause(self) -> None:
        print("\nPress Enter to continue...")
        safe_input("")


if __name__ == "__main__":
    try:
        app = AuthConsoleApp()
        app.main_menu()
    except SystemExit:
        pass
    except Exception as exc:
        log_event(f"Unexpected runtime error: {exc}")
        print(f"An unexpected error occurred: {exc}")
        print("The application will close. Please review the activity log for details.")
        sys.exit(1)
