#!/usr/bin/env python3
"""
Pre-commit validation script for KahfGuard blacklists, whitelists, and IP lists.

Validates:
- Domain format in blacklist and whitelist files
- IP address and CIDR notation in IP lists
- No duplicates
- Proper sorting
- No empty lines or invalid characters

Auto-fixes (with --fix):
- Removes www. prefix
- Removes http:// https:// protocols
- Removes trailing slashes and paths
- Converts to lowercase
- Removes duplicates
- Sorts alphabetically

Directories validated:
- lists/block/*.txt
- lists/allow/*.txt
- blacklist_domains.txt, whitelist_domains.txt
- ip_blacklist.txt, ip_whitelist.txt

Usage:
    python validate_lists.py                    # Validate all files
    python validate_lists.py --fix              # Fix issues automatically
    python validate_lists.py --file path.txt   # Validate specific file

Exit codes:
    0 - All validations passed
    1 - Validation errors found
"""

import argparse
import ipaddress
import re
import sys
from pathlib import Path
from typing import Tuple


class ValidationError:
    def __init__(self, file: str, line_num: int, line: str, message: str):
        self.file = file
        self.line_num = line_num
        self.line = line
        self.message = message

    def __str__(self):
        return f"{self.file}:{self.line_num}: {self.message} -> '{self.line}'"


def normalize_domain(domain: str) -> str:
    """
    Normalize a domain by removing unnecessary parts.

    Removes:
    - http:// https:// protocols
    - www. prefix
    - Trailing slashes and paths
    - Port numbers
    - Query strings and fragments
    - Trailing dots
    - Whitespace
    """
    if not domain:
        return ""

    # Strip whitespace
    domain = domain.strip()

    # Remove protocol
    domain = re.sub(r"^https?://", "", domain, flags=re.IGNORECASE)

    # Remove path, query string, fragment (keep only domain)
    domain = domain.split("/")[0]
    domain = domain.split("?")[0]
    domain = domain.split("#")[0]

    # Remove port number
    domain = re.sub(r":\d+$", "", domain)

    # Remove www. prefix (and any www\d. like www2.)
    domain = re.sub(r"^www\d*\.", "", domain, flags=re.IGNORECASE)

    # Remove trailing dot
    domain = domain.rstrip(".")

    # Convert to lowercase
    domain = domain.lower()

    return domain


def validate_domain(domain: str) -> Tuple[bool, str]:
    """Validate a domain name format."""
    if not domain:
        return False, "Empty domain"

    if len(domain) > 253:
        return False, "Domain too long (max 253 chars)"

    # Remove trailing dot if present
    domain = domain.rstrip(".")

    # Check for valid characters
    if not re.match(r"^[a-zA-Z0-9.-]+$", domain):
        return False, "Invalid characters in domain"

    # Check domain pattern
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    if not re.match(pattern, domain):
        return False, "Invalid domain format"

    # Check for double dots
    if ".." in domain:
        return False, "Double dots in domain"

    # Check for leading/trailing hyphens in labels
    labels = domain.split(".")
    for label in labels:
        if label.startswith("-") or label.endswith("-"):
            return False, "Label starts/ends with hyphen"
        if len(label) > 63:
            return False, "Label too long (max 63 chars)"

    return True, ""


def validate_ip_entry(entry: str) -> Tuple[bool, str]:
    """Validate an IP address or CIDR notation (with optional comment)."""
    if not entry:
        return False, "Empty entry"

    # Split IP from comment
    parts = entry.split("#", 1)
    ip_part = parts[0].strip()

    if not ip_part:
        return False, "Empty IP address"

    try:
        # Try parsing as network (CIDR)
        if "/" in ip_part:
            ipaddress.ip_network(ip_part, strict=False)
        else:
            ipaddress.ip_address(ip_part)
        return True, ""
    except ValueError as e:
        return False, f"Invalid IP/CIDR: {e}"


def validate_domain_file(filepath: Path, fix: bool = False) -> list[ValidationError]:
    """Validate a domain blacklist/whitelist file."""
    errors = []
    valid_domains = []
    seen = set()
    needs_fix = False

    with open(filepath, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        original_line = line.strip()

        # Skip empty lines and comments
        if not original_line or original_line.startswith("#"):
            if original_line:
                valid_domains.append(original_line)
            continue

        # Normalize domain (remove www., protocol, etc.)
        domain = normalize_domain(original_line)

        # Check if normalization changed anything
        if domain != original_line.lower():
            needs_fix = True
            errors.append(
                ValidationError(
                    str(filepath),
                    i,
                    original_line,
                    f"Needs normalization -> '{domain}'",
                )
            )

        # Skip if normalization resulted in empty string
        if not domain:
            errors.append(
                ValidationError(
                    str(filepath), i, original_line, "Invalid/empty after normalization"
                )
            )
            continue

        # Check for duplicates
        if domain in seen:
            needs_fix = True
            errors.append(
                ValidationError(str(filepath), i, original_line, "Duplicate domain")
            )
            continue
        seen.add(domain)

        # Validate format
        is_valid, msg = validate_domain(domain)
        if not is_valid:
            errors.append(ValidationError(str(filepath), i, original_line, msg))
            continue

        valid_domains.append(domain)

    # Check sorting
    sorted_domains = sorted([d for d in valid_domains if not d.startswith("#")])
    actual_domains = [d for d in valid_domains if not d.startswith("#")]

    if actual_domains != sorted_domains:
        needs_fix = True
        errors.append(
            ValidationError(str(filepath), 0, "", "File is not sorted alphabetically")
        )

    # Fix if requested
    if fix and needs_fix:
        # Preserve comment positions, sort domains within each section
        sections = []
        current_comment = None
        current_domains = []

        for d in valid_domains:
            if d.startswith("#"):
                if current_comment is not None or current_domains:
                    sections.append((current_comment, current_domains))
                current_comment = d
                current_domains = []
            else:
                current_domains.append(d)
        sections.append((current_comment, current_domains))

        with open(filepath, "w") as f:
            for comment, domains in sections:
                if comment:
                    f.write(f"{comment}\n")
                for domain in sorted(set(domains)):
                    f.write(f"{domain}\n")

        print(f"Fixed: {filepath}")
        # Return empty errors since we fixed them
        return []

    return errors


def validate_ip_file(filepath: Path, fix: bool = False) -> list[ValidationError]:
    """Validate an IP blacklist file."""
    errors = []
    valid_entries = []
    seen_ips = set()

    with open(filepath, "r") as f:
        lines = f.readlines()

    for i, line in enumerate(lines, 1):
        line = line.strip()

        # Skip empty lines
        if not line:
            continue

        # Skip comment-only lines
        if line.startswith("#"):
            valid_entries.append(line)
            continue

        # Extract IP part for duplicate check
        ip_part = line.split("#")[0].strip()

        # Check for duplicates (by IP, not comment)
        if ip_part in seen_ips:
            errors.append(ValidationError(str(filepath), i, line, "Duplicate IP entry"))
            continue
        seen_ips.add(ip_part)

        # Validate format
        is_valid, msg = validate_ip_entry(line)
        if not is_valid:
            errors.append(ValidationError(str(filepath), i, line, msg))
            continue

        valid_entries.append(line)

    # Fix if requested
    if fix and errors:
        with open(filepath, "w") as f:
            for entry in valid_entries:
                f.write(f"{entry}\n")
        print(f"Fixed: {filepath}")
        return []

    return errors


def find_files(repo_root: Path) -> Tuple[list[Path], list[Path]]:
    """Find all domain and IP list files to validate."""
    domain_files = []
    ip_files = []

    # Domain blacklist files
    blacklist_dir = repo_root / "lists/block"
    if blacklist_dir.exists():
        for f in blacklist_dir.glob("*.txt"):
            if f.name != "README.md":
                domain_files.append(f)

    # Domain whitelist files
    whitelist_dir = repo_root / "lists/allow"
    if whitelist_dir.exists():
        for f in whitelist_dir.glob("*.txt"):
            if f.name != "README.md":
                domain_files.append(f)

    # Root level domain files
    for pattern in ["blacklist_domains.txt", "whitelist_domains.txt"]:
        f = repo_root / pattern
        if f.exists():
            domain_files.append(f)

    # IP files
    for pattern in ["ip_blacklist.txt", "ip_whitelist.txt"]:
        f = repo_root / pattern
        if f.exists():
            ip_files.append(f)

    return domain_files, ip_files


def main():
    parser = argparse.ArgumentParser(
        description="Validate KahfGuard blacklists and IP lists"
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Automatically fix issues (remove duplicates, sort)",
    )
    parser.add_argument("--file", "-f", type=Path, help="Validate a specific file")
    parser.add_argument(
        "--type",
        "-t",
        choices=["domain", "ip", "auto"],
        default="auto",
        help="File type (auto-detected by default)",
    )

    args = parser.parse_args()

    # Find repo root
    script_dir = Path(__file__).parent
    repo_root = script_dir.parent

    all_errors = []

    if args.file:
        # Validate specific file
        filepath = args.file
        if not filepath.exists():
            print(f"Error: File not found: {filepath}")
            return 1

        # Auto-detect type
        file_type = args.type
        if file_type == "auto":
            if "ip_" in filepath.name or "ip-" in filepath.name:
                file_type = "ip"
            else:
                file_type = "domain"

        if file_type == "ip":
            errors = validate_ip_file(filepath, args.fix)
        else:
            errors = validate_domain_file(filepath, args.fix)

        all_errors.extend(errors)
    else:
        # Validate all files
        domain_files, ip_files = find_files(repo_root)

        print(
            f"Validating {len(domain_files)} domain files and {len(ip_files)} IP files...\n"
        )

        for filepath in domain_files:
            errors = validate_domain_file(filepath, args.fix)
            all_errors.extend(errors)
            if not errors:
                print(f"✓ {filepath.name}")
            else:
                print(f"✗ {filepath.name} ({len(errors)} errors)")

        for filepath in ip_files:
            errors = validate_ip_file(filepath, args.fix)
            all_errors.extend(errors)
            if not errors:
                print(f"✓ {filepath.name}")
            else:
                print(f"✗ {filepath.name} ({len(errors)} errors)")

    # Report errors
    if all_errors:
        print(f"\n{'='*60}")
        print(f"VALIDATION ERRORS: {len(all_errors)}")
        print(f"{'='*60}")
        for error in all_errors[:50]:  # Limit output
            print(f"  {error}")
        if len(all_errors) > 50:
            print(f"  ... and {len(all_errors) - 50} more errors")
        print(f"\nRun with --fix to automatically fix issues")
        return 1

    print(f"\n✓ All validations passed!")
    return 0


if __name__ == "__main__":
    sys.exit(main())
