#!/usr/bin/env python3
"""
Domain Collector and Validator for KahfGuard Blacklists

This script collects domains from various sources (web scraping, SEO data)
and validates them against the KahfGuard DNS to check blocking status.

Usage:
    python collect_domains.py --category gambling --source web
    python collect_domains.py --category all --validate-only
    python collect_domains.py --category gambling --add-missing
"""

import argparse
import subprocess
import re
import sys
import os
from pathlib import Path
from typing import Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

# Category configurations with search terms and seed sources
CATEGORIES = {
    "gambling": {
        "search_terms": [
            "top gambling sites",
            "best online casinos",
            "sports betting sites",
            "poker sites online",
            "slot machine sites",
            "betting websites",
        ],
        "seed_sources": [
            "casino.org",
            "askgamblers.com",
            "casinomeister.com",
        ],
    },
    "adult": {
        "search_terms": [
            "adult content sites",
        ],
        "seed_sources": [],
    },
    "dating": {
        "search_terms": [
            "dating sites",
            "dating apps",
        ],
        "seed_sources": [],
    },
    "piracy": {
        "search_terms": [
            "torrent sites",
            "streaming sites free",
        ],
        "seed_sources": [],
    },
    "malware": {
        "search_terms": [
            "known malware domains",
        ],
        "seed_sources": [],
    },
    "social": {
        "search_terms": [],
        "seed_sources": [],
    },
    "violence": {
        "search_terms": [],
        "seed_sources": [],
    },
}

# DNS server for validation
DNS_SERVER = "low.kahfguard.com"
BLOCKED_CNAME = "blocked.kahfguard.com"


def extract_domain(text: str) -> Optional[str]:
    """Extract a valid domain from text."""
    # Pattern to match domains
    domain_pattern = r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
    match = re.search(domain_pattern, text)
    if match:
        domain = match.group(0).lower()
        # Filter out common non-domain patterns
        if not any(x in domain for x in ['example.com', 'localhost', 'test.com']):
            return domain
    return None


def validate_domain_format(domain: str) -> bool:
    """Validate domain format."""
    if not domain or len(domain) > 253:
        return False

    # Basic domain validation
    pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))


def check_blocking_status(domain: str) -> dict:
    """
    Check if a domain is blocked by KahfGuard DNS.

    Returns:
        dict with keys: domain, is_blocked, cname, error
    """
    result = {
        "domain": domain,
        "is_blocked": False,
        "cname": None,
        "error": None,
    }

    try:
        # Run dig command
        cmd = ["dig", f"@{DNS_SERVER}", domain, "+short", "+time=5", "+tries=2"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)

        output = proc.stdout.strip()

        if BLOCKED_CNAME in output:
            result["is_blocked"] = True
            result["cname"] = BLOCKED_CNAME
        elif output:
            result["cname"] = output.split('\n')[0]

    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def load_existing_domains(category: str) -> set:
    """Load existing domains from the blacklist file."""
    script_dir = Path(__file__).parent
    blacklist_file = script_dir.parent / "kahf-custom-blacklist" / f"{category}.txt"

    domains = set()
    if blacklist_file.exists():
        with open(blacklist_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.add(line.lower())
    return domains


def save_domains(category: str, domains: set) -> None:
    """Save domains to the blacklist file (sorted, deduplicated)."""
    script_dir = Path(__file__).parent
    blacklist_file = script_dir.parent / "kahf-custom-blacklist" / f"{category}.txt"

    sorted_domains = sorted(domains)
    with open(blacklist_file, 'w') as f:
        for domain in sorted_domains:
            f.write(f"{domain}\n")

    print(f"Saved {len(sorted_domains)} domains to {blacklist_file}")


def validate_category(category: str, verbose: bool = False) -> dict:
    """
    Validate all domains in a category against KahfGuard DNS.

    Returns:
        dict with blocked, not_blocked, errors counts and lists
    """
    domains = load_existing_domains(category)

    results = {
        "total": len(domains),
        "blocked": [],
        "not_blocked": [],
        "errors": [],
    }

    print(f"\nValidating {len(domains)} domains in '{category}'...")

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = {executor.submit(check_blocking_status, d): d for d in domains}

        for i, future in enumerate(as_completed(futures), 1):
            result = future.result()
            domain = result["domain"]

            if result["error"]:
                results["errors"].append(domain)
                if verbose:
                    print(f"  [{i}/{len(domains)}] ERROR: {domain} - {result['error']}")
            elif result["is_blocked"]:
                results["blocked"].append(domain)
                if verbose:
                    print(f"  [{i}/{len(domains)}] BLOCKED: {domain}")
            else:
                results["not_blocked"].append(domain)
                if verbose:
                    print(f"  [{i}/{len(domains)}] NOT BLOCKED: {domain} -> {result['cname']}")

            # Progress indicator
            if not verbose and i % 50 == 0:
                print(f"  Progress: {i}/{len(domains)}")

    return results


def collect_from_web(category: str, max_results: int = 100) -> set:
    """
    Collect domains from web sources for a category.

    TODO(human): Implement the web scraping logic for collecting domains.
    This function should use the search terms defined in CATEGORIES[category]
    to find and extract domain names from search results.
    """
    config = CATEGORIES.get(category, {})
    search_terms = config.get("search_terms", [])

    collected = set()

    # Placeholder - implement web scraping logic
    print(f"Web collection for '{category}' - search terms: {search_terms}")
    print("Note: Web scraping requires additional implementation based on your needs")

    return collected


def generate_report(category: str, results: dict) -> str:
    """Generate a validation report."""
    report = []
    report.append(f"\n{'='*60}")
    report.append(f"VALIDATION REPORT: {category.upper()}")
    report.append(f"{'='*60}")
    report.append(f"Total domains: {results['total']}")
    report.append(f"Blocked:       {len(results['blocked'])} ({100*len(results['blocked'])//max(results['total'],1)}%)")
    report.append(f"Not blocked:   {len(results['not_blocked'])}")
    report.append(f"Errors:        {len(results['errors'])}")

    if results['not_blocked']:
        report.append(f"\nDomains NOT blocked (need investigation):")
        for domain in sorted(results['not_blocked'])[:20]:
            report.append(f"  - {domain}")
        if len(results['not_blocked']) > 20:
            report.append(f"  ... and {len(results['not_blocked']) - 20} more")

    if results['errors']:
        report.append(f"\nDomains with errors:")
        for domain in sorted(results['errors'])[:10]:
            report.append(f"  - {domain}")

    report.append(f"{'='*60}\n")
    return '\n'.join(report)


def main():
    parser = argparse.ArgumentParser(
        description="Collect and validate domains for KahfGuard blacklists"
    )
    parser.add_argument(
        "--category", "-c",
        choices=list(CATEGORIES.keys()) + ["all"],
        help="Category to process (or 'all' for all categories)"
    )
    parser.add_argument(
        "--validate-only", "-v",
        action="store_true",
        help="Only validate existing domains, don't collect new ones"
    )
    parser.add_argument(
        "--collect", "-C",
        action="store_true",
        help="Collect new domains from web sources"
    )
    parser.add_argument(
        "--add-domains", "-a",
        nargs="+",
        help="Manually add domains to the category"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Show detailed output"
    )
    parser.add_argument(
        "--check-domain", "-d",
        help="Check blocking status of a single domain"
    )

    args = parser.parse_args()

    # Single domain check (doesn't require category)
    if args.check_domain:
        result = check_blocking_status(args.check_domain)
        status = "BLOCKED" if result["is_blocked"] else "NOT BLOCKED"
        print(f"{result['domain']}: {status}")
        if result["cname"]:
            print(f"  CNAME: {result['cname']}")
        if result["error"]:
            print(f"  Error: {result['error']}")
        return 0

    # Category is required for other operations
    if not args.category:
        parser.error("--category is required (unless using --check-domain)")

    categories = list(CATEGORIES.keys()) if args.category == "all" else [args.category]

    for category in categories:
        print(f"\n{'#'*60}")
        print(f"# Processing: {category.upper()}")
        print(f"{'#'*60}")

        # Load existing domains
        existing = load_existing_domains(category)
        print(f"Loaded {len(existing)} existing domains")

        # Add manual domains if specified
        if args.add_domains:
            for domain in args.add_domains:
                domain = domain.lower().strip()
                if validate_domain_format(domain):
                    existing.add(domain)
                    print(f"  Added: {domain}")
                else:
                    print(f"  Invalid domain format: {domain}")
            save_domains(category, existing)

        # Collect from web if requested
        if args.collect:
            new_domains = collect_from_web(category)
            if new_domains:
                added = new_domains - existing
                print(f"Found {len(new_domains)} domains, {len(added)} new")
                existing.update(new_domains)
                save_domains(category, existing)

        # Validate domains
        if args.validate_only or not args.add_domains:
            results = validate_category(category, verbose=args.verbose)
            report = generate_report(category, results)
            print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
