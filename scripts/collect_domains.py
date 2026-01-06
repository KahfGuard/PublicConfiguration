#!/usr/bin/env python3
"""
Domain Collector and Validator for KahfGuard Blacklists

Collects domains from multiple sources:
- Public blocklists (OISD, StevenBlack, etc.)
- SEO/Traffic ranking APIs (Tranco, Majestic Million)
- Aggregator sites (casino.org, askgamblers, etc.)
- Web scraping of category-specific sites

Usage:
    python collect_domains.py --category gambling --collect
    python collect_domains.py --category all --validate-only
    python collect_domains.py -d bet365.com
"""

import argparse
import subprocess
import re
import sys
import time
import urllib.request
import urllib.error
import ssl
from pathlib import Path
from typing import Optional, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass

# Type definitions
CategoryConfig = dict[str, list[str]]
BlockingResult = dict[str, Any]
ValidationResults = dict[str, Any]

# Public blocklist sources for each category
BLOCKLIST_SOURCES: dict[str, list[str]] = {
    "gambling": [
        # StevenBlack gambling hosts
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/gambling/hosts",
        # OISD gambling
        "https://raw.githubusercontent.com/sjhgvr/oisd/main/domainswild_gambling.txt",
        # Sinfonietta gambling
        "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/gambling-hosts",
        # Betting domains list
        "https://raw.githubusercontent.com/nextdns/gambling/main/gambling-domains",
    ],
    "adult": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/porn/hosts",
        "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/pornography-hosts",
        "https://raw.githubusercontent.com/chadmayfield/my-pihole-blocklists/master/lists/pi_blocklist_porn_all.list",
    ],
    "piracy": [
        "https://raw.githubusercontent.com/Sinfonietta/hostfiles/master/piracy-hosts",
        "https://raw.githubusercontent.com/nextdns/piracy-domains/main/piracy-domains",
    ],
    "malware": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
        "https://urlhaus.abuse.ch/downloads/hostfile/",
        "https://raw.githubusercontent.com/DandelionSprout/adfilt/master/Alternate%20versions%20Anti-Malware%20List/AntiMalwareHosts.txt",
    ],
    "social": [
        "https://raw.githubusercontent.com/StevenBlack/hosts/master/alternates/social/hosts",
    ],
    "dating": [],
    "violence": [],
}

# Aggregator sites to scrape for domains
AGGREGATOR_URLS: dict[str, list[str]] = {
    "gambling": [
        "https://www.casino.org/online-casinos/",
        "https://www.askgamblers.com/online-casinos",
        "https://www.top10casinos.com/",
        "https://www.gambling.com/online-casinos",
        "https://www.legitgamblingsites.com/online-casinos/",
        "https://www.sportsbettingdime.com/sportsbooks/",
        "https://www.covers.com/betting/betting-sites",
        "https://www.oddsshark.com/sportsbooks",
        "https://www.pokernews.com/poker-sites/",
        "https://www.cardschat.com/poker-sites/",
    ],
    "adult": [],
    "piracy": [
        "https://proxybay.github.io/",
    ],
    "malware": [],
    "social": [],
    "dating": [
        "https://www.top10.com/dating",
    ],
    "violence": [],
}

# Category-specific keywords to identify domains
CATEGORY_KEYWORDS: dict[str, list[str]] = {
    "gambling": [
        "casino", "bet", "poker", "slots", "gambling", "wager", "bingo",
        "lottery", "jackpot", "roulette", "blackjack", "sportsbook",
        "betting", "1xbet", "mostbet", "melbet", "parimatch", "betway",
        "stake", "roobet", "bovada", "draftkings", "fanduel",
    ],
    "adult": ["xxx", "porn", "adult", "nude", "nsfw"],
    "piracy": ["torrent", "pirate", "stream", "movie", "download"],
    "malware": ["malware", "virus", "phish"],
    "social": ["facebook", "instagram", "twitter", "tiktok", "snapchat"],
    "dating": ["dating", "match", "tinder", "bumble", "hinge"],
    "violence": [],
}

# DNS server for validation
DNS_SERVER = "low.kahfguard.com"
BLOCKED_CNAME = "blocked.kahfguard.com"

# HTTP settings
REQUEST_TIMEOUT = 30
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
)


@dataclass
class CollectionStats:
    """Statistics for domain collection."""
    source: str
    total_found: int
    new_domains: int
    errors: list[str]


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context that handles certificate issues gracefully."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_url(url: str, timeout: int = REQUEST_TIMEOUT) -> Optional[str]:
    """Fetch content from URL with error handling."""
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": USER_AGENT}
        )
        ctx = create_ssl_context()
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as response:
            return response.read().decode("utf-8", errors="ignore")
    except urllib.error.HTTPError as e:
        print(f"  HTTP Error {e.code} fetching {url}")
        return None
    except urllib.error.URLError as e:
        print(f"  URL Error fetching {url}: {e.reason}")
        return None
    except Exception as e:
        print(f"  Error fetching {url}: {e}")
        return None


def extract_domains_from_text(text: str) -> set[str]:
    """Extract all valid domains from text content."""
    domains: set[str] = set()

    # Pattern to match domains
    domain_pattern = (
        r'(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}'
    )

    # Find all potential domains
    for match in re.finditer(domain_pattern, text):
        domain = match.group(0).lower()

        # Skip common non-domain patterns
        skip_patterns = [
            "example.com", "localhost", "test.com", "domain.com",
            "yoursite.com", "website.com", "placeholder",
            ".png", ".jpg", ".gif", ".css", ".js", ".svg",
            "github.com", "githubusercontent.com", "cloudflare",
        ]
        if any(skip in domain for skip in skip_patterns):
            continue

        # Skip if too short or looks like a file extension
        if len(domain) < 4 or domain.count(".") < 1:
            continue

        # Validate format
        if validate_domain_format(domain):
            domains.add(domain)

    return domains


def extract_domains_from_hosts_file(content: str) -> set[str]:
    """Extract domains from hosts file format (0.0.0.0 domain.com)."""
    domains: set[str] = set()

    for line in content.splitlines():
        line = line.strip()

        # Skip comments and empty lines
        if not line or line.startswith("#"):
            continue

        # Parse hosts file format: IP domain
        parts = line.split()
        if len(parts) >= 2:
            # Domain is usually the second part
            domain = parts[1].lower()
            if validate_domain_format(domain):
                domains.add(domain)

    return domains


def validate_domain_format(domain: str) -> bool:
    """Validate domain format."""
    if not domain or len(domain) > 253:
        return False

    # Remove www. prefix for consistency
    if domain.startswith("www."):
        domain = domain[4:]

    # Basic domain validation
    pattern = (
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    return bool(re.match(pattern, domain))


def check_blocking_status(domain: str) -> BlockingResult:
    """Check if a domain is blocked by KahfGuard DNS."""
    result: BlockingResult = {
        "domain": domain,
        "is_blocked": False,
        "cname": None,
        "error": None,
    }

    try:
        cmd = ["dig", f"@{DNS_SERVER}", domain, "+short", "+time=5", "+tries=2"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        output = proc.stdout.strip()

        if BLOCKED_CNAME in output:
            result["is_blocked"] = True
            result["cname"] = BLOCKED_CNAME
        elif output:
            result["cname"] = output.split("\n")[0]

    except subprocess.TimeoutExpired:
        result["error"] = "timeout"
    except Exception as e:
        result["error"] = str(e)

    return result


def load_existing_domains(category: str) -> set[str]:
    """Load existing domains from the blacklist file."""
    script_dir = Path(__file__).parent
    blacklist_file = script_dir.parent / "kahf-custom-blacklist" / f"{category}.txt"

    domains: set[str] = set()
    if blacklist_file.exists():
        with open(blacklist_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    return domains


def save_domains(category: str, domains: set[str]) -> None:
    """Save domains to the blacklist file (sorted, deduplicated)."""
    script_dir = Path(__file__).parent
    blacklist_file = script_dir.parent / "kahf-custom-blacklist" / f"{category}.txt"

    sorted_domains = sorted(domains)
    with open(blacklist_file, "w") as f:
        for domain in sorted_domains:
            f.write(f"{domain}\n")

    print(f"Saved {len(sorted_domains)} domains to {blacklist_file}")


def fetch_from_blocklists(category: str) -> tuple[set[str], list[str]]:
    """Fetch domains from public blocklists."""
    domains: set[str] = set()
    errors: list[str] = []

    sources = BLOCKLIST_SOURCES.get(category, [])
    if not sources:
        return domains, errors

    print(f"\n  Fetching from {len(sources)} public blocklist sources...")

    for url in sources:
        print(f"    - {url[:60]}...")
        content = fetch_url(url)

        if content is None:
            errors.append(f"Failed to fetch: {url}")
            continue

        # Detect format and extract domains
        if "0.0.0.0" in content or "127.0.0.1" in content:
            extracted = extract_domains_from_hosts_file(content)
        else:
            extracted = extract_domains_from_text(content)

        domains.update(extracted)
        print(f"      Found {len(extracted)} domains")

        # Rate limiting
        time.sleep(0.5)

    return domains, errors


def fetch_from_aggregators(category: str) -> tuple[set[str], list[str]]:
    """Scrape domains from aggregator websites."""
    domains: set[str] = set()
    errors: list[str] = []

    urls = AGGREGATOR_URLS.get(category, [])
    keywords = CATEGORY_KEYWORDS.get(category, [])

    if not urls:
        return domains, errors

    print(f"\n  Scraping {len(urls)} aggregator sites...")

    for url in urls:
        print(f"    - {url[:60]}...")
        content = fetch_url(url)

        if content is None:
            errors.append(f"Failed to fetch: {url}")
            continue

        # Extract all domains from the page
        extracted = extract_domains_from_text(content)

        # Filter by category keywords if available
        if keywords:
            filtered: set[str] = set()
            for domain in extracted:
                if any(kw in domain for kw in keywords):
                    filtered.add(domain)
            extracted = filtered

        domains.update(extracted)
        print(f"      Found {len(extracted)} relevant domains")

        # Rate limiting to be respectful
        time.sleep(1)

    return domains, errors


def fetch_from_tranco_list(category: str, limit: int = 10000) -> tuple[set[str], list[str]]:
    """
    Fetch top domains from Tranco list and filter by category keywords.
    Tranco combines Alexa, Umbrella, Majestic rankings.
    """
    domains: set[str] = set()
    errors: list[str] = []

    keywords = CATEGORY_KEYWORDS.get(category, [])
    if not keywords:
        return domains, errors

    print("\n  Fetching from Tranco Top Sites list...")

    # Tranco provides daily updated list of top sites
    url = "https://tranco-list.eu/top-1m.csv.zip"

    try:
        import zipfile
        import io

        content = fetch_url(url, timeout=60)
        if content is None:
            errors.append("Failed to fetch Tranco list")
            return domains, errors

        # The response is actually binary for zip
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        ctx = create_ssl_context()
        with urllib.request.urlopen(req, timeout=60, context=ctx) as response:
            zip_data = response.read()

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            with zf.open("top-1m.csv") as csvfile:
                for i, line in enumerate(csvfile):
                    if i >= limit:
                        break
                    try:
                        _, domain = line.decode().strip().split(",")
                        domain = domain.lower()
                        if any(kw in domain for kw in keywords):
                            if validate_domain_format(domain):
                                domains.add(domain)
                    except Exception:
                        continue

        print(f"    Found {len(domains)} matching domains in top {limit}")

    except ImportError:
        print("    Skipping Tranco (zipfile module issue)")
    except Exception as e:
        errors.append(f"Tranco fetch error: {e}")
        print(f"    Error: {e}")

    return domains, errors


def collect_from_web(category: str, max_results: int = 5000) -> set[str]:
    """
    Collect domains from multiple web sources for a category.

    Sources:
    1. Public blocklists (StevenBlack, OISD, etc.)
    2. SEO ranking lists (Tranco)
    3. Category-specific aggregator sites

    Returns:
        Set of discovered domain names
    """
    all_domains: set[str] = set()
    all_stats: list[CollectionStats] = []

    print(f"\n{'='*50}")
    print(f"COLLECTING DOMAINS FOR: {category.upper()}")
    print(f"{'='*50}")

    # 1. Fetch from public blocklists
    blocklist_domains, blocklist_errors = fetch_from_blocklists(category)
    all_domains.update(blocklist_domains)
    all_stats.append(CollectionStats(
        source="Public Blocklists",
        total_found=len(blocklist_domains),
        new_domains=len(blocklist_domains),
        errors=blocklist_errors
    ))

    # 2. Fetch from aggregator sites
    aggregator_domains, aggregator_errors = fetch_from_aggregators(category)
    new_from_agg = aggregator_domains - all_domains
    all_domains.update(aggregator_domains)
    all_stats.append(CollectionStats(
        source="Aggregator Sites",
        total_found=len(aggregator_domains),
        new_domains=len(new_from_agg),
        errors=aggregator_errors
    ))

    # 3. Fetch from Tranco ranking list
    tranco_domains, tranco_errors = fetch_from_tranco_list(category)
    new_from_tranco = tranco_domains - all_domains
    all_domains.update(tranco_domains)
    all_stats.append(CollectionStats(
        source="Tranco Top Sites",
        total_found=len(tranco_domains),
        new_domains=len(new_from_tranco),
        errors=tranco_errors
    ))

    # Print collection summary
    print(f"\n{'='*50}")
    print("COLLECTION SUMMARY")
    print(f"{'='*50}")
    for stat in all_stats:
        print(f"  {stat.source}: {stat.total_found} found, {stat.new_domains} new")
        if stat.errors:
            for err in stat.errors[:3]:
                print(f"    ⚠ {err[:60]}")

    print(f"\n  TOTAL UNIQUE DOMAINS: {len(all_domains)}")

    # Limit results if needed
    if len(all_domains) > max_results:
        print(f"  (Limited to {max_results} results)")
        all_domains = set(list(all_domains)[:max_results])

    return all_domains


def validate_category(category: str, verbose: bool = False) -> ValidationResults:
    """Validate all domains in a category against KahfGuard DNS."""
    domains = load_existing_domains(category)

    results: ValidationResults = {
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
                    print(f"  [{i}/{len(domains)}] ERROR: {domain}")
            elif result["is_blocked"]:
                results["blocked"].append(domain)
                if verbose:
                    print(f"  [{i}/{len(domains)}] BLOCKED: {domain}")
            else:
                results["not_blocked"].append(domain)
                if verbose:
                    cname = result["cname"]
                    print(f"  [{i}/{len(domains)}] NOT BLOCKED: {domain} -> {cname}")

            if not verbose and i % 50 == 0:
                print(f"  Progress: {i}/{len(domains)}")

    return results


def generate_report(category: str, results: ValidationResults) -> str:
    """Generate a validation report."""
    report: list[str] = []
    total = results["total"]
    blocked_count = len(results["blocked"])
    pct = (100 * blocked_count // max(total, 1))

    report.append(f"\n{'=' * 60}")
    report.append(f"VALIDATION REPORT: {category.upper()}")
    report.append(f"{'=' * 60}")
    report.append(f"Total domains: {total}")
    report.append(f"Blocked:       {blocked_count} ({pct}%)")
    report.append(f"Not blocked:   {len(results['not_blocked'])}")
    report.append(f"Errors:        {len(results['errors'])}")

    if results["not_blocked"]:
        report.append("\nDomains NOT blocked (need investigation):")
        for domain in sorted(results["not_blocked"])[:20]:
            report.append(f"  - {domain}")
        remaining = len(results["not_blocked"]) - 20
        if remaining > 0:
            report.append(f"  ... and {remaining} more")

    if results["errors"]:
        report.append("\nDomains with errors:")
        for domain in sorted(results["errors"])[:10]:
            report.append(f"  - {domain}")

    report.append(f"{'=' * 60}\n")
    return "\n".join(report)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Collect and validate domains for KahfGuard blacklists"
    )
    parser.add_argument(
        "--category", "-c",
        choices=list(BLOCKLIST_SOURCES.keys()) + ["all"],
        help="Category to process (or 'all')"
    )
    parser.add_argument(
        "--validate-only", "-v",
        action="store_true",
        help="Only validate existing domains"
    )
    parser.add_argument(
        "--collect", "-C",
        action="store_true",
        help="Collect new domains from web sources"
    )
    parser.add_argument(
        "--add-domains", "-a",
        nargs="+",
        help="Manually add domains"
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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Don't save changes, just show what would be added"
    )

    args = parser.parse_args()

    # Single domain check
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

    categories = (
        list(BLOCKLIST_SOURCES.keys())
        if args.category == "all"
        else [args.category]
    )

    for category in categories:
        print(f"\n{'#' * 60}")
        print(f"# Processing: {category.upper()}")
        print(f"{'#' * 60}")

        existing = load_existing_domains(category)
        print(f"Loaded {len(existing)} existing domains")

        # Add manual domains
        if args.add_domains:
            for domain in args.add_domains:
                domain = domain.lower().strip()
                if validate_domain_format(domain):
                    existing.add(domain)
                    print(f"  Added: {domain}")
                else:
                    print(f"  Invalid: {domain}")
            if not args.dry_run:
                save_domains(category, existing)

        # Collect from web
        if args.collect:
            new_domains = collect_from_web(category)
            added = new_domains - existing

            print(f"\nNew domains to add: {len(added)}")
            if added and args.verbose:
                for domain in sorted(added)[:50]:
                    print(f"  + {domain}")

            if added and not args.dry_run:
                existing.update(new_domains)
                save_domains(category, existing)
            elif args.dry_run:
                print("\n(Dry run - no changes saved)")

        # Validate
        if args.validate_only or (not args.add_domains and not args.collect):
            results = validate_category(category, verbose=args.verbose)
            report = generate_report(category, results)
            print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
