#!/usr/bin/env python3
"""
Build whitelist with top global sites and critical Bangladesh sites.

Fetches top 1000 domains from Tranco list and combines with:
- Bangladesh government, education, banking, telecom sites
- Global tech and productivity services
- Islamic resources

Usage:
    python build_whitelist.py              # Update whitelist_domains.txt
    python build_whitelist.py --dry-run    # Show what would be added
"""

import argparse
import urllib.request
import urllib.error
import ssl
from pathlib import Path

# Domains to exclude (gambling, adult, etc.)
EXCLUDE_KEYWORDS = [
    "porn", "xxx", "adult", "sex", "nude", "erotic", "hentai",
    "casino", "bet", "gambling", "poker", "slots", "lottery",
    "torrent", "pirate", "warez",
    "xvideos", "xnxx", "xhamster", "pornhub", "redtube",
    "roblox",  # Gaming platform, may be blocked intentionally
]

# Bangladesh critical domains
BANGLADESH_CRITICAL = [
    # Government
    "gov.bd", "bangladesh.gov.bd", "cabinet.gov.bd", "mopa.gov.bd",
    "police.gov.bd", "nb.gov.bd", "bb.org.bd", "bbs.gov.bd",
    "btrc.gov.bd", "mof.gov.bd", "mincom.gov.bd", "mod.gov.bd",
    "mohfw.gov.bd", "moe.gov.bd", "lgd.gov.bd", "imed.gov.bd",
    "bida.gov.bd", "customs.gov.bd", "nctb.gov.bd",
    # Education
    "du.ac.bd", "buet.ac.bd", "bracu.ac.bd", "nsu.edu.bd",
    "aiub.edu", "iub.edu.bd", "ewubd.edu", "daffodilvarsity.edu.bd",
    "uiu.ac.bd", "aust.edu", "uap-bd.edu", "nu.ac.bd", "cu.ac.bd",
    "ru.ac.bd", "ju.ac.bd", "kuet.ac.bd", "ruet.ac.bd", "cuet.ac.bd",
    "sust.edu", "bup.edu.bd",
    # Banks & Finance
    "bracbank.com", "dutchbanglabank.com", "ebl.com.bd",
    "islamibankbd.com", "primebank.com.bd", "standardbankbd.com",
    "ucb.com.bd", "onebankbd.com", "mtb.com.bd", "citybank.com.bd",
    "pubalibank.com.bd", "bankasia-bd.com", "southeastbank.com.bd",
    "nagad.com.bd", "bkash.com", "rocket.com.bd", "upay.com.bd",
    "dsebd.org", "cse.com.bd",
    # Telecom
    "grameenphone.com", "robi.com.bd", "banglalink.net",
    "teletalk.com.bd", "btcl.com.bd",
    # News & Media
    "prothomalo.com", "thedailystar.net", "bd-pratidin.com",
    "kalerkantho.com", "jugantor.com", "ittefaq.com.bd",
    "samakal.com", "banglanews24.com", "bdnews24.com",
    "dhakatribune.com", "newagebd.net", "bssnews.net",
    # E-commerce
    "daraz.com.bd", "chaldal.com", "foodpanda.com.bd",
    "pathao.com", "shohoz.com", "bikroy.com", "bdjobs.com",
    # Healthcare
    "dghs.gov.bd", "squarehospital.com", "labaid.com.bd",
    # Utilities
    "desco.org.bd", "dpdc.org.bd", "dwasa.org.bd",
    "railway.gov.bd", "biman-airlines.com", "caab.gov.bd",
]

# Global critical services
GLOBAL_CRITICAL = [
    # Search & Productivity
    "google.com", "bing.com", "duckduckgo.com",
    # Social (legitimate business use)
    "facebook.com", "instagram.com", "linkedin.com",
    "twitter.com", "x.com", "pinterest.com", "reddit.com",
    # Messaging
    "whatsapp.com", "whatsapp.net", "wa.me",
    "telegram.org", "signal.org", "discord.com",
    "slack.com", "zoom.us", "teams.microsoft.com",
    # Video & Media
    "youtube.com", "youtu.be", "vimeo.com", "twitch.tv",
    "netflix.com", "spotify.com", "soundcloud.com",
    # Cloud & Dev
    "github.com", "gitlab.com", "bitbucket.org",
    "stackoverflow.com", "npmjs.com", "pypi.org",
    "aws.amazon.com", "azure.microsoft.com", "cloud.google.com",
    "digitalocean.com", "vercel.com", "netlify.com",
    # E-commerce
    "amazon.com", "ebay.com", "aliexpress.com", "shopify.com",
    # Knowledge
    "wikipedia.org", "medium.com", "quora.com",
    # Finance
    "paypal.com", "stripe.com", "wise.com",
    # Tools
    "figma.com", "canva.com", "adobe.com",
    "notion.com", "notion.so", "trello.com", "dropbox.com",
    # Education
    "coursera.org", "udemy.com", "edx.org", "khanacademy.org",
    # Islamic Resources
    "quran.com", "sunnah.com", "islamqa.info",
    "muslimcentral.com", "islamicfinder.org",
]


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for HTTPS requests."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_tranco_top(count: int = 1000) -> list[str]:
    """Fetch top domains from Tranco list."""
    # Get latest list ID
    url = f"https://tranco-list.eu/download/ZWJGG/{count}"
    try:
        ctx = create_ssl_context()
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30, context=ctx) as response:
            content = response.read().decode("utf-8")
            domains = []
            for line in content.strip().split("\n"):
                if "," in line:
                    _, domain = line.split(",", 1)
                    domains.append(domain.strip().lower())
            return domains
    except Exception as e:
        print(f"Error fetching Tranco: {e}")
        return []


def is_safe_domain(domain: str) -> bool:
    """Check if domain is safe to whitelist."""
    domain_lower = domain.lower()
    for keyword in EXCLUDE_KEYWORDS:
        if keyword in domain_lower:
            return False
    return True


def load_existing_whitelist() -> set[str]:
    """Load existing whitelist domains."""
    script_dir = Path(__file__).parent
    whitelist_file = script_dir.parent / "whitelist_domains.txt"

    domains: set[str] = set()
    if whitelist_file.exists():
        with open(whitelist_file, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    return domains


def save_whitelist(domains: set[str]) -> None:
    """Save whitelist (sorted, deduplicated)."""
    script_dir = Path(__file__).parent
    whitelist_file = script_dir.parent / "whitelist_domains.txt"

    header = [
        "# KahfGuard Whitelist - Critical domains that should never be blocked",
        "# Includes: Top 1000 global sites (Tranco), Bangladesh critical services",
        "#",
    ]

    sorted_domains = sorted(domains)
    with open(whitelist_file, "w") as f:
        for line in header:
            f.write(f"{line}\n")
        for domain in sorted_domains:
            f.write(f"{domain}\n")

    print(f"Saved {len(sorted_domains)} domains to {whitelist_file}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Build comprehensive whitelist")
    parser.add_argument("--dry-run", action="store_true", help="Show changes without saving")
    args = parser.parse_args()

    print("Building comprehensive whitelist...\n")

    # Load existing
    existing = load_existing_whitelist()
    print(f"Existing whitelist: {len(existing)} domains")

    # Fetch Tranco
    print("\nFetching Tranco top 1000...")
    tranco = fetch_tranco_top(1000)
    safe_tranco = [d for d in tranco if is_safe_domain(d)]
    print(f"Fetched {len(tranco)}, filtered to {len(safe_tranco)} safe domains")

    # Combine all
    all_domains: set[str] = set()
    all_domains.update(existing)
    all_domains.update(d.lower() for d in safe_tranco)
    all_domains.update(d.lower() for d in BANGLADESH_CRITICAL)
    all_domains.update(d.lower() for d in GLOBAL_CRITICAL)

    # Final filter
    final_domains = {d for d in all_domains if is_safe_domain(d)}

    print(f"\nFinal whitelist: {len(final_domains)} domains")
    new_domains = final_domains - existing
    print(f"New domains to add: {len(new_domains)}")

    if args.dry_run:
        print("\n[DRY RUN] Would add these domains:")
        for d in sorted(new_domains)[:50]:
            print(f"  + {d}")
        if len(new_domains) > 50:
            print(f"  ... and {len(new_domains) - 50} more")
    else:
        save_whitelist(final_domains)

    return 0


if __name__ == "__main__":
    exit(main())
