#!/usr/bin/env python3
"""
Build whitelist with top global sites and critical Bangladesh sites.

Fetches top 1000 domains from Tranco list and combines with:
- Bangladesh government, education, banking, telecom sites
- Global tech and productivity services
- Islamic resources

Organizes into categories in lists/allow/ directory.

Usage:
    python build_whitelist.py              # Update all whitelist categories
    python build_whitelist.py --dry-run    # Show what would be added
"""

import argparse
import ssl
import urllib.request
from pathlib import Path

# Domains to exclude (gambling, adult, etc.)
EXCLUDE_KEYWORDS = [
    "porn",
    "xxx",
    "adult",
    "sex",
    "nude",
    "erotic",
    "hentai",
    "casino",
    "bet",
    "gambling",
    "poker",
    "slots",
    "lottery",
    "torrent",
    "pirate",
    "warez",
    "xvideos",
    "xnxx",
    "xhamster",
    "pornhub",
    "redtube",
]

# Bangladesh critical domains
BANGLADESH_CRITICAL = [
    # Government
    "gov.bd",
    "bangladesh.gov.bd",
    "cabinet.gov.bd",
    "mopa.gov.bd",
    "police.gov.bd",
    "nb.gov.bd",
    "bb.org.bd",
    "bbs.gov.bd",
    "btrc.gov.bd",
    "mof.gov.bd",
    "mincom.gov.bd",
    "mod.gov.bd",
    "mohfw.gov.bd",
    "moe.gov.bd",
    "lgd.gov.bd",
    "imed.gov.bd",
    "bida.gov.bd",
    "customs.gov.bd",
    "nctb.gov.bd",
    "pcc.police.gov.bd",
    "gd.police.gov.bd",
    "web.bise-ctg.gov.bd",
    "bise-ctg.gov.bd",
    # Education
    "du.ac.bd",
    "buet.ac.bd",
    "bracu.ac.bd",
    "nsu.edu.bd",
    "aiub.edu",
    "iub.edu.bd",
    "ewubd.edu",
    "daffodilvarsity.edu.bd",
    "uiu.ac.bd",
    "aust.edu",
    "uap-bd.edu",
    "nu.ac.bd",
    "cu.ac.bd",
    "ru.ac.bd",
    "ju.ac.bd",
    "kuet.ac.bd",
    "ruet.ac.bd",
    "cuet.ac.bd",
    "sust.edu",
    "bup.edu.bd",
    "iom.edu.bd",
    # Banks & Finance
    "bracbank.com",
    "dutchbanglabank.com",
    "ebl.com.bd",
    "islamibankbd.com",
    "primebank.com.bd",
    "standardbankbd.com",
    "ucb.com.bd",
    "onebankbd.com",
    "mtb.com.bd",
    "citybank.com.bd",
    "pubalibank.com.bd",
    "bankasia-bd.com",
    "southeastbank.com.bd",
    "nagad.com.bd",
    "bkash.com",
    "bka.sh",
    "rocket.com.bd",
    "upay.com.bd",
    "dsebd.org",
    "cse.com.bd",
    # Telecom
    "grameenphone.com",
    "robi.com.bd",
    "banglalink.net",
    "teletalk.com.bd",
    "btcl.com.bd",
    # News & Media
    "prothomalo.com",
    "thedailystar.net",
    "bd-pratidin.com",
    "kalerkantho.com",
    "jugantor.com",
    "ittefaq.com.bd",
    "samakal.com",
    "banglanews24.com",
    "bdnews24.com",
    "dhakatribune.com",
    "newagebd.net",
    "bssnews.net",
    "tbsnews.net",
    # E-commerce
    "daraz.com.bd",
    "chaldal.com",
    "foodpanda.com.bd",
    "pathao.com",
    "shohoz.com",
    "bikroy.com",
    "bdjobs.com",
    # Healthcare
    "dghs.gov.bd",
    "squarehospital.com",
    "labaid.com.bd",
    # Utilities
    "desco.org.bd",
    "dpdc.org.bd",
    "dwasa.org.bd",
    "railway.gov.bd",
    "biman-airlines.com",
    "caab.gov.bd",
    # Education platforms
    "online.udvash-unmesh.com",
    "sikho.co",
    "ieducationbd.com",
]

# Category patterns for whitelist organization
WHITELIST_CATEGORIES: dict[str, list[str]] = {
    "microsoft": [
        "microsoft",
        "azure",
        "office",
        "outlook",
        "live.com",
        "live.net",
        "msn.com",
        "bing.com",
        "msedge",
        "windows",
        "xbox",
        "skype",
        "linkedin",
        "github",
        "visualstudio",
        "onedrive",
        "sharepoint",
        "teams",
        "yammer",
        "hotmail",
        "msft",
        "msauth",
        "microsoftonline",
        "onenote",
        "sway",
        "powerbi",
        "powerapps",
        "flow.microsoft",
        "defender",
        "intune",
        "dynamics",
    ],
    "google": [
        "google",
        "youtube",
        "gmail",
        "gstatic",
        "googleapis",
        "ggpht",
        "ytimg",
        "googlevideo",
        "gvt1",
        "gvt2",
        "gvt3",
        "doubleclick",
        "googlesyndication",
        "googleadservices",
        "googletagmanager",
        "googleanalytics",
        "blogger",
        "blogspot",
        "firebase",
        "firebaseio",
        "appspot",
        "withgoogle",
        "android",
        "chromium",
        "ampproject",
        "recaptcha",
        "goog",
        "g.co",
        "g.page",
    ],
    "apple": [
        "apple",
        "icloud",
        "itunes",
        "mzstatic",
        "aaplimg",
        "apple-dns",
    ],
    "meta": [
        "facebook",
        "fb.com",
        "fbcdn",
        "instagram",
        "whatsapp",
        "messenger",
        "threads.com",
        "meta.com",
        "oculus",
    ],
    "amazon": [
        "amazon.",
        "amzn",
        "primevideo",
        "amazonalexa",
        "amazontrust",
        "amazonvideo",
        "ssl-images-amazon",
        "media-amazon",
        "a2z.com",
    ],
    "bangladesh": [
        ".bd",
        "bangladesh",
        "bangla",
        "bkash",
        "nagad",
        "grameenphone",
        "robi.com",
        "pathao",
        "daraz.com.bd",
        "chaldal",
        "foodpanda.com.bd",
        "prothomalo",
        "thedailystar",
        "bdnews24",
        "ittefaq",
        "kalerkantho",
        "jugantor",
        "samakal",
        "somewhereinblog",
        "bikroy",
        "bdjobs",
        "shohoz",
        "rocket.com.bd",
        "upay",
        "dutchbanglabank",
        "bracbank",
        "citybank.com.bd",
        "ebl.com.bd",
        "mtb.com.bd",
        "primebank",
        "standardbankbd",
        "islamibankbd",
        "onebankbd",
        "ucb.com.bd",
        "labaid",
        "squarehospital",
        "udvash",
        "sikho",
        "muhammadyunus",
    ],
    "infrastructure": [
        "akamai",
        "cloudflare",
        "fastly",
        "edgecast",
        "cdn",
        "amazonaws",
        "azure",
        "digitalocean",
        "linode",
        "rackspace",
        "ovh.net",
        "bunny",
        "gcdn",
        "ngenix",
        "cloudfront",
        "edgekey",
        "edgesuite",
        "akadns",
        "gtld",
        "root-servers",
        "dnspod",
        "dnsowl",
        "cloudns",
        "he.net",
        "verisign",
        "globalsign",
        "digicert",
        "letsencrypt",
        "identrust",
        "entrust",
        "geotrust",
        "ocsp",
        "crl",
        "pki.goog",
        "cacerts",
    ],
    "social-media": [
        "twitter",
        "x.com",
        "twimg",
        "t.co",
        "tiktok",
        "snapchat",
        "reddit",
        "tumblr",
        "pinterest",
        "discord",
        "telegram",
        "viber",
        "line.me",
        "vk.com",
        "vk.ru",
        "ok.ru",
        "weibo",
        "bsky.app",
    ],
    "news-media": [
        "bbc.",
        "cnn.",
        "nytimes",
        "washingtonpost",
        "reuters",
        "apnews",
        "npr.org",
        "theguardian",
        "forbes",
        "bloomberg",
        "wsj.com",
        "economist",
        "time.com",
        "newsweek",
        "huffpost",
        "buzzfeed",
        "businessinsider",
        "techcrunch",
        "wired",
        "theverge",
        "cnet",
        "independent",
        "telegraph",
        "dailymail",
        "foxnews",
        "cbsnews",
        "nbcnews",
        "usatoday",
        "ft.com",
        "hbr.org",
    ],
    "education": [
        ".edu",
        "coursera",
        "udemy",
        "khanacademy",
        "edx.org",
        "duolingo",
        "quizlet",
        "academia.edu",
        "researchgate",
        "arxiv.org",
        "ieee.org",
        "britannica",
        "wikipedia",
        "wikimedia",
        "cambridge.org",
        "harvard",
        "mit.edu",
        "stanford",
        "berkeley",
        "cornell",
        "yale",
        "princeton",
    ],
    "ecommerce": [
        "ebay",
        "alibaba",
        "aliexpress",
        "shopify",
        "etsy",
        "walmart",
        "target",
        "bestbuy",
        "costco",
        "homedepot",
        "lowes",
        "ikea",
        "nike",
        "shein",
        "temu",
        "booking.com",
        "airbnb",
        "tripadvisor",
        "agoda",
        "rakuten",
    ],
    "productivity": [
        "slack",
        "zoom",
        "webex",
        "teamviewer",
        "anydesk",
        "notion",
        "trello",
        "atlassian",
        "dropbox",
        "box.com",
        "adobe",
        "canva",
        "figma",
        "mailchimp",
        "hubspot",
        "salesforce",
        "zendesk",
        "grammarly",
        "deepl",
        "openai",
        "chatgpt",
        "cursor",
    ],
    "gaming": [
        "steam",
        "epicgames",
        "playstation",
        "xbox",
        "nintendo",
        "twitch",
        "riot",
        "blizzard",
        "ea.com",
        "ubisoft",
        "supercell",
        "unity3d",
        "kick.com",
    ],
    "security": [
        "kaspersky",
        "mcafee",
        "norton",
        "avast",
        "sophos",
        "trendmicro",
        "eset",
        "paloalto",
        "checkpoint",
        "crowdstrike",
        "sentinelone",
        "f5.com",
        "cisco",
    ],
    "government": [
        ".gov",
        "gov.uk",
        "gov.br",
        "europa.eu",
        "un.org",
        "who.int",
        "unesco",
        "worldbank",
        "whitehouse",
        "nasa.gov",
        "nih.gov",
        "cdc.gov",
    ],
    "finance": [
        "paypal",
        "stripe",
        "visa",
        "mastercard",
        "bankofamerica",
        "binance",
        "coinbase",
        "intuit",
        "tradingview",
    ],
    "islamic": [
        "quran",
        "islamqa",
        "islamicfinder",
        "sunnah",
        "alhadith",
        "muslimcentral",
    ],
    "chinese-tech": [
        "163.com",
        "360.cn",
        "360safe",
        "baidu",
        "alibaba",
        "tencent",
        "qq.com",
        "aliyun",
        "alicdn",
        "taobao",
        "bilibili",
        "youku",
        "xiaomi",
        "huawei",
        "bytedance",
        "bytedns",
        "bytefcdn",
        "douyin",
        "kwai",
        "sohu",
        "sina",
        "netease",
    ],
    "russian-tech": [
        "yandex",
        "mail.ru",
        "rambler",
        "avito",
        "sberbank",
        "gosuslugi",
        "wildberries",
        "ozon.ru",
        "pikabu",
        "dzen.ru",
        "rutube",
        "ivi.ru",
        "livejournal",
        "rbc.ru",
    ],
    "developer": [
        "github",
        "gitlab",
        "bitbucket",
        "stackoverflow",
        "npm",
        "pypi",
        "readthedocs",
        "launchpad",
        "sourceforge",
        "gnu.org",
        "debian",
        "ubuntu",
        "redhat",
        "docker",
        "jsdelivr",
        "unpkg",
        "w3.org",
        "w3schools",
    ],
    "hardware": [
        "asus",
        "dell",
        "hp.com",
        "lenovo",
        "samsung",
        "lg.com",
        "sony",
        "intel",
        "amd",
        "nvidia",
        "cisco",
        "netgear",
        "tp-link",
        "ubnt",
        "mikrotik",
        "synology",
        "xerox",
        "garmin",
    ],
    "streaming": [
        "netflix",
        "spotify",
        "disney",
        "hbo",
        "hulu",
        "soundcloud",
        "bandcamp",
        "vimeo",
        "dailymotion",
        "roku",
        "scdn.co",
        "spotifycdn",
        "nflx",
    ],
    "advertising": [
        "adsrvr",
        "adnxs",
        "pubmatic",
        "rubiconproject",
        "criteo",
        "taboola",
        "outbrain",
        "teads",
        "sharethrough",
        "openx",
        "smaato",
        "inmobi",
        "applovin",
        "vungle",
        "adjust",
        "appsflyer",
        "branch",
        "amplitude",
        "mixpanel",
        "segment",
        "braze",
        "onetrust",
        "cookielaw",
        "quantcast",
        "newrelic",
        "datadog",
        "hotjar",
        "clarity.ms",
    ],
}


def create_ssl_context() -> ssl.SSLContext:
    """Create SSL context for HTTPS requests."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def fetch_tranco_top(count: int = 1000) -> list[str]:
    """Fetch top domains from Tranco list."""
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


def categorize_domain(domain: str) -> str:
    """Determine the category for a whitelist domain."""
    domain_lower = domain.lower()

    for category, keywords in WHITELIST_CATEGORIES.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category

    return "misc"


def load_domains(filepath: Path) -> set[str]:
    """Load domains from a file."""
    domains: set[str] = set()
    if filepath.exists():
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.add(line.lower())
    return domains


def save_domains(filepath: Path, domains: set[str]) -> None:
    """Save domains to a file (sorted)."""
    sorted_domains = sorted(domains)
    with open(filepath, "w") as f:
        for domain in sorted_domains:
            f.write(f"{domain}\n")


def load_all_existing_domains(whitelist_dir: Path) -> set[str]:
    """Load all existing domains from all category files."""
    all_existing: set[str] = set()
    categories = list(WHITELIST_CATEGORIES.keys()) + ["misc"]

    for category in categories:
        category_file = whitelist_dir / f"{category}.txt"
        all_existing.update(load_domains(category_file))

    return all_existing


def main() -> int:
    parser = argparse.ArgumentParser(description="Build comprehensive whitelist")
    parser.add_argument(
        "--dry-run", action="store_true", help="Show changes without saving"
    )
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    whitelist_dir = repo_root / "lists/allow"

    print("Building comprehensive whitelist...\n")

    # Load all existing domains from all category files first
    print("Loading existing domains from all category files...")
    all_existing = load_all_existing_domains(whitelist_dir)
    print(f"Found {len(all_existing)} existing domains across all categories")

    # Fetch Tranco
    print("\nFetching Tranco top 1000...")
    tranco = fetch_tranco_top(1000)
    safe_tranco = [d for d in tranco if is_safe_domain(d)]
    print(f"Fetched {len(tranco)}, filtered to {len(safe_tranco)} safe domains")

    # Combine all sources
    all_domains: set[str] = set()
    all_domains.update(d.lower() for d in safe_tranco)
    all_domains.update(d.lower() for d in BANGLADESH_CRITICAL)

    # Final filter
    final_domains = {d for d in all_domains if is_safe_domain(d)}

    # Filter out domains that already exist in any category
    new_domains = final_domains - all_existing
    print(
        f"Total domains: {len(final_domains)}, New (not in any category): {len(new_domains)}"
    )

    if not new_domains:
        print("\nNo new domains to add. All domains already exist in category files.")
        return 0

    # Categorize only NEW domains
    categorized: dict[str, set[str]] = {cat: set() for cat in WHITELIST_CATEGORIES}
    categorized["misc"] = set()

    for domain in new_domains:
        category = categorize_domain(domain)
        categorized[category].add(domain)

    # Print results
    print("\nNew domains by category:")
    for category, domains in sorted(categorized.items(), key=lambda x: -len(x[1])):
        if domains:
            print(f"  {category}: +{len(domains)} new")

    if args.dry_run:
        print("\n[DRY RUN] Would update category files")
        return 0

    # Merge with existing and save
    print("\nAdding new domains to category files...")

    for category, new_cat_domains in categorized.items():
        if not new_cat_domains:
            continue
        category_file = whitelist_dir / f"{category}.txt"
        existing = load_domains(category_file)
        merged = existing | new_cat_domains
        save_domains(category_file, merged)
        print(
            f"  {category}.txt: {len(existing)} + {len(new_cat_domains)} = {len(merged)}"
        )

    # Update whitelist_domains.txt with deprecation notice
    whitelist_file = repo_root / "whitelist_domains.txt"
    with open(whitelist_file, "w") as f:
        f.write("# This file is deprecated. See lists/allow/ for categorized lists.\n")
        f.write(
            "# The whitelist is now organized into categories for easier maintenance.\n"
        )

    print("\nDone!")
    return 0


if __name__ == "__main__":
    exit(main())
