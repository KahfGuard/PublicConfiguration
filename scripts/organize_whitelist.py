#!/usr/bin/env python3
"""
Organize whitelist_domains.txt into category-specific files.

Categorizes domains based on keywords and patterns, organizing them into:
- lists/allow/microsoft.txt
- lists/allow/google.txt
- lists/allow/apple.txt
- lists/allow/meta.txt
- lists/allow/amazon.txt
- lists/allow/bangladesh.txt
- lists/allow/infrastructure.txt
- lists/allow/social-media.txt
- lists/allow/news-media.txt
- lists/allow/education.txt
- lists/allow/ecommerce.txt
- lists/allow/productivity.txt
- lists/allow/gaming.txt
- lists/allow/security.txt
- lists/allow/government.txt
- lists/allow/finance.txt
- lists/allow/islamic.txt
- lists/allow/chinese-tech.txt
- lists/allow/russian-tech.txt
- lists/allow/developer.txt
- lists/allow/hardware.txt
- lists/allow/streaming.txt
- lists/allow/advertising.txt
- lists/allow/misc.txt

Remaining uncategorized domains go to misc.txt.

Usage:
    python organize_whitelist.py              # Organize and save
    python organize_whitelist.py --dry-run    # Preview without saving
"""

import argparse
from pathlib import Path

# Category keyword patterns (same as build_whitelist.py)
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
        "dns.google",
        "opendns",
        "quad9",
        "cleanbrowsing",
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


def categorize_domain(domain: str) -> str:
    """Determine the category for a domain."""
    domain_lower = domain.lower()

    for category, keywords in WHITELIST_CATEGORIES.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category

    return "misc"


def load_domains(filepath: Path) -> list[str]:
    """Load domains from a file."""
    domains = []
    if filepath.exists():
        with open(filepath, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    domains.append(line.lower())
    return domains


def load_category_domains(category: str, whitelist_dir: Path) -> set[str]:
    """Load existing domains from a category file."""
    category_file = whitelist_dir / f"{category}.txt"
    return set(load_domains(category_file))


def save_domains(filepath: Path, domains: set[str]) -> None:
    """Save domains to a file (sorted)."""
    sorted_domains = sorted(domains)
    with open(filepath, "w") as f:
        for domain in sorted_domains:
            f.write(f"{domain}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Organize whitelist into categories")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    whitelist_file = repo_root / "whitelist_domains.txt"
    whitelist_dir = repo_root / "lists/allow"

    print("Organizing whitelist into categories...\n")

    # Load all domains from whitelist_domains.txt
    all_domains = load_domains(whitelist_file)
    print(f"Loaded {len(all_domains)} domains from whitelist_domains.txt")

    # Also load domains from all existing category files
    for category in list(WHITELIST_CATEGORIES.keys()) + ["misc"]:
        category_file = whitelist_dir / f"{category}.txt"
        if category_file.exists():
            existing = load_domains(category_file)
            all_domains.extend(existing)
            print(f"  + {len(existing)} from {category}.txt")

    # Deduplicate
    all_domains = list(set(all_domains))
    print(f"\nTotal unique domains: {len(all_domains)}")

    # Categorize all domains
    categorized: dict[str, set[str]] = {cat: set() for cat in WHITELIST_CATEGORIES}
    categorized["misc"] = set()

    for domain in all_domains:
        category = categorize_domain(domain)
        categorized[category].add(domain)

    # Print results
    print("\nCategorization results:")
    for category, domains in sorted(categorized.items(), key=lambda x: -len(x[1])):
        if domains:
            print(f"  {category}: {len(domains)} domains")

    if args.dry_run:
        print("\n[DRY RUN] Would save to category files")
        return 0

    # Save to category files
    print("\nSaving to category files...")

    for category, domains in categorized.items():
        if domains:
            category_file = whitelist_dir / f"{category}.txt"
            save_domains(category_file, domains)
            print(f"  {category}.txt: {len(domains)} domains")

    # Update whitelist_domains.txt with deprecation notice
    with open(whitelist_file, "w") as f:
        f.write("# This file is deprecated. See lists/allow/ for categorized lists.\n")
        f.write(
            "# The whitelist is now organized into categories for easier maintenance.\n"
        )

    print(f"\nwhitelist_domains.txt: updated with deprecation notice")
    print("\nDone!")
    return 0


if __name__ == "__main__":
    exit(main())
