#!/usr/bin/env python3
"""
Organize blacklist_domains.txt into category-specific files.

Categorizes domains based on keywords and patterns, moving them to:
- lists/block/gambling.txt
- lists/block/adult.txt
- lists/block/piracy.txt
- lists/block/malware.txt
- lists/block/social.txt
- lists/block/dating.txt
- lists/block/violence.txt

Remaining domains stay in blacklist_domains.txt (misc category).

Usage:
    python organize_blacklist.py              # Organize and save
    python organize_blacklist.py --dry-run    # Preview without saving
"""

import argparse
from pathlib import Path

# Category keyword patterns
CATEGORY_PATTERNS: dict[str, list[str]] = {
    "gambling": [
        "bet",
        "casino",
        "poker",
        "slot",
        "gambling",
        "lottery",
        "jackpot",
        "roulette",
        "blackjack",
        "bingo",
        "wager",
        "sportsbook",
        "1xbet",
        "mostbet",
        "melbet",
        "betwinner",
        "parimatch",
        "betway",
        "jeetwin",
        "jeetbuzz",
        "fairplay",
        "stake",
        "roobet",
        "linebet",
        "22bet",
        "10cric",
        "fun88",
        "dafabet",
        "betcity",
        "bettilt",
        "cloudbet",
        "nitrogen",
        "rainbet",
        "rolletto",
        "lvbet",
        "luckygames",
        "fairspin",
        "winbd",
        "babu88",
        "nagad88",
        "baji",
        "krikya",
        "crickex",
        "khela88",
        "mcw",
        "jaya9",
        "glory",
        "mega888",
        "918kiss",
        "r777",
        "tk999",
        "pbc88",
        "bigtaka",
    ],
    "adult": [
        "porn",
        "xxx",
        "sex",
        "nude",
        "erotic",
        "hentai",
        "nsfw",
        "xvideos",
        "xnxx",
        "xhamster",
        "pornhub",
        "redtube",
        "youporn",
        "brazzers",
        "blacked",
        "spankbang",
        "thumbzilla",
        "livejasmin",
        "chaturbate",
        "stripchat",
        "fap",
        "choti",
        "golpo",
        "desi",
        "mms",
        "masala",
        "maza",
        "aunty",
        "incest",
        "18up",
        "adult",
        "hotflix",
        "uncutmaza",
        "xmaal",
        "xmasti",
        "fsiblog",
        "indiansex",
        "desihub",
        "porno365",
        "fullxcinema",
        "analsex",
        "hanime",
        "hentaimoon",
        "ehentai",
        "pururin",
        "kissjav",
        "jav",
        "missav",
        "sextop",
        "sexmix",
        "arousr",
        "flingster",
        "chatville",
        "talkwithstranger",
        "bangsexting",
        "sextfriend",
        "nsfwchat",
        "juicychat",
        "seduced",
        "wifey",
        "crushon.ai",
        "herahaven",
        "civitai",
        "seaart",
        "pixai",
        "basedlabs",
        "betterwaifu",
        "deepfake",
        "ainudez",
        "xpicture",
        "xgenerator",
        "aagmaal",
        "masahub",
        "southfreak",
        "ullu",
        "webxseries",
        "primehub",
        "ottwebseries",
        "hiwebxseries",
        "hotullu",
    ],
    "piracy": [
        "torrent",
        "pirate",
        "warez",
        "crack",
        "keygen",
        "yomovies",
        "9xmovies",
        "filmywap",
        "movierulz",
        "pagalmovies",
        "moviesbaba",
        "vegamovies",
        "hdhub4u",
        "skymovieshd",
        "themoviesflix",
        "mkvcinemas",
        "mlsbd",
        "mlwbd",
        "movielinkbd",
        "ctgmovies",
        "flixbd",
        "fmxbd",
        "subsbd",
        "movibd",
        "dooflix",
        "sflix",
        "123movies",
        "fmovies",
        "putlocker",
        "watchomovies",
        "streamingcommunity",
        "vivamax",
        "h33t",
        "1337x",
        "rarbg",
        "kickass",
        "thepiratebay",
        "mangadex",
        "mangapark",
        "manhua",
        "manhwa",
        "bato",
        "wattpad",
        "webnovel",
        "chereads",
        "gdtot",
        "bunkr",
    ],
    "malware": [
        "phish",
        "malware",
        "virus",
        "trojan",
        "ransomware",
        "grabify",
        "iplogger",
        "webhook",
        "proxyium",
        "netmirror",
        "iosmirror",
    ],
    "social": [
        # Specific problematic social platforms
        "9gag.com",
        "vk.com",
    ],
    "dating": [
        "dating",
        "match",
        "tinder",
        "bumble",
        "hinge",
        "secondwife",
        "antiland",
    ],
    "violence": [
        "gore",
        "violence",
        "bestgore",
        "liveleak",
    ],
}


def categorize_domain(domain: str) -> str:
    """Determine the category for a domain."""
    domain_lower = domain.lower()

    for category, keywords in CATEGORY_PATTERNS.items():
        for keyword in keywords:
            if keyword in domain_lower:
                return category

    # Default: misc (stays in blacklist_domains.txt)
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


def load_category_domains(category: str) -> set[str]:
    """Load existing domains from a category file."""
    script_dir = Path(__file__).parent
    category_file = script_dir.parent / "lists/block" / f"{category}.txt"
    return set(load_domains(category_file))


def save_domains(filepath: Path, domains: set[str], header: str = "") -> None:
    """Save domains to a file (sorted)."""
    sorted_domains = sorted(domains)
    with open(filepath, "w") as f:
        if header:
            f.write(f"{header}\n")
        for domain in sorted_domains:
            f.write(f"{domain}\n")


def load_all_existing_domains(blacklist_dir: Path) -> set[str]:
    """Load all existing domains from all category files."""
    all_existing: set[str] = set()
    categories = [
        "gambling",
        "adult",
        "piracy",
        "malware",
        "social",
        "dating",
        "violence",
        "anti-islamic",
        "lgbt",
    ]

    for category in categories:
        category_file = blacklist_dir / f"{category}.txt"
        if category_file.exists():
            all_existing.update(load_domains(category_file))

    return all_existing


def main() -> int:
    parser = argparse.ArgumentParser(description="Organize blacklist into categories")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    blacklist_file = repo_root / "blacklist_domains.txt"
    blacklist_dir = repo_root / "lists/block"

    print("Organizing blacklist_domains.txt into categories...\n")

    # Load all existing domains from all category files first
    print("Loading existing domains from all category files...")
    all_existing = load_all_existing_domains(blacklist_dir)
    print(f"Found {len(all_existing)} existing domains across all categories")

    # Load domains from blacklist_domains.txt
    all_domains = load_domains(blacklist_file)
    print(f"Loaded {len(all_domains)} domains from blacklist_domains.txt")

    # Filter out domains that already exist in any category
    new_domains = [d for d in all_domains if d not in all_existing]
    print(f"New domains (not in any category): {len(new_domains)}\n")

    if not new_domains:
        print(
            "No new domains to categorize. All domains already exist in category files."
        )
        return 0

    # Categorize only NEW domains
    categorized: dict[str, set[str]] = {
        "gambling": set(),
        "adult": set(),
        "piracy": set(),
        "malware": set(),
        "social": set(),
        "dating": set(),
        "violence": set(),
        "misc": set(),
    }

    for domain in new_domains:
        category = categorize_domain(domain)
        categorized[category].add(domain)

    # Print results
    print("New domains by category:")
    for category, domains in categorized.items():
        if domains:
            print(f"  {category}: +{len(domains)} new")

    if args.dry_run:
        print("\n[DRY RUN] Would add domains to category files")
        return 0

    # Merge with existing and save
    print("\nAdding new domains to category files...")

    for category in [
        "gambling",
        "adult",
        "piracy",
        "malware",
        "social",
        "dating",
        "violence",
    ]:
        if not categorized[category]:
            continue
        existing = load_category_domains(category)
        merged = existing | categorized[category]
        category_file = repo_root / "lists/block" / f"{category}.txt"
        save_domains(category_file, merged)
        print(
            f"  {category}.txt: {len(existing)} + {len(categorized[category])} = {len(merged)}"
        )

    # Save misc back to blacklist_domains.txt (only if there are new misc domains)
    if categorized["misc"]:
        existing_misc = set(load_domains(blacklist_file))
        merged_misc = existing_misc | categorized["misc"]
        header = "# KahfGuard Misc Blacklist\n# Anti-Islamic, ex-Muslim, LGBT, and other user-reported sites\n#"
        save_domains(blacklist_file, merged_misc, header)
        print(
            f"  blacklist_domains.txt: {len(existing_misc)} + {len(categorized['misc'])} = {len(merged_misc)}"
        )

    print("\nDone!")
    return 0


if __name__ == "__main__":
    exit(main())
