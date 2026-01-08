#!/usr/bin/env python3
"""
Organize blacklist_domains.txt into category-specific files.

Categorizes domains based on keywords and patterns, moving them to:
- kahf-custom-blacklist/gambling.txt
- kahf-custom-blacklist/adult.txt
- kahf-custom-blacklist/piracy.txt
- kahf-custom-blacklist/malware.txt
- kahf-custom-blacklist/social.txt
- kahf-custom-blacklist/dating.txt
- kahf-custom-blacklist/violence.txt

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
        "bet", "casino", "poker", "slot", "gambling", "lottery", "jackpot",
        "roulette", "blackjack", "bingo", "wager", "sportsbook",
        "1xbet", "mostbet", "melbet", "betwinner", "parimatch", "betway",
        "jeetwin", "jeetbuzz", "fairplay", "stake", "roobet", "linebet",
        "22bet", "10cric", "fun88", "dafabet", "betcity", "bettilt",
        "cloudbet", "nitrogen", "rainbet", "rolletto", "lvbet",
        "luckygames", "fairspin", "winbd", "babu88", "nagad88", "baji",
        "krikya", "crickex", "khela88", "mcw", "jaya9", "glory",
        "mega888", "918kiss", "r777", "tk999", "pbc88", "bigtaka",
    ],
    "adult": [
        "porn", "xxx", "sex", "nude", "erotic", "hentai", "nsfw",
        "xvideos", "xnxx", "xhamster", "pornhub", "redtube", "youporn",
        "brazzers", "blacked", "spankbang", "thumbzilla",
        "livejasmin", "chaturbate", "stripchat", "fap",
        "choti", "golpo", "desi", "mms", "masala", "maza",
        "aunty", "incest", "18up", "adult", "hotflix", "uncutmaza",
        "xmaal", "xmasti", "fsiblog", "indiansex", "desihub",
        "porno365", "fullxcinema", "analsex",
        "hanime", "hentaimoon", "ehentai", "pururin",
        "kissjav", "jav", "missav", "sextop", "sexmix",
        "arousr", "flingster", "chatville", "talkwithstranger",
        "bangsexting", "sextfriend", "nsfwchat", "juicychat",
        "seduced", "wifey", "crushon.ai", "herahaven",
        "civitai", "seaart", "pixai", "basedlabs", "betterwaifu",
        "deepfake", "ainudez", "xpicture", "xgenerator",
        "aagmaal", "masahub", "southfreak", "ullu", "webxseries",
        "primehub", "ottwebseries", "hiwebxseries", "hotullu",
    ],
    "piracy": [
        "torrent", "pirate", "warez", "crack", "keygen",
        "yomovies", "9xmovies", "filmywap", "movierulz",
        "pagalmovies", "moviesbaba", "vegamovies", "hdhub4u", "skymovieshd",
        "themoviesflix", "mkvcinemas", "mlsbd", "mlwbd", "movielinkbd",
        "ctgmovies", "flixbd", "fmxbd", "subsbd", "movibd", "dooflix",
        "sflix", "123movies", "fmovies", "putlocker",
        "watchomovies", "streamingcommunity", "vivamax",
        "h33t", "1337x", "rarbg", "kickass", "thepiratebay",
        "mangadex", "mangapark", "manhua", "manhwa", "bato",
        "wattpad", "webnovel", "chereads",
        "gdtot", "bunkr",
    ],
    "malware": [
        "phish", "malware", "virus", "trojan", "ransomware",
        "grabify", "iplogger", "webhook",
        "proxyium", "netmirror", "iosmirror",
    ],
    "social": [
        # Specific problematic social platforms
        "9gag.com", "vk.com",
    ],
    "dating": [
        "dating", "match", "tinder", "bumble", "hinge",
        "secondwife", "antiland",
    ],
    "violence": [
        "gore", "violence", "bestgore", "liveleak",
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
    category_file = script_dir.parent / "kahf-custom-blacklist" / f"{category}.txt"
    return set(load_domains(category_file))


def save_domains(filepath: Path, domains: set[str], header: str = "") -> None:
    """Save domains to a file (sorted)."""
    sorted_domains = sorted(domains)
    with open(filepath, "w") as f:
        if header:
            f.write(f"{header}\n")
        for domain in sorted_domains:
            f.write(f"{domain}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description="Organize blacklist into categories")
    parser.add_argument("--dry-run", action="store_true", help="Preview without saving")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    repo_root = script_dir.parent
    blacklist_file = repo_root / "blacklist_domains.txt"

    print("Organizing blacklist_domains.txt into categories...\n")

    # Load all domains
    all_domains = load_domains(blacklist_file)
    print(f"Loaded {len(all_domains)} domains from blacklist_domains.txt\n")

    # Categorize
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

    for domain in all_domains:
        category = categorize_domain(domain)
        categorized[category].add(domain)

    # Print results
    print("Categorization results:")
    for category, domains in categorized.items():
        print(f"  {category}: {len(domains)} domains")

    if args.dry_run:
        print("\n[DRY RUN] Would move domains to category files")
        return 0

    # Merge with existing and save
    print("\nMerging and saving...")

    for category in ["gambling", "adult", "piracy", "malware", "social", "dating", "violence"]:
        existing = load_category_domains(category)
        merged = existing | categorized[category]
        category_file = repo_root / "kahf-custom-blacklist" / f"{category}.txt"
        save_domains(category_file, merged)
        print(f"  {category}.txt: {len(existing)} + {len(categorized[category])} = {len(merged)}")

    # Save misc back to blacklist_domains.txt
    header = "# KahfGuard Misc Blacklist\n# Anti-Islamic, ex-Muslim, LGBT, and other user-reported sites\n#"
    save_domains(blacklist_file, categorized["misc"], header)
    print(f"  blacklist_domains.txt: {len(categorized['misc'])} domains")

    print("\nDone!")
    return 0


if __name__ == "__main__":
    exit(main())
