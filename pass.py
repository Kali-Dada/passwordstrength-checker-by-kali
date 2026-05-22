#!/usr/bin/env python3
"""
PassGuard — Python Password Strength Analyzer
A command-line cybersecurity tool for analyzing and generating passwords.
100% standard library — no pip installs required.

Usage:
    python password_checker.py                  # Interactive mode
    python password_checker.py -p "MyPass123!"  # Analyze a specific password
    python password_checker.py -g               # Generate a strong password
    python password_checker.py -g --length 20   # Generate with custom length
"""

import re
import math
import secrets
import string
import argparse
import getpass
import sys

# ── ANSI Colors (auto-disabled on Windows if not supported) ───────────────────
class C:
    RESET   = "\033[0m"
    BOLD    = "\033[1m"
    RED     = "\033[91m"
    ORANGE  = "\033[38;5;208m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    MUTED   = "\033[90m"
    WHITE   = "\033[97m"

    @staticmethod
    def disable():
        for attr in ['RESET','BOLD','RED','ORANGE','YELLOW','GREEN','CYAN','MUTED','WHITE']:
            setattr(C, attr, '')

# Disable colors on Windows without ANSI support
if sys.platform == "win32":
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        kernel32.SetConsoleMode(kernel32.GetStdHandle(-11), 7)
    except Exception:
        C.disable()


# ── Common password patterns ──────────────────────────────────────────────────
COMMON_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in [
        r'^password', r'^12345', r'^qwerty', r'^abc123', r'^letmein',
        r'^welcome', r'^monkey', r'^dragon', r'^master', r'^admin',
        r'^iloveyou', r'^sunshine', r'^princess', r'^football',
        r'^shadow', r'^superman', r'^michael', r'^charlie',
        r'^batman', r'^trustno1', r'^pass\d+', r'^test\d*',
        r'^guest', r'^login', r'^user\d*',
    ]
]

SEQUENTIAL_RE = re.compile(
    r'(.)\1{2,}|'
    r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|'
    r'pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz|012|123|234|345|456|567|'
    r'678|789|890|qwe|wer|ert|rty|tyu|yui|uio|iop|asd|sdf|dfg|fgh|'
    r'ghj|hjk|jkl|zxc|xcv|cvb|vbn|nbm)',
    re.IGNORECASE
)


# ── Analysis Functions ────────────────────────────────────────────────────────

def get_charset_size(pwd: str) -> int:
    """Return the effective character set size used in the password."""
    size = 0
    if re.search(r'[a-z]', pwd): size += 26
    if re.search(r'[A-Z]', pwd): size += 26
    if re.search(r'\d', pwd):    size += 10
    if re.search(r'[^a-zA-Z0-9]', pwd): size += 32
    return size


def calc_entropy(pwd: str) -> float:
    """Calculate password entropy in bits."""
    cs = get_charset_size(pwd)
    if cs == 0 or not pwd:
        return 0.0
    return len(pwd) * math.log2(cs)


def estimate_crack_time(entropy: float) -> str:
    """
    Estimate crack time assuming 10 billion guesses/second (GPU cluster).
    Returns a human-readable string.
    """
    if entropy == 0:
        return "instant"
    guesses = 2 ** entropy
    seconds = guesses / 1e10

    if seconds < 1:           return "< 1 second"
    if seconds < 60:          return f"{seconds:.0f} seconds"
    if seconds < 3600:        return f"{seconds/60:.0f} minutes"
    if seconds < 86400:       return f"{seconds/3600:.0f} hours"
    if seconds < 2_592_000:   return f"{seconds/86400:.0f} days"
    if seconds < 31_536_000:  return f"{seconds/2_592_000:.0f} months"
    if seconds < 3.15e9:      return f"{seconds/31_536_000:.0f} years"
    if seconds < 3.15e12:     return f"{seconds/3.15e9:.1f} thousand years"
    if seconds < 3.15e15:     return f"{seconds/3.15e12:.1f} million years"
    return "longer than the age of the universe"


def score_password(pwd: str) -> dict:
    """
    Score a password from 0–100 and return full analysis.

    Returns a dict with:
        score    (int 0–100)
        level    (str: critical/weak/fair/strong/fortress)
        criteria (dict of bool checks)
        threats  (list of str warnings)
        entropy  (float bits)
        charset  (int)
    """
    if not pwd:
        return dict(score=0, level=None, criteria={}, threats=[], entropy=0.0, charset=0)

    criteria = {
        "length_12":  len(pwd) >= 12,
        "uppercase":  bool(re.search(r'[A-Z]', pwd)),
        "lowercase":  bool(re.search(r'[a-z]', pwd)),
        "digits":     bool(re.search(r'\d', pwd)),
        "special":    bool(re.search(r'[^a-zA-Z0-9]', pwd)),
        "no_repeat":  not bool(SEQUENTIAL_RE.search(pwd)),
        "no_common":  not any(p.search(pwd) for p in COMMON_PATTERNS),
    }

    entropy = calc_entropy(pwd)
    charset = get_charset_size(pwd)
    threats = []

    # Base score from entropy
    score = min(entropy * 1.2, 60)

    # Diversity bonus
    type_count = sum([
        criteria["uppercase"], criteria["lowercase"],
        criteria["digits"],    criteria["special"],
    ])
    score += type_count * 6

    # Length bonuses
    if len(pwd) >= 8:  score += 5
    if len(pwd) >= 12: score += 8
    if len(pwd) >= 20: score += 10

    # Penalties + threats
    if not criteria["no_repeat"]:
        score -= 20
        threats.append("Repeating or sequential characters detected (e.g. 'aaa', '123')")
    if not criteria["no_common"]:
        score -= 30
        threats.append("Matches a commonly used password pattern")
    if len(pwd) < 8:
        score -= 25
        threats.append("Critically short password (< 8 characters)")
    if type_count == 1:
        score -= 15
        threats.append("Only one character type — extremely predictable")
    elif type_count == 2:
        score -= 5

    if not criteria["special"]:
        threats.append("No special characters — significantly reduces search space")
    if not criteria["uppercase"]:
        threats.append("No uppercase letters — character set reduced")
    if not criteria["digits"]:
        threats.append("No digits — character set reduced")
    if len(pwd) < 12:
        threats.append(f"Length {len(pwd)} — minimum recommended is 12")
    if re.match(r'^[a-zA-Z]+\d{1,3}$', pwd):
        threats.append("Trailing digits on a word is a predictable pattern (e.g. 'monkey99')")

    score = max(0, min(100, round(score)))

    if   score < 20: level = "critical"
    elif score < 40: level = "weak"
    elif score < 60: level = "fair"
    elif score < 80: level = "strong"
    else:            level = "fortress"

    return dict(
        score=score, level=level,
        criteria=criteria, threats=list(dict.fromkeys(threats)),  # deduplicate
        entropy=entropy, charset=charset,
    )


# ── Password Generator ────────────────────────────────────────────────────────

def generate_password(length: int = 18) -> str:
    """
    Generate a cryptographically secure password using secrets module.
    Guarantees all 4 character types are present.
    """
    if length < 8:
        raise ValueError("Password length must be at least 8.")

    upper   = string.ascii_uppercase.replace('O', '').replace('I', '')
    lower   = string.ascii_lowercase.replace('l', '').replace('o', '')
    digits  = '23456789'
    special = '!@#$%^&*-_+=?'
    pool    = upper + lower + digits + special

    # Guarantee at least one from each category
    pwd = [
        secrets.choice(upper),
        secrets.choice(lower),
        secrets.choice(digits),
        secrets.choice(special),
    ]
    pwd += [secrets.choice(pool) for _ in range(length - 4)]

    # Shuffle in-place using secrets-based index
    for i in range(len(pwd) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        pwd[i], pwd[j] = pwd[j], pwd[i]

    return ''.join(pwd)


# ── Display Helpers ───────────────────────────────────────────────────────────

LEVEL_COLORS = {
    "critical": C.RED,
    "weak":     C.ORANGE,
    "fair":     C.YELLOW,
    "strong":   C.GREEN,
    "fortress": C.CYAN,
}

LEVEL_LABELS = {
    "critical": "CRITICAL",
    "weak":     "WEAK",
    "fair":     "FAIR",
    "strong":   "STRONG",
    "fortress": "FORTRESS ★",
}

BAR_WIDTH = 40

def render_bar(score: int, level: str) -> str:
    filled = round(score / 100 * BAR_WIDTH)
    color  = LEVEL_COLORS.get(level, C.MUTED)
    bar    = color + "█" * filled + C.MUTED + "░" * (BAR_WIDTH - filled) + C.RESET
    return f"[{bar}] {score}/100"


CRITERIA_LABELS = {
    "length_12": "Minimum 12 characters",
    "uppercase": "Uppercase letters (A–Z)",
    "lowercase": "Lowercase letters (a–z)",
    "digits":    "Numeric digits (0–9)",
    "special":   "Special characters (!@#$…)",
    "no_repeat": "No repeating/sequential sequences",
    "no_common": "Not a common password pattern",
}


def print_report(result: dict, pwd: str) -> None:
    """Print a full terminal report for the analyzed password."""
    level  = result["level"]
    score  = result["score"]
    color  = LEVEL_COLORS.get(level, C.MUTED)
    label  = LEVEL_LABELS.get(level, "—")

    print()
    print(f"{C.BOLD}{C.WHITE}{'─'*54}{C.RESET}")
    print(f"  {C.BOLD}⬡ PASSGUARD — Password Analysis Report{C.RESET}")
    print(f"{'─'*54}")

    # Strength
    print(f"\n  {C.MUTED}STRENGTH INDEX{C.RESET}")
    print(f"  {render_bar(score, level)}")
    print(f"  Status : {color}{C.BOLD}{label}{C.RESET}")

    # Stats
    entropy    = result["entropy"]
    crack_time = estimate_crack_time(entropy)
    charset    = result["charset"]

    print(f"\n  {C.MUTED}STATISTICS{C.RESET}")
    print(f"  {'Length':<16} {C.WHITE}{len(pwd)}{C.RESET}")
    print(f"  {'Entropy':<16} {C.WHITE}{entropy:.1f} bits{C.RESET}")
    print(f"  {'Charset size':<16} {C.WHITE}{charset}{C.RESET}")
    print(f"  {'Crack time':<16} {C.WHITE}{crack_time}{C.RESET}")
    print(f"  {C.MUTED}(Assumes 10 billion guesses/sec GPU attack){C.RESET}")

    # Criteria
    print(f"\n  {C.MUTED}SECURITY CRITERIA{C.RESET}")
    for key, label_text in CRITERIA_LABELS.items():
        passed = result["criteria"].get(key, False)
        icon   = f"{C.GREEN}✔{C.RESET}" if passed else f"{C.RED}✖{C.RESET}"
        print(f"  {icon}  {label_text}")

    # Threats
    threats = result["threats"]
    print(f"\n  {C.MUTED}THREAT ANALYSIS{C.RESET}")
    if not threats:
        print(f"  {C.GREEN}✔  No significant threats detected.{C.RESET}")
    else:
        for t in threats:
            print(f"  {C.ORANGE}⚠  {t}{C.RESET}")

    print(f"\n{'─'*54}\n")


def print_generated(pwd: str) -> None:
    """Print a generated password with its analysis."""
    print(f"\n  {C.MUTED}GENERATED PASSWORD{C.RESET}")
    print(f"  {C.BOLD}{C.GREEN}{pwd}{C.RESET}")
    result = score_password(pwd)
    print_report(result, pwd)


# ── CLI Entry Point ───────────────────────────────────────────────────────────

def interactive_mode() -> None:
    """Loop: prompt user, analyze, repeat until Ctrl+C / empty input."""
    print(f"\n{C.BOLD}{C.GREEN}  ⬡ PassGuard — Interactive Mode{C.RESET}")
    print(f"  {C.MUTED}Type a password to analyze, or press Enter to quit.{C.RESET}\n")

    while True:
        try:
            # Use getpass to hide input by default
            pwd = getpass.getpass(f"  {C.MUTED}Password (hidden): {C.RESET}")
        except (KeyboardInterrupt, EOFError):
            print(f"\n  {C.MUTED}Exiting PassGuard. Stay secure! 🔐{C.RESET}\n")
            break

        if not pwd:
            print(f"\n  {C.MUTED}Exiting PassGuard. Stay secure! 🔐{C.RESET}\n")
            break

        result = score_password(pwd)
        print_report(result, pwd)

        again = input(f"  Analyze another? [Y/n]: ").strip().lower()
        if again in ('n', 'no', 'q', 'quit'):
            print(f"\n  {C.MUTED}Exiting. Stay secure! 🔐{C.RESET}\n")
            break


def main() -> None:
    parser = argparse.ArgumentParser(
        description="PassGuard — Password Strength Analyzer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python password_checker.py                    Interactive mode (hidden input)
  python password_checker.py -p "MyPass123!"    Analyze a specific password
  python password_checker.py -g                 Generate a strong password
  python password_checker.py -g --length 24     Generate with custom length
        """
    )
    parser.add_argument('-p', '--password', type=str,
                        help='Password to analyze (use quotes if it has spaces)')
    parser.add_argument('-g', '--generate', action='store_true',
                        help='Generate a cryptographically strong password')
    parser.add_argument('--length', type=int, default=18,
                        help='Length for generated password (default: 18)')
    parser.add_argument('--no-color', action='store_true',
                        help='Disable colored output')

    args = parser.parse_args()

    if args.no_color:
        C.disable()

    if args.generate:
        pwd = generate_password(args.length)
        print_generated(pwd)

    elif args.password:
        result = score_password(args.password)
        print_report(result, args.password)

    else:
        interactive_mode()


if __name__ == "__main__":
    main()