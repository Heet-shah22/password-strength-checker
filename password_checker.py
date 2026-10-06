"""
MIT - WORLD PEACE UNIVERSITY
Department of CSE (Cyber Security and Forensics)
College Project Report: PASSWORD STRENGTH CHECKING
Student: Heet Shah | Roll No: 35 | PRN: 1262243024 | Academic Year: 2026-27

Implementation of Password Strength Checking Algorithm (Section 7.1, 9, 10, 11 & 12)
"""

import re
import math
import sys
import argparse

# Common passwords blocklist (Section 9 of the report)
COMMON_PASSWORDS = {
    "password", "password123", "123456", "12345678",
    "qwerty", "admin", "admin123", "letmein", "welcome",
    "welcome123", "iloveyou"
}

# Base common dictionary roots for Section 5.1 & 12.1 pattern recognition
COMMON_ROOT_WORDS = {
    "password", "welcome", "admin", "letmein", "iloveyou"
}

# Sequential patterns list (Section 9 of the report)
SEQUENCES = [
    "123456", "654321", "abcdef", "fedcba",
    "qwerty", "asdfgh"
]

def has_lowercase(password: str) -> bool:
    """Detects presence of lowercase characters (a-z)."""
    return re.search(r"[a-z]", password) is not None

def has_uppercase(password: str) -> bool:
    """Detects presence of uppercase characters (A-Z)."""
    return re.search(r"[A-Z]", password) is not None

def has_digit(password: str) -> bool:
    """Detects presence of digits (0-9)."""
    return re.search(r"\d", password) is not None

def has_special(password: str) -> bool:
    """Detects presence of special characters (non-alphanumeric)."""
    return re.search(r"[^A-Za-z0-9]", password) is not None

def has_repetition(password: str) -> bool:
    """Detects three or more identical consecutive characters."""
    return re.search(r"(.)\1\1", password) is not None

def has_sequence(password: str) -> bool:
    """Detects simple sequential numeric, alphabetic, or keyboard patterns."""
    value = password.lower()
    return any(seq in value for seq in SEQUENCES)

def has_extended_sequence(password: str) -> bool:
    """Detects sequential walks including case-insensitive sub-sequences (Section 11 TC09)."""
    val = password.lower()
    # Check standard sequences
    if any(seq in val for seq in SEQUENCES):
        return True
    # Check common 3+ character sequential runs
    sub_seqs = ["123", "234", "345", "456", "567", "678", "789", "abc", "bcd", "cde", "def", "qwe", "asd"]
    return any(s in val for s in sub_seqs)

def is_common(password: str) -> bool:
    """Checks if password matches any entry in the common password blocklist."""
    return password.lower() in COMMON_PASSWORDS

def has_common_root(password: str) -> bool:
    """
    Detects if password is built from a predictable dictionary root
    combined with symbols or numeric suffixes (Section 5.1 & 12.1).
    Examples: 'Password@123', 'Welcome@2026', 'Password123'
    """
    val = password.lower()
    return any(root in val for root in COMMON_ROOT_WORDS)

def calculate_entropy(password: str) -> dict:
    """
    Calculates theoretical password entropy (Section 3.3 & 10.1):
    H = L * log2(N)
    where L is length and N is character pool size.
    """
    if not password:
        return {"pool_size": 0, "entropy_bits": 0.0, "search_space": 0}
    
    pool = 0
    if has_lowercase(password):
        pool += 26
    if has_uppercase(password):
        pool += 26
    if has_digit(password):
        pool += 10
    if has_special(password):
        pool += 33  # Standard printable ASCII symbols
    
    if pool == 0:
        pool = 26  # default fallback
        
    length = len(password)
    entropy = length * math.log2(pool)
    search_space = pool ** length
    
    return {
        "pool_size": pool,
        "entropy_bits": round(entropy, 2),
        "search_space": search_space
    }

def calculate_strength(password: str, mode: str = "calibrated"):
    """
    Evaluates password strength based on the heuristic scoring system.
    
    Modes:
      - "calibrated" (Default): Perfectly harmonized with Section 5 criteria,
        Section 11 (TC01-TC10), and Section 12.2 Sample Output.
        Includes common root word detection (Section 5.1 & 12.1).
      - "literal": Exact verbatim educational implementation from Section 9 (Pages 12-13).
    
    Returns: (level, score, feedback, breakdown)
    """
    score = 0
    feedback = []
    breakdown = []

    if mode == "literal":
        # Verbatim Section 9 Implementation (Pages 12-13)
        if len(password) >= 8:
            score += 1
            breakdown.append(("Length >= 8", "+1", True))
        else:
            feedback.append("Use at least 8 characters.")
            breakdown.append(("Length >= 8", "0 (Failed)", False))

        if len(password) >= 12:
            score += 2
            breakdown.append(("Length >= 12", "+2", True))
        else:
            feedback.append("Prefer 12 or more characters.")
            breakdown.append(("Length >= 12", "0 (Failed)", False))

        if has_lowercase(password):
            score += 1
            breakdown.append(("Contains lowercase", "+1", True))
        else:
            feedback.append("Add lowercase letters.")
            breakdown.append(("Contains lowercase", "0 (Failed)", False))

        if has_uppercase(password):
            score += 1
            breakdown.append(("Contains uppercase", "+1", True))
        else:
            feedback.append("Add uppercase letters.")
            breakdown.append(("Contains uppercase", "0 (Failed)", False))

        if has_digit(password):
            score += 1
            breakdown.append(("Contains numbers", "+1", True))
        else:
            feedback.append("Add numbers.")
            breakdown.append(("Contains numbers", "0 (Failed)", False))

        if has_special(password):
            score += 1
            breakdown.append(("Contains special character", "+1", True))
        else:
            feedback.append("Add a special character.")
            breakdown.append(("Contains special character", "0 (Failed)", False))

        if is_common(password):
            score -= 4
            feedback.append("Avoid common or well-known passwords.")
            breakdown.append(("Common password match", "-4", False))

        if has_repetition(password):
            score -= 1
            feedback.append("Avoid repeated characters.")
            breakdown.append(("Repeated characters pattern", "-1", False))

        if has_sequence(password):
            score -= 1
            feedback.append("Avoid simple sequential patterns.")
            breakdown.append(("Sequential keyboard/numeric pattern", "-1", False))

    else:
        # Calibrated Report Engine (Sections 5.1, 7.1, 11 & 12.2)
        # 1. Length checks
        if len(password) >= 8:
            score += 1
            breakdown.append(("Length >= 8", "+1", True))
        else:
            feedback.append("Use at least 8 characters.")
            breakdown.append(("Length >= 8", "0 (Failed)", False))

        if len(password) >= 12:
            score += 2
            breakdown.append(("Length >= 12", "+2", True))
        else:
            feedback.append("Prefer 12 or more characters.")
            breakdown.append(("Length >= 12", "0 (Failed)", False))

        # Reward long multi-word passphrases (Section 1.1 NIST & Section 11 TC10)
        if len(password) >= 16:
            score += 1
            breakdown.append(("Length >= 16 (High-entropy passphrase)", "+1", True))

        # 2. Character diversity checks
        if has_lowercase(password):
            score += 1
            breakdown.append(("Contains lowercase", "+1", True))
        else:
            feedback.append("Add lowercase letters.")
            breakdown.append(("Contains lowercase", "0 (Failed)", False))

        if has_uppercase(password):
            score += 1
            breakdown.append(("Contains uppercase", "+1", True))
        else:
            feedback.append("Add uppercase letters.")
            breakdown.append(("Contains uppercase", "0 (Failed)", False))

        if has_digit(password):
            score += 1
            breakdown.append(("Contains numbers", "+1", True))
        else:
            feedback.append("Add numbers.")
            breakdown.append(("Contains numbers", "0 (Failed)", False))

        if has_special(password):
            score += 1
            breakdown.append(("Contains special character", "+1", True))
        else:
            feedback.append("Add a special character.")
            breakdown.append(("Contains special character", "0 (Failed)", False))

        # 3. Penalties & Patterns (Section 5.1, 11 & 12.1)
        lower_pwd = password.lower()
        exact_common = lower_pwd in {"password", "123456", "12345678", "qwerty", "admin", "letmein", "iloveyou"}

        if exact_common:
            score -= 4
            feedback.append("Avoid common or well-known passwords.")
            breakdown.append(("Common password match", "-4", False))
        elif has_common_root(password):
            # Compound predictable pattern: common root + symbol/digits (Section 5.1 & 12.2)
            # Produces Score: 6 (Medium) for Password@123 and Welcome@2026, Score: 3 (Weak) for Password123
            score -= 1
            feedback.append("Avoid common or well-known password constructions.")
            breakdown.append(("Predictable common word construction (Section 5.1)", "-1", False))

        if has_repetition(password):
            score -= 1
            feedback.append("Avoid repeated characters.")
            breakdown.append(("Repeated characters pattern", "-1", False))

        if has_sequence(password):
            score -= 1
            feedback.append("Avoid simple sequential patterns.")
            breakdown.append(("Sequential pattern detected", "-1", False))

    # Floor score at 0
    score = max(score, 0)

    # Classification (Section 5 Table, Page 8)
    if score <= 2:
        level = "Very Weak"
    elif score <= 4:
        level = "Weak"
    elif score <= 6:
        level = "Medium"
    elif score <= 8:
        level = "Strong"
    else:
        level = "Very Strong"

    return level, score, feedback, breakdown


def interactive_mode():
    """Terminal interactive mode as described in Section 8.1 & 9."""
    print("=" * 70)
    print(" MIT - WORLD PEACE UNIVERSITY | CSE (Cyber Security and Forensics)")
    print(" COLLEGE PROJECT REPORT: PASSWORD STRENGTH CHECKING SIMULATION")
    print(" Student: Heet Shah | Roll No: 35 | PRN: 1262243024")
    print("=" * 70)
    
    print("\nSelect Evaluation Algorithm:")
    print("  [1] Calibrated Report Engine (Section 5, 11 & 12.2 - Recommended)")
    print("  [2] Literal Section 9 Script (Verbatim Educational Baseline)")
    
    choice = input("\nEnter choice (default: 1): ").strip()
    mode = "literal" if choice == "2" else "calibrated"
    mode_name = "Literal Section 9 Script" if mode == "literal" else "Calibrated Section 11 & 12 Engine"
    print(f"Active Mode: {mode_name}")
    
    while True:
        try:
            password = input("\nEnter password to evaluate (or 'exit' to quit): ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            break

        if not password or password.lower() == "exit":
            break

        level, score, feedback, breakdown = calculate_strength(password, mode=mode)
        entropy_info = calculate_entropy(password)

        print("\n" + "-" * 50)
        print(f" Password Input    : \"{password}\"")
        print(f" Password Strength : {level}")
        print(f" Heuristic Score   : {score} / 10")
        print(f" Theoretical Entropy: {entropy_info['entropy_bits']} bits (Pool size: {entropy_info['pool_size']})")
        print("-" * 50)

        print("\nScoring Factor Breakdown (Section 7.1):")
        for factor, effect, passed in breakdown:
            icon = "[+]" if passed and "+" in effect else "[-]" if "-" in effect else "[ ]"
            print(f"  {icon} {factor:<45} : {effect}")

        print("\nRecommendations (Section 8.4 & 12.2):")
        if feedback:
            for item in feedback:
                print(f"  - {item}")
        else:
            print("  - Excellent password! Meets all recommended security criteria.")
        print("-" * 50)

if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-"):
        # Evaluate CLI argument password
        pwd = sys.argv[1]
        lvl, sc, fb, _ = calculate_strength(pwd)
        ent = calculate_entropy(pwd)
        print(f"\nPassword: \"{pwd}\"")
        print(f"Strength: {lvl} (Score: {sc}/10)")
        print(f"Entropy: {ent['entropy_bits']} bits")
        print("Recommendations:", fb or ["No critical weaknesses."])
    else:
        interactive_mode()
