"""
Data Extraction & Secure Validation Assignment
Author: Mathiang Mathew

This program reads a raw text export of campus WiFi-credit support mentions
(as if pulled from a community-monitoring API covering an internal support
app and a student WhatsApp group), pulls out four types of structured data
(emails, credit card numbers, hashtags, currency amounts), and validates
each one — both for correct format AND for signs of malicious content.

Design approach: two stages per data type.
  1. EXTRACT — a loose regex finds anything that looks like a candidate.
  2. VALIDATE — a stricter Python check decides if that candidate is
     actually well-formed / trustworthy.
Keeping these separate makes each stage easy to reason about and test,
instead of writing one giant regex that tries to do both jobs at once.
"""

import re
import os
import json
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Step 1: Split the raw text into individual "tickets".
# Each ticket in our export starts with a header line like:
#   Ticket #4504 | Category: Insurance Payment | Status: Open | Requester: Aisha Bello <a.bello@alueducation.com> | Submitted: 2026-08-12 18:10
# Everything after that line, up to the next "Ticket #" header (or end of
# file), is that ticket's description text.
# ---------------------------------------------------------------------------

TICKET_HEADER_RE = re.compile(
    r"Ticket #(?P<num>\d+)\s*\|\s*Category:\s*(?P<category>[^|]+?)\s*\|\s*"
    r"Status:\s*(?P<status>[^|]+?)\s*\|\s*Requester:\s*(?P<requester>[^|]+?)\s*\|\s*"
    r"Submitted:\s*(?P<submitted_at>[^\n]+)"
)


def parse_tickets(raw_text):
    """Split the raw export into a list of ticket dicts (number, category,
    status, requester, submitted_at, body)."""
    headers = list(TICKET_HEADER_RE.finditer(raw_text))
    tickets = []
    for i, match in enumerate(headers):
        body_start = match.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(raw_text)
        body = raw_text[body_start:body_end].strip()
        tickets.append({
            "ticket_number": int(match.group("num")),
            "category": match.group("category").strip(),
            "status": match.group("status").strip(),
            "requester": match.group("requester").strip(),
            "submitted_at": match.group("submitted_at").strip(),
            "body": body,
        })
    return tickets


# ---------------------------------------------------------------------------
# Step 2: Malicious content scanner.
# This runs BEFORE we try to extract anything useful from a post. If a post
# contains one of these known attack patterns, we quarantine the whole post
# instead of processing its contents as normal data.
# ---------------------------------------------------------------------------

MALICIOUS_PATTERNS = {
    "script_tag": re.compile(r"<\s*script\b", re.IGNORECASE),
    "js_event_handler": re.compile(r"\bon\w+\s*=\s*['\"]", re.IGNORECASE),
    "javascript_uri": re.compile(r"javascript\s*:", re.IGNORECASE),
    "sql_injection": re.compile(
        r"(;\s*--)|(\bDROP\s+TABLE\b)|(\bUNION\s+SELECT\b)|('\s*OR\s*'?1'?\s*=\s*'?1)",
        re.IGNORECASE,
    ),
}


def scan_for_malicious_content(text):
    """Return a list of the pattern names that matched in this text.
    An empty list means nothing suspicious was found."""
    return [label for label, pattern in MALICIOUS_PATTERNS.items() if pattern.search(text)]


# ---------------------------------------------------------------------------
# Step 3: Email addresses.
# ---------------------------------------------------------------------------

EMAIL_CANDIDATE_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}"
)


def validate_email(email):
    """Format-valid regex match isn't the whole story — this catches things
    a loose regex would let through, like consecutive dots."""
    if ".." in email:
        return False
    local, _, domain = email.partition("@")
    if not local or local.startswith(".") or local.endswith("."):
        return False
    if not domain or domain.startswith(".") or domain.startswith("-"):
        return False
    if len(email) > 254:
        return False
    return True


# ---------------------------------------------------------------------------
# Step 3b: ALU-specific domain validation.
#
# Security consideration: we deliberately use an EXACT suffix match
# (str.endswith) here rather than a substring check like
# `"alueducation.com" in email`. A substring check would be fooled by a
# classic phishing trick — burying the real, trusted domain earlier inside
# a longer, attacker-controlled domain, e.g.
#   noreply@alueducation.com.verify-now.net
# That string DOES contain "alueducation.com", but it is not an ALU
# address — the actual domain is "verify-now.net". endswith() only
# accepts it if the email genuinely terminates in one of our three real
# ALU domains.
#
# Order also matters: alumni.alueducation.com and si.alueducation.com are
# subdomains of alueducation.com, so we check the more specific ones
# first. In practice this isn't strictly required for correctness here
# (a subdomain address never ends with the bare "@alueducation.com"
# suffix either, since the character right before "alueducation.com"
# would be "." not "@"), but checking specific-to-general is still the
# clearer and safer habit as more subdomains get added later.
# ---------------------------------------------------------------------------

ALU_DOMAIN_CORE = "alueducation.com"
ALU_OFFICIAL_SUFFIX = "@alueducation.com"
ALU_ALUMNI_SUFFIX = "@alumni.alueducation.com"
ALU_SI_SUFFIX = "@si.alueducation.com"


def classify_alu_email(email):
    """Return 'official', 'alumni', 'si', or None. Being in one of these
    categories does NOT by itself mean the email is trustworthy — it must
    also pass validate_email(). A syntactically broken address can still
    happen to end in the right suffix."""
    lower = email.lower()
    if lower.endswith(ALU_ALUMNI_SUFFIX):
        return "alumni"
    if lower.endswith(ALU_SI_SUFFIX):
        return "si"
    if lower.endswith(ALU_OFFICIAL_SUFFIX):
        return "official"
    return None


def is_alu_domain_lookalike(email):
    """Flags the domain-padding phishing trick described above: the ALU
    domain string appears somewhere in the email, but it does NOT end
    with one of the three real ALU suffixes. This is a best-effort check,
    not a complete defense — it will NOT catch character-substitution
    typosquats (e.g. 'alu-education.com' or 'aIueducation.com' with a
    capital I). Catching those reliably needs fuzzy string matching
    (e.g. Levenshtein distance), which is outside the scope of a
    regex-based assignment, but is worth naming as a real gap."""
    lower = email.lower()
    if classify_alu_email(lower):
        return False
    return ALU_DOMAIN_CORE in lower


def mask_email(email):
    """Security consideration: an email's local part (the bit before the
    @) is personally identifying, so — same principle as the credit card
    masking below — we never write the full address to output or logs.
    The domain is kept visible because it's what makes the ALU-category
    reporting above actually useful to read."""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


# ---------------------------------------------------------------------------
# Step 4: Credit card numbers.
# We support the two most common real-world layouts:
#   - 16 digits in four groups of four   (Visa / Mastercard / Discover)
#   - 15 digits in a 4-6-5 grouping      (American Express)
# separated by spaces, dashes, or nothing at all.
# ---------------------------------------------------------------------------

CARD_CANDIDATE_RE = re.compile(
    r"\b(?:\d{4}[ -]?\d{6}[ -]?\d{5}|\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b"
)


def luhn_check(digits):
    """The Luhn algorithm — the same checksum banks use to catch typos and
    made-up card numbers. Double every second digit from the right; if a
    doubled digit goes over 9, subtract 9 from it; sum everything up; a
    real card number's sum is always divisible by 10."""
    total = 0
    for i, ch in enumerate(reversed(digits)):
        d = int(ch)
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def validate_credit_card(raw):
    """Strip separators, check the digit count is a real card length, then
    run Luhn. Format-valid does NOT mean the number is real."""
    digits = re.sub(r"[ -]", "", raw)
    if len(digits) not in (15, 16):
        return False
    return luhn_check(digits)


def mask_credit_card(raw):
    """Never output a full card number, even a valid one — mask everything
    except the last 4 digits, the same way a receipt would."""
    digits = re.sub(r"[ -]", "", raw)
    return "*" * (len(digits) - 4) + digits[-4:]


# ---------------------------------------------------------------------------
# Step 5: Hashtags.
# A basic word-character match already mirrors real platform behaviour: a
# dash breaks a hashtag on Twitter/Instagram too, so "#no-dashes-allowed"
# naturally extracts as just "#no". Validation adds the business rule on
# top: a sensible length, and not just a string of digits.
# ---------------------------------------------------------------------------

HASHTAG_CANDIDATE_RE = re.compile(r"#\w+")


def validate_hashtag(tag):
    body = tag[1:]  # strip the leading '#'
    if not (2 <= len(body) <= 30):
        return False
    if body.isdigit():
        return False
    return True


# ---------------------------------------------------------------------------
# Step 6: Currency amounts.
# Extraction is deliberately loose here too — it grabs a symbol/code plus
# any run of digits/commas/dots, even a malformed one like "49..99".
# Handles both orderings people actually use: a symbol or code BEFORE the
# number ("$15.00", "RWF 500..00") and a currency code AFTER the number
# ("500 RWF"), which is the more natural way many local amounts get typed.
# Validation then enforces the real rule: correct thousand-comma grouping
# and at most a 2-digit decimal.
# ---------------------------------------------------------------------------

CURRENCY_CANDIDATE_RE = re.compile(
    r"(?:[$£€]\s?\d(?:[\d,.]*\d)?)"
    r"|(?:\b(?:USD|KES|UGX|GBP|EUR|RWF)\s?\d(?:[\d,.]*\d)?)"
    r"|(?:\b\d(?:[\d,.]*\d)?\s?(?:RWF|USD|KES|UGX|GBP|EUR)\b)"
)

CURRENCY_PREFIX_RE = re.compile(r"^([$£€]|USD|KES|UGX|GBP|EUR|RWF)\s?(.+)$")
CURRENCY_SUFFIX_RE = re.compile(r"^(.+?)\s?(USD|KES|UGX|GBP|EUR|RWF)$")
CURRENCY_AMOUNT_RE = re.compile(r"^(\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{2})?$")


def validate_currency(raw):
    prefix_match = CURRENCY_PREFIX_RE.match(raw)
    if prefix_match:
        return bool(CURRENCY_AMOUNT_RE.match(prefix_match.group(2)))
    suffix_match = CURRENCY_SUFFIX_RE.match(raw)
    if suffix_match:
        return bool(CURRENCY_AMOUNT_RE.match(suffix_match.group(1)))
    return False


# ---------------------------------------------------------------------------
# Step 6b: Structural-anomaly detection (header-injection defense).
#
# Security consideration: parse_posts() finds "Post #N | Platform: ... |
# Handle: ... | Posted: ..." ANYWHERE in the raw text, including inside
# another post's own message body. That means a hostile post can embed a
# string that looks like a brand new header, tricking our own parser into
# treating attacker-controlled text as if it were a separate, trusted
# record — this is the same family of bug as log injection or CRLF
# injection: text designed to manipulate how downstream code interprets
# structure, not just what it says.
#
# We can't stop the injected text from being split out as its own entry
# without a much smarter parser, but we CAN refuse to trust it once it
# is: legitimate post numbers in a real export only ever run from 1 up to
# however many posts actually exist. A number far outside that range (or
# a number reused twice) is treated as a forged record, not real data.
#
# This is a best-effort mitigation, not a full fix — it's worth being
# honest that the real, complete fix is to not use human-readable
# delimiters for structured data in the first place (a properly escaped
# format like JSON or CSV doesn't have this problem, because record
# boundaries aren't just a string an attacker can imitate).
# ---------------------------------------------------------------------------

def detect_structural_anomalies(posts):
    """Return the set of post_numbers that look like forged/injected
    records rather than genuine posts from the export."""
    total = len(posts)
    seen = set()
    anomalies = set()
    for post in posts:
        num = post["post_number"]
        if num < 1 or num > total or num in seen:
            anomalies.add(num)
        seen.add(num)
    return anomalies


# ---------------------------------------------------------------------------
# Step 7: Putting it all together.
# For each post: check it isn't a forged/injected record first, then scan
# for malicious content. If both checks pass, run all four extractors and
# validate every match. If either check fails, quarantine the whole post —
# we don't process its contents as normal data.
# ---------------------------------------------------------------------------

def process_post(post, anomalous_numbers):
    result = {
        "post_number": post["post_number"],
        "platform": post["platform"],
        "handle": post["handle"],
        "posted_at": post["posted_at"],
        "flagged_unsafe": False,
        "unsafe_reasons": [],
        "extracted": None,
    }

    unsafe_reasons = []
    if post["post_number"] in anomalous_numbers:
        unsafe_reasons.append("structural_anomaly_suspected_header_injection")
    unsafe_reasons.extend(scan_for_malicious_content(post["body"]))

    if unsafe_reasons:
        result["flagged_unsafe"] = True
        result["unsafe_reasons"] = unsafe_reasons
        return result

    body = post["body"]

    emails = [
        {
            "masked": mask_email(e),
            "valid": validate_email(e),
            "alu_category": classify_alu_email(e),
            "suspicious_alu_lookalike": is_alu_domain_lookalike(e),
        }
        for e in EMAIL_CANDIDATE_RE.findall(body)
    ]

    credit_cards = [
        {
            "masked": mask_credit_card(c),
            "valid": validate_credit_card(c),
        }
        for c in CARD_CANDIDATE_RE.findall(body)
    ]

    hashtags = [
        {"value": h, "valid": validate_hashtag(h)}
        for h in HASHTAG_CANDIDATE_RE.findall(body)
    ]

    currency_amounts = [
        {"value": m.group(0), "valid": validate_currency(m.group(0))}
        for m in CURRENCY_CANDIDATE_RE.finditer(body)
    ]

    result["extracted"] = {
        "emails": emails,
        "credit_cards": credit_cards,
        "hashtags": hashtags,
        "currency_amounts": currency_amounts,
    }
    return result


def build_summary(processed_posts):
    summary = {
        "emails_found": 0, "emails_valid": 0,
        "emails_alu_official": 0, "emails_alu_alumni": 0, "emails_alu_si": 0,
        "emails_suspicious_alu_lookalike": 0,
        "credit_cards_found": 0, "credit_cards_valid": 0,
        "hashtags_found": 0, "hashtags_valid": 0,
        "currency_amounts_found": 0, "currency_amounts_valid": 0,
    }
    for post in processed_posts:
        if not post["extracted"]:
            continue
        for key, summary_prefix in [
            ("emails", "emails"),
            ("credit_cards", "credit_cards"),
            ("hashtags", "hashtags"),
            ("currency_amounts", "currency_amounts"),
        ]:
            items = post["extracted"][key]
            summary[f"{summary_prefix}_found"] += len(items)
            summary[f"{summary_prefix}_valid"] += sum(1 for i in items if i["valid"])
        for e in post["extracted"]["emails"]:
            if e["alu_category"] == "official":
                summary["emails_alu_official"] += 1
            elif e["alu_category"] == "alumni":
                summary["emails_alu_alumni"] += 1
            elif e["alu_category"] == "si":
                summary["emails_alu_si"] += 1
            if e["suspicious_alu_lookalike"]:
                summary["emails_suspicious_alu_lookalike"] += 1
    return summary


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    input_path = os.path.join(project_root, "input", "raw-text.txt")
    output_path = os.path.join(project_root, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    posts = parse_posts(raw_text)
    anomalous_numbers = detect_structural_anomalies(posts)
    processed_posts = [process_post(p, anomalous_numbers) for p in posts]
    summary = build_summary(processed_posts)
    flagged_count = sum(1 for p in processed_posts if p["flagged_unsafe"])

    output_data = {
        "meta": {
            "source_file": "input/raw-text.txt",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_posts_found": len(posts),
            "posts_flagged_unsafe": flagged_count,
            "posts_flagged_structural_anomaly": len(anomalous_numbers),
        },
        "posts": processed_posts,
        "summary": summary,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Processed {len(posts)} posts.")
    print(f"  Flagged (malicious content or structural anomaly): {flagged_count}")
    print(f"Emails:    {summary['emails_valid']}/{summary['emails_found']} valid "
          f"(official={summary['emails_alu_official']}, alumni={summary['emails_alu_alumni']}, "
          f"si={summary['emails_alu_si']}, suspicious_lookalike={summary['emails_suspicious_alu_lookalike']})")
    print(f"Cards:     {summary['credit_cards_valid']}/{summary['credit_cards_found']} valid (Luhn)")
    print(f"Hashtags:  {summary['hashtags_valid']}/{summary['hashtags_found']} valid")
    print(f"Currency:  {summary['currency_amounts_valid']}/{summary['currency_amounts_found']} valid")
    print(f"Full results written to {output_path}")


if __name__ == "__main__":
    main()
