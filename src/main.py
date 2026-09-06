"""
Data Extraction & Secure Validation Assignment
Author: Mathiang Mathew

Reads a raw export of ALU Finance & IT Helpdesk tickets and extracts four
data types: emails, credit card numbers, hashtags, and currency amounts.
Each type is handled in two stages — extract loosely with regex, then
validate strictly with Python logic.
"""

import re
import os
import json
from datetime import datetime, timezone


# ---------------------------------------------------------------------------
# PART 1: TICKET PARSER
# Splits the raw text into individual tickets using the header line format:
# Ticket #NNNN | Category: ... | Status: ... | Requester: ... | Submitted: ...
# ---------------------------------------------------------------------------

TICKET_HEADER_RE = re.compile(
    r"Ticket #(?P<num>\d+)\s*\|\s*Category:\s*(?P<category>[^|]+?)\s*\|\s*"
    r"Status:\s*(?P<status>[^|]+?)\s*\|\s*Requester:\s*(?P<requester>[^|]+?)\s*\|\s*"
    r"Submitted:\s*(?P<submitted_at>[^\n]+)"
)


def parse_tickets(raw_text):
    """Split the raw export into a list of ticket dicts."""
    headers = list(TICKET_HEADER_RE.finditer(raw_text))
    tickets = []
    for i, match in enumerate(headers):
        body_start = match.end()
        body_end = headers[i + 1].start() if i + 1 < len(headers) else len(raw_text)
        body = raw_text[body_start:body_end].strip()
        tickets.append({
            "ticket_number": int(match.group("num")),
            "category":      match.group("category").strip(),
            "status":        match.group("status").strip(),
            "requester":     match.group("requester").strip(),
            "submitted_at":  match.group("submitted_at").strip(),
            "body":          body,
        })
    return tickets


# ---------------------------------------------------------------------------
# PART 2: MALICIOUS CONTENT SCANNER
# Runs before extraction. Any match quarantines the whole ticket.
# Patterns: XSS script tags, inline JS handlers, javascript: URIs, SQL injection.
# ---------------------------------------------------------------------------

MALICIOUS_PATTERNS = {
    "script_tag":       re.compile(r"<\s*script\b", re.IGNORECASE),
    "js_event_handler": re.compile(r"\bon\w+\s*=\s*['\"]", re.IGNORECASE),
    "javascript_uri":   re.compile(r"javascript\s*:", re.IGNORECASE),
    "sql_injection":    re.compile(
        r"(;\s*--)|(\bDROP\s+TABLE\b)|(\bUNION\s+SELECT\b)|('\s*OR\s*'?1'?\s*=\s*'?1)",
        re.IGNORECASE,
    ),
}


def scan_for_malicious_content(text):
    """Return a list of matched pattern names. Empty list means clean."""
    return [label for label, pattern in MALICIOUS_PATTERNS.items() if pattern.search(text)]


# ---------------------------------------------------------------------------
# PART 3: STRUCTURAL ANOMALY DETECTION
# Defends against header-injection: a forged ticket number buried inside
# a description. Real ticket numbers cluster tightly; we flag outliers
# using median absolute deviation so one extreme value doesn't skew the check.
# ---------------------------------------------------------------------------

def detect_structural_anomalies(tickets):
    """Flag ticket numbers that sit far outside the batch's normal range."""
    numbers = [t["ticket_number"] for t in tickets]
    if len(numbers) < 2:
        return set()

    sorted_nums = sorted(numbers)
    n = len(sorted_nums)
    median = (
        sorted_nums[n // 2] if n % 2
        else (sorted_nums[n // 2 - 1] + sorted_nums[n // 2]) / 2
    )
    deviations = sorted(abs(x - median) for x in numbers)
    mad = (
        deviations[n // 2] if n % 2
        else (deviations[n // 2 - 1] + deviations[n // 2]) / 2
    )
    threshold = max(mad * 5, 10)

    seen = set()
    anomalies = set()
    for num in numbers:
        if num in seen or abs(num - median) > threshold:
            anomalies.add(num)
        seen.add(num)
    return anomalies


# ---------------------------------------------------------------------------
# PART 4: EMAIL EXTRACTION AND VALIDATION
# Extraction: standard local@domain.tld shape.
# Validation: rejects consecutive dots, bad starts/ends, and overlength addresses.
# ---------------------------------------------------------------------------

# Matches anything shaped like a valid email address
EMAIL_CANDIDATE_RE = re.compile(
    r"[A-Za-z0-9](?:[A-Za-z0-9._%+-]*[A-Za-z0-9])?@"
    r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,}"
)


def validate_email(email):
    """Return True if the email passes all format checks."""
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
# PART 4b: ALU DOMAIN CLASSIFICATION
# Uses exact suffix match (str.endswith), NOT substring check — a substring
# check would accept phishing addresses like noreply@alueducation.com.fake.net.
# Subdomains (alumni, si) are checked before the bare official suffix.
# ---------------------------------------------------------------------------

ALU_DOMAIN_CORE     = "alueducation.com"
ALU_OFFICIAL_SUFFIX = "@alueducation.com"
ALU_ALUMNI_SUFFIX   = "@alumni.alueducation.com"
ALU_SI_SUFFIX       = "@si.alueducation.com"


def classify_alu_email(email):
    """Return 'official', 'alumni', 'si', or None."""
    lower = email.lower()
    if lower.endswith(ALU_ALUMNI_SUFFIX):
        return "alumni"
    if lower.endswith(ALU_SI_SUFFIX):
        return "si"
    if lower.endswith(ALU_OFFICIAL_SUFFIX):
        return "official"
    return None


def is_alu_domain_lookalike(email):
    """Return True if the address contains alueducation.com but is not a real ALU domain."""
    lower = email.lower()
    if classify_alu_email(lower):
        return False
    return ALU_DOMAIN_CORE in lower


def mask_email(email):
    """Mask the local part to avoid exposing personal data in output.
    Example: a.bello@alueducation.com -> a*****o@alueducation.com"""
    local, _, domain = email.partition("@")
    if len(local) <= 2:
        masked_local = "*" * len(local)
    else:
        masked_local = local[0] + "*" * (len(local) - 2) + local[-1]
    return f"{masked_local}@{domain}"


# ---------------------------------------------------------------------------
# PART 5: CREDIT CARD EXTRACTION AND VALIDATION
# Extraction: 16-digit (Visa/Mastercard/Discover) or 15-digit AmEx layout.
# Separators can be spaces, dashes, or nothing.
# Validation: Luhn algorithm — same checksum banks use to catch invalid numbers.
# Masking: last 4 digits only. Card numbers are always treated as sensitive.
# ---------------------------------------------------------------------------

# Matches 15-digit AmEx (4-6-5) or 16-digit (4-4-4-4) with optional separators
CARD_CANDIDATE_RE = re.compile(
    r"\b(?:\d{4}[ -]?\d{6}[ -]?\d{5}|\d{4}[ -]?\d{4}[ -]?\d{4}[ -]?\d{4})\b"
)


def luhn_check(digits):
    """Return True if the digit string passes the Luhn checksum."""
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
    """Strip separators, check length is 15 or 16, then run Luhn."""
    digits = re.sub(r"[ -]", "", raw)
    if len(digits) not in (15, 16):
        return False
    return luhn_check(digits)


def mask_credit_card(raw):
    """Replace all but the last 4 digits with asterisks."""
    digits = re.sub(r"[ -]", "", raw)
    return "*" * (len(digits) - 4) + digits[-4:]


# ---------------------------------------------------------------------------
# PART 6: HASHTAG EXTRACTION AND VALIDATION
# Extraction: # followed by word characters (letters, digits, underscore).
# A dash ends a hashtag, so #please-fix-asap extracts as just #please.
# Validation: body must be 2-30 characters and not purely numeric.
# ---------------------------------------------------------------------------

HASHTAG_CANDIDATE_RE = re.compile(r"#\w+")


def validate_hashtag(tag):
    """Return True if the hashtag body is the right length and not all digits."""
    body = tag[1:]
    if not (2 <= len(body) <= 30):
        return False
    if body.isdigit():
        return False
    return True


# ---------------------------------------------------------------------------
# PART 7: CURRENCY EXTRACTION AND VALIDATION
# Extraction: supports symbol/code before number ($1,000 / RWF 500) and
# currency code after number (500 RWF / 1,000 USD) — both forms are used
# naturally at ALU Kigali.
# Validation: correct thousands-comma grouping, at most 2 decimal places.
# ---------------------------------------------------------------------------

# Matches prefix form ($, £, €, or code) and suffix form (code after number)
CURRENCY_CANDIDATE_RE = re.compile(
    r"(?:[$£€]\s?\d(?:[\d,.]*\d)?)"
    r"|(?:\b(?:USD|KES|UGX|GBP|EUR|RWF)\s?\d(?:[\d,.]*\d)?)"
    r"|(?:\b\d(?:[\d,.]*\d)?\s?(?:RWF|USD|KES|UGX|GBP|EUR)\b)"
)

CURRENCY_PREFIX_RE = re.compile(r"^([$£€]|USD|KES|UGX|GBP|EUR|RWF)\s?(.+)$")
CURRENCY_SUFFIX_RE = re.compile(r"^(.+?)\s?(USD|KES|UGX|GBP|EUR|RWF)$")
CURRENCY_AMOUNT_RE = re.compile(r"^(\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{2})?$")


def validate_currency(raw):
    """Return True if the amount has correct comma grouping and decimal format."""
    prefix_match = CURRENCY_PREFIX_RE.match(raw)
    if prefix_match:
        return bool(CURRENCY_AMOUNT_RE.match(prefix_match.group(2)))
    suffix_match = CURRENCY_SUFFIX_RE.match(raw)
    if suffix_match:
        return bool(CURRENCY_AMOUNT_RE.match(suffix_match.group(1)))
    return False


# ---------------------------------------------------------------------------
# PART 8: PROCESS A SINGLE TICKET
# Runs security checks first, then all four extractors.
# Scans requester field + body together — the requester email lives in the
# header, not the description, so scanning body alone would miss it.
# ---------------------------------------------------------------------------

def process_ticket(ticket, anomalous_numbers):
    """Return a result dict for one ticket — flagged or fully extracted."""
    result = {
        "ticket_number":  ticket["ticket_number"],
        "category":       ticket["category"],
        "status":         ticket["status"],
        "requester":      ticket["requester"],
        "submitted_at":   ticket["submitted_at"],
        "flagged_unsafe": False,
        "unsafe_reasons": [],
        "extracted":      None,
    }

    # Combine header + body so no field is left unscanned
    full_text = f"{ticket['requester']}\n{ticket['body']}"

    unsafe_reasons = []
    if ticket["ticket_number"] in anomalous_numbers:
        unsafe_reasons.append("structural_anomaly_suspected_header_injection")
    unsafe_reasons.extend(scan_for_malicious_content(full_text))

    if unsafe_reasons:
        result["flagged_unsafe"] = True
        result["unsafe_reasons"] = unsafe_reasons
        return result

    emails = [
        {
            "masked":                   mask_email(e),
            "valid":                    validate_email(e),
            "alu_category":             classify_alu_email(e),
            "suspicious_alu_lookalike": is_alu_domain_lookalike(e),
        }
        for e in EMAIL_CANDIDATE_RE.findall(full_text)
    ]

    credit_cards = [
        {
            "masked": mask_credit_card(c),
            "valid":  validate_credit_card(c),
        }
        for c in CARD_CANDIDATE_RE.findall(full_text)
    ]

    hashtags = [
        {"value": h, "valid": validate_hashtag(h)}
        for h in HASHTAG_CANDIDATE_RE.findall(full_text)
    ]

    currency_amounts = [
        {"value": m.group(0), "valid": validate_currency(m.group(0))}
        for m in CURRENCY_CANDIDATE_RE.finditer(full_text)
    ]

    result["extracted"] = {
        "emails":           emails,
        "credit_cards":     credit_cards,
        "hashtags":         hashtags,
        "currency_amounts": currency_amounts,
    }
    return result


# ---------------------------------------------------------------------------
# PART 9: BUILD SUMMARY
# Aggregates counts across all tickets for the summary block in the output.
# ---------------------------------------------------------------------------

def build_summary(processed_tickets):
    """Return a dict of totals across all processed tickets."""
    summary = {
        "emails_found": 0, "emails_valid": 0,
        "emails_alu_official": 0, "emails_alu_alumni": 0, "emails_alu_si": 0,
        "emails_suspicious_alu_lookalike": 0,
        "credit_cards_found": 0, "credit_cards_valid": 0,
        "hashtags_found": 0, "hashtags_valid": 0,
        "currency_amounts_found": 0, "currency_amounts_valid": 0,
    }
    for ticket in processed_tickets:
        if not ticket["extracted"]:
            continue
        for key in ("emails", "credit_cards", "hashtags", "currency_amounts"):
            items = ticket["extracted"][key]
            summary[f"{key}_found"] += len(items)
            summary[f"{key}_valid"] += sum(1 for i in items if i["valid"])
        for e in ticket["extracted"]["emails"]:
            if e["alu_category"] == "official":
                summary["emails_alu_official"] += 1
            elif e["alu_category"] == "alumni":
                summary["emails_alu_alumni"] += 1
            elif e["alu_category"] == "si":
                summary["emails_alu_si"] += 1
            if e["suspicious_alu_lookalike"]:
                summary["emails_suspicious_alu_lookalike"] += 1
    return summary


# ---------------------------------------------------------------------------
# PART 10: MAIN
# Reads input, runs all processing, writes JSON output, prints summary.
# ---------------------------------------------------------------------------

def main():
    script_dir   = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(script_dir)
    input_path   = os.path.join(project_root, "input", "raw-text.txt")
    output_path  = os.path.join(project_root, "output", "sample-output.json")

    with open(input_path, "r", encoding="utf-8") as f:
        raw_text = f.read()

    tickets           = parse_tickets(raw_text)
    anomalous_numbers = detect_structural_anomalies(tickets)
    processed_tickets = [process_ticket(t, anomalous_numbers) for t in tickets]
    summary           = build_summary(processed_tickets)
    flagged_count     = sum(1 for t in processed_tickets if t["flagged_unsafe"])

    output_data = {
        "meta": {
            "source_file":                       "input/raw-text.txt",
            "generated_at":                      datetime.now(timezone.utc).isoformat(),
            "total_tickets_found":               len(tickets),
            "tickets_flagged_unsafe":            flagged_count,
            "tickets_flagged_structural_anomaly": len(anomalous_numbers),
        },
        "tickets": processed_tickets,
        "summary": summary,
    }

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(output_data, f, indent=2)

    print(f"Processed {len(tickets)} tickets.")
    print(f"  Flagged (malicious or structural anomaly): {flagged_count}")
    print(f"Emails:   {summary['emails_valid']}/{summary['emails_found']} valid "
          f"(official={summary['emails_alu_official']}, "
          f"alumni={summary['emails_alu_alumni']}, "
          f"si={summary['emails_alu_si']}, "
          f"suspicious_lookalike={summary['emails_suspicious_alu_lookalike']})")
    print(f"Cards:    {summary['credit_cards_valid']}/{summary['credit_cards_found']} valid (Luhn)")
    print(f"Hashtags: {summary['hashtags_valid']}/{summary['hashtags_found']} valid")
    print(f"Currency: {summary['currency_amounts_valid']}/{summary['currency_amounts_found']} valid")
    print(f"Results written to {output_path}")


if __name__ == "__main__":
    main()
