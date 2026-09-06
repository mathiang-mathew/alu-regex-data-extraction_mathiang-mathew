# ALU Regex Data Extraction & Secure Validation

**Author:** Mathiang Mathew  
**Language:** Python 3

---

## What this project is about

At ALU, students regularly submit payment-related support tickets — for
tuition installments, health insurance, module re-sit fees, and Student
Immersion program deposits. Parents paying from outside Rwanda often use
an international card because Mobile Money doesn't work cross-border.

This program takes a raw batch export from the helpdesk system and pulls
out structured data from the free-text descriptions: email addresses,
credit card numbers, hashtags, and currency amounts. It also validates
everything it finds and flags anything suspicious before processing it.

I built the input data around this scenario because it's realistic — the
kind of messy, real-world text a junior developer would actually have to
write a pipeline for.

---

## Folder structure

```
alu-regex-data-extraction_mathiang-mathew/
├── input/
│   └── raw-text.txt        # 14 sample helpdesk tickets
├── src/
│   └── main.py             # all the logic
├── output/
│   └── sample-output.json  # generated when you run the program
└── README.md
```

---

## How to run it

From the project root:

```bash
python3 src/main.py
```

It reads `input/raw-text.txt`, processes every ticket, and writes the
results to `output/sample-output.json`. You'll also see a short summary
printed to the terminal.

---

## How extraction and validation work

Every data type follows the same two-step approach: first a regex finds
anything that looks like a candidate (loose on purpose), then a separate
Python check decides if that candidate is actually valid. Keeping these
two steps separate makes the logic easier to follow and easier to test —
and it means a malformed value still gets found and reported as invalid,
rather than silently disappearing.

### Emails

The regex looks for the standard `local@domain.tld` shape. Validation
then catches things the regex would still let through — consecutive dots,
a local part starting or ending with a dot, addresses over 254 characters.

Every email is also checked against the three real ALU domains:

| What it means | Domain |
|---|---|
| Current student or staff | `@alueducation.com` |
| ALU graduate | `@alumni.alueducation.com` |
| Student Immersion office | `@si.alueducation.com` |

One thing worth noting: the check uses `str.endswith()`, not a substring
search. A substring check would accept something like
`noreply@alueducation.com.verify-now.net` because the trusted string
appears inside it — but the real domain is `verify-now.net`. The sample
data includes exactly this phishing trick and the program correctly flags
it as a lookalike, not a real ALU address.

### Credit card numbers

The regex matches two formats: 16-digit cards in groups of four
(Visa, Mastercard, Discover) and 15-digit American Express cards in
4-6-5 grouping. Separators can be spaces, dashes, or nothing.

Validation runs the Luhn algorithm — the same checksum banks use to catch
typos and made-up numbers. A well-formatted number can still fail Luhn,
and that distinction is exactly what this step is for.

Card numbers are always masked to their last 4 digits in the output
(`************1111`), valid or not. Anything that looks like a card
number in free text gets treated as sensitive by default.

### Hashtags

The regex grabs `#` followed by word characters. A dash ends a hashtag —
so `#please-fix-asap` extracts as just `#please`, which is how real
platforms handle it too. Validation rejects tags that are shorter than
2 characters, longer than 30, or purely numeric (since `#2` in
"installment #2 of 3" means "number", not a hashtag).

### Currency amounts

The regex handles both orderings people actually use — code before the
number (`$1,000`, `RWF 500`, `USD 250.00`) and code after the number
(`500 RWF`, `1,000 USD`). The trailing-code form is how people at ALU
Kigali naturally write RWF amounts, so leaving it out would miss real
data. Validation enforces correct comma grouping and at most two decimal
places — which is what catches `USD 40..00` as found-but-invalid rather
than just ignoring it.

---

## Security

### Sensitive data stays out of the output

Card numbers are masked to the last 4 digits. Email local parts are also
masked (`a*****o@alueducation.com`). Neither ever gets written to disk
in full.

### Malicious content is caught before extraction runs

Each ticket is scanned for known attack patterns before anything else
happens. If a match is found, the whole ticket is quarantined — no
extraction runs on it at all. The patterns I check for are script tags
(XSS), inline JavaScript event handlers, `javascript:` URIs, and common
SQL injection markers. Two tickets in the sample data trigger this: one
contains a hidden script tag inside what looks like a student complaint,
and another contains a SQL injection string framed as a bug report.

### Header injection is detected

The parser finds ticket boundaries by searching for the header pattern
anywhere in the raw text — which means a hostile ticket could embed a
fake `Ticket #9999 | ...` line inside its own description and trick the
parser into treating that attacker-written text as a separate trusted
record. This is the same class of bug as log injection.

The defense I implemented flags any ticket number that sits far outside
the batch's normal range, using median absolute deviation so one extreme
outlier doesn't skew the check. Ticket #4511 in the sample data attempts
exactly this attack, and the forged `#9999` record it produces gets
quarantined.

---

## Reading the output

The JSON file has three sections:

- `meta` — how many tickets were found, how many were flagged, and how
  many of those were structural anomalies specifically.
- `tickets` — one entry per ticket. Flagged tickets show `flagged_unsafe: true`
  and the reason, with no extracted data. Clean tickets show everything
  that was found and whether each item passed validation.
- `summary` — totals across the whole run, including the breakdown of ALU
  email categories and how many suspicious lookalike addresses were caught.
