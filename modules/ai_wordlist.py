import os
import json
from datetime import datetime

try:
    import anthropic
    ANTHROPIC_LIB = True
except ImportError:
    ANTHROPIC_LIB = False

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

ANTHROPIC_API_KEY  = os.environ.get("ANTHROPIC_API_KEY", "")
DEFAULT_WORDLIST   = os.path.join(os.path.dirname(__file__),
                                  "../wordlists/subdomains.txt")
AI_WORDLIST_OUTPUT = os.path.join(os.path.dirname(__file__),
                                  "../wordlists/ai_generated.txt")
MAX_TOKENS         = 1024
MODEL              = "claude-opus-4-6"

# ──────────────────────────────────────────────
#  LOCAL TERM DATABASES (no API required)
# ──────────────────────────────────────────────

INDUSTRY_TERMS = {
    "banking": [
        "ib", "ibank", "internetbanking", "onlinebanking", "retail",
        "corporate", "corp", "loans", "loan", "cards", "card", "credit",
        "atm", "branch", "branches", "wakala", "agent", "agents", "agency",
        "benki", "tiss", "swift", "rtgs", "forex", "treasury", "wealth",
        "invest", "investment", "mortgage", "savings", "account", "accounts",
        "statement", "statements", "transfer", "payments", "pay", "billpay",
    ],
    "fintech": [
        "pay", "payment", "payments", "wallet", "money", "cash", "send",
        "mpesa", "mpesagateway", "tigopesa", "airtelmoney", "halopesa",
        "ussd", "stk", "c2b", "b2c", "b2b", "collection", "collections",
        "disbursement", "float", "agent", "agents", "wakala", "till",
        "paybill", "checkout", "gateway", "api", "sandbox", "merchant",
    ],
    "telecom": [
        "selfcare", "care", "myaccount", "recharge", "topup", "airtime",
        "bundles", "data", "roaming", "ussd", "sms", "smsc", "vas",
        "ott", "ivr", "crm", "billing", "prepaid", "postpaid", "sim",
        "esim", "network", "noc", "ggsn", "sgsn", "hlr", "ims", "volte",
    ],
    "government": [
        "portal", "services", "eservices", "citizen", "citizens", "egov",
        "gov", "tax", "revenue", "license", "licensing", "permit", "permits",
        "registry", "records", "passport", "visa", "immigration", "customs",
        "tender", "tenders", "procurement", "payroll", "hr", "staff",
    ],
    "ecommerce": [
        "shop", "store", "cart", "checkout", "payment", "pay", "order",
        "orders", "catalog", "products", "seller", "sellers", "vendor",
        "vendors", "merchant", "delivery", "logistics", "track", "tracking",
        "warehouse", "inventory", "stock", "promo", "deals", "marketplace",
    ],
    "health": [
        "patient", "patients", "portal", "ehr", "emr", "records", "appointment",
        "appointments", "booking", "pharmacy", "lab", "labs", "results",
        "telemedicine", "telehealth", "claims", "insurance", "billing",
    ],
    "education": [
        "student", "students", "portal", "elearning", "lms", "moodle",
        "exam", "exams", "results", "admission", "admissions", "library",
        "staff", "faculty", "alumni", "research", "sis", "registration",
    ],
    "technology": [
        "api", "dev", "staging", "test", "uat", "qa", "sandbox", "demo",
        "app", "apps", "cloud", "git", "gitlab", "jenkins", "ci", "cd",
        "registry", "docker", "k8s", "console", "dashboard", "admin",
    ],
}

UNIVERSAL_TERMS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "mx", "email",
    "remote", "vpn", "portal", "admin", "administrator", "login", "sso",
    "dev", "development", "staging", "stage", "test", "testing", "uat",
    "qa", "demo", "sandbox", "preprod", "prod", "production",
    "api", "api-dev", "api-staging", "apis", "rest", "graphql", "ws",
    "app", "apps", "mobile", "m", "web", "dashboard", "panel",
    "cpanel", "whm", "plesk", "webdisk", "ns1", "ns2", "dns", "ftp", "sftp",
    "git", "gitlab", "github", "bitbucket", "jenkins", "ci", "cd", "build",
    "jira", "confluence", "wiki", "docs", "support", "help", "helpdesk",
    "status", "monitor", "monitoring", "grafana", "kibana", "prometheus",
    "db", "database", "mysql", "postgres", "mongo", "redis", "elastic",
    "backup", "backups", "old", "legacy", "archive", "temp", "tmp",
    "internal", "intranet", "corp", "corporate", "secure", "private",
    "cdn", "static", "assets", "media", "img", "images", "files", "upload",
    "blog", "news", "shop", "store", "pay", "payment", "billing", "invoice",
    "crm", "erp", "hr", "payroll", "finance", "accounts", "auth", "oauth",
]

REGIONAL_AFFIXES = {
    "Tanzania":     ["tz", "tza", "dar", "dsm", "tz-prod", "tz-dev"],
    "Kenya":        ["ke", "ken", "nbo", "nairobi", "ke-prod", "ke-dev"],
    "Nigeria":      ["ng", "nga", "lagos", "lag", "abuja", "ng-prod"],
    "Uganda":       ["ug", "uga", "kla", "kampala", "ug-prod"],
    "Rwanda":       ["rw", "rwa", "kigali", "kgl", "rw-prod"],
    "Ghana":        ["gh", "gha", "accra", "acc", "gh-prod"],
    "South Africa": ["za", "zaf", "jhb", "johannesburg", "cpt", "capetown"],
}

PERMUTATION_AFFIXES = [
    "1", "2", "3", "01", "02", "dev", "test", "staging", "prod",
    "new", "old", "v1", "v2", "internal", "external", "uat",
]

# ──────────────────────────────────────────────
#  DOMAIN INTELLIGENCE
# ──────────────────────────────────────────────

def extract_domain_intelligence(domain):
    intelligence = {
        "domain":   domain,
        "tld":      domain.split(".")[-1],
        "sld":      domain.split(".")[-2] if len(domain.split(".")) > 1 else domain,
        "region":   "unknown",
        "industry": "unknown",
    }

    regional_tlds = {
        "tz": "Tanzania", "ke": "Kenya", "ng": "Nigeria",
        "ug": "Uganda",   "rw": "Rwanda", "gh": "Ghana",
        "za": "South Africa", "et": "Ethiopia", "cm": "Cameroon",
        "sn": "Senegal",  "ci": "Ivory Coast", "eg": "Egypt",
    }

    industry_keywords = {
        "bank": "banking", "benki": "banking", "finance": "finance",
        "pay": "fintech", "money": "fintech", "pesa": "fintech",
        "telecom": "telecom", "mobile": "telecom", "airtel": "telecom",
        "vodacom": "telecom", "tigo": "telecom", "health": "health",
        "hospital": "health", "shop": "ecommerce", "store": "ecommerce",
        "tech": "technology", "soft": "technology",
    }

    parts = domain.split(".")
    if parts[-1] in regional_tlds:
        intelligence["region"] = regional_tlds[parts[-1]]

    domain_lower = domain.lower()
    for keyword, industry in industry_keywords.items():
        if keyword in domain_lower:
            intelligence["industry"] = industry
            break

    return intelligence

# ──────────────────────────────────────────────
#  LOCAL WORDLIST GENERATOR (no API)
# ──────────────────────────────────────────────

def generate_local_wordlist(domain, intelligence):
    """
    Generate a contextual wordlist using local rules and detected
    intelligence. No API key required — works for everyone.
    """
    print(f"\n[*] Generating local contextual wordlist for {domain}...")
    words = set()

    words.update(UNIVERSAL_TERMS)

    industry = intelligence.get("industry", "unknown")
    if industry in INDUSTRY_TERMS:
        words.update(INDUSTRY_TERMS[industry])
        print(f"    [+] Added {len(INDUSTRY_TERMS[industry])} {industry} terms")

    region = intelligence.get("region", "unknown")
    if region in REGIONAL_AFFIXES:
        for affix in REGIONAL_AFFIXES[region]:
            words.add(affix)
            for key in ["api", "portal", "app", "vpn", "mail", "admin"]:
                words.add(f"{key}-{affix}")
                words.add(f"{affix}-{key}")
        print(f"    [+] Added regional terms for {region}")

    high_value = ["api", "app", "portal", "admin", "vpn", "dashboard",
                  "gateway", "auth", "pay", "secure"]
    for term in high_value:
        for affix in PERMUTATION_AFFIXES:
            words.add(f"{term}-{affix}")
            words.add(f"{term}{affix}")

    result = sorted(words)
    print(f"    [+] Local generator produced {len(result)} contextual words")
    return result

# ──────────────────────────────────────────────
#  AI WORDLIST GENERATOR (requires API)
# ──────────────────────────────────────────────

def generate_ai_wordlist(domain, intelligence):
    """
    Call Claude API for contextual subdomains. Returns [] if no
    API key or library — caller falls back to local generator.
    """
    if not ANTHROPIC_LIB:
        print("[*] anthropic library not installed — using local generator only")
        return []
    if not ANTHROPIC_API_KEY:
        print("[*] No API key set — using local generator only")
        return []

    print(f"\n[*] Generating AI wordlist for {domain}...")
    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    prompt = f"""You are a professional penetration tester performing authorized
reconnaissance on {domain}.

Target intelligence:
- Domain: {intelligence['domain']}
- TLD: {intelligence['tld']}
- Region: {intelligence['region']}
- Industry: {intelligence['industry']}

Generate 200 highly relevant subdomain prefixes for this specific target.
Consider the industry, region (include local language and Africa-specific
platform names like M-Pesa, Airtel Money, wakala, benki where relevant),
internal infrastructure, dev/staging environments, and API endpoints.

Return ONLY a JSON array of lowercase subdomain strings, no dots, no spaces,
no explanations, no markdown. Example: ["mail","dev","api","wakala","mpesa"]"""

    try:
        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}]
        )
        response_text = message.content[0].text.strip()
        subdomains = json.loads(response_text)
        if isinstance(subdomains, list):
            print(f"    [+] AI generated {len(subdomains)} contextual subdomains")
            return subdomains
        return []
    except json.JSONDecodeError:
        print("[!] Could not parse AI response — using local generator")
        return []
    except Exception as e:
        print(f"[!] AI generation failed ({e}) — using local generator")
        return []

# ──────────────────────────────────────────────
#  WORDLIST MERGER
# ──────────────────────────────────────────────

def merge_wordlists(*wordlists, standard_wordlist_path=DEFAULT_WORDLIST):
    """
    Merge any number of wordlists with the standard wordlist.
    Deduplicates while preserving order (contextual words first).
    """
    print(f"\n[*] Merging wordlists...")

    combined = []
    for wl in wordlists:
        combined.extend(wl)

    standard_words = []
    if os.path.exists(standard_wordlist_path):
        with open(standard_wordlist_path, "r") as f:
            standard_words = [line.strip() for line in f if line.strip()]

    merged = list(dict.fromkeys(combined + standard_words))
    print(f"    [+] Contextual words: {len(combined)}")
    print(f"    [+] Standard words: {len(standard_words)}")
    print(f"    [+] Merged total: {len(merged)} (deduplicated)")
    return merged

# ──────────────────────────────────────────────
#  SAVE WORDLIST
# ──────────────────────────────────────────────

def save_wordlist(words, output_path=AI_WORDLIST_OUTPUT):
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for word in words:
            f.write(word + "\n")
    print(f"    [+] Wordlist saved to {output_path}")
    return output_path

# ──────────────────────────────────────────────
#  MAIN ENTRY POINT
# ──────────────────────────────────────────────

def run(domain):
    """
    Full contextual wordlist pipeline:
      1. Extract domain intelligence
      2. Generate local wordlist (always)
      3. Generate AI wordlist (if API available)
      4. Merge everything with standard wordlist
      5. Save and return path
    Works with or without API credits.
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — CONTEXTUAL WORDLIST MODULE")
    print(f"  Target : {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    intelligence = extract_domain_intelligence(domain)
    print(f"\n[*] Domain intelligence:")
    print(f"    Region  : {intelligence['region']}")
    print(f"    Industry: {intelligence['industry']}")
    print(f"    TLD     : {intelligence['tld']}")

    # Always generate local wordlist
    local_words = generate_local_wordlist(domain, intelligence)

    # Try AI wordlist (returns [] if unavailable)
    ai_words = generate_ai_wordlist(domain, intelligence)

    # Merge everything
    merged = merge_wordlists(ai_words, local_words)

    # Save
    output_path = save_wordlist(merged)

    engine = "AI + local" if ai_words else "local only"
    print(f"\n[*] Wordlist ready — {len(merged)} candidates ({engine})")
    print(f"{'='*60}\n")

    return output_path
