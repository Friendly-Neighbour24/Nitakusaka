import os
import json
import anthropic
from datetime import datetime

# ──────────────────────────────────────────────
#  CONFIGURATION
# ──────────────────────────────────────────────

ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
DEFAULT_WORDLIST   = os.path.join(os.path.dirname(__file__),
                                  "../wordlists/subdomains.txt")
AI_WORDLIST_OUTPUT = os.path.join(os.path.dirname(__file__),
                                  "../wordlists/ai_generated.txt")
MAX_TOKENS         = 1024
MODEL              = "claude-opus-4-6"

# ──────────────────────────────────────────────
#  DOMAIN INTELLIGENCE
# ──────────────────────────────────────────────

def extract_domain_intelligence(domain):
    """
    Extract clues about the target's industry and region
    from the domain itself before calling the AI.
    The more context we give the AI, the better its guesses.
    """
    intelligence = {
        "domain":   domain,
        "tld":      domain.split(".")[-1],
        "sld":      domain.split(".")[-2] if len(domain.split(".")) > 1 else domain,
        "region":   "unknown",
        "industry": "unknown",
    }

    # Regional TLD mapping
    regional_tlds = {
        "tz": "Tanzania", "ke": "Kenya", "ng": "Nigeria",
        "ug": "Uganda",   "rw": "Rwanda", "gh": "Ghana",
        "za": "South Africa", "et": "Ethiopia", "cm": "Cameroon",
        "sn": "Senegal",  "ci": "Ivory Coast", "eg": "Egypt",
    }

    # Second level regional TLDs (.co.tz, .co.ke, .go.tz etc)
    second_level_tlds = {
        "co":  "commercial", "go":  "government",
        "ac":  "academic",   "or":  "organization",
        "mil": "military",   "net": "network",
    }

    # Industry keyword mapping
    industry_keywords = {
        "bank":     "banking", "benki":   "banking",
        "finance":  "finance", "pay":     "fintech",
        "money":    "fintech", "pesa":    "fintech",
        "telecom":  "telecom", "mobile":  "telecom",
        "airtel":   "telecom", "vodacom": "telecom",
        "health":   "health",  "hospital":"health",
        "gov":      "government", "go":   "government",
        "edu":      "education",  "ac":   "education",
        "shop":     "ecommerce",  "store":"ecommerce",
        "tech":     "technology", "soft": "technology",
    }

    # Detect region from TLD
    parts = domain.split(".")
    if parts[-1] in regional_tlds:
        intelligence["region"] = regional_tlds[parts[-1]]
    if len(parts) >= 3 and parts[-2] in second_level_tlds:
        intelligence["sector"] = second_level_tlds[parts[-2]]

    # Detect industry from domain name keywords
    domain_lower = domain.lower()
    for keyword, industry in industry_keywords.items():
        if keyword in domain_lower:
            intelligence["industry"] = industry
            break

    return intelligence

# ──────────────────────────────────────────────
#  AI WORDLIST GENERATOR
# ──────────────────────────────────────────────

def generate_ai_wordlist(domain, intelligence):
    """
    Call Claude API with target intelligence to generate
    contextually relevant subdomain guesses specific to
    this target's industry, region, and technology stack.
    """
    print(f"\n[*] Generating AI wordlist for {domain}...")

    if not ANTHROPIC_API_KEY:
        print("[!] No API key found. Set ANTHROPIC_API_KEY environment variable.")
        return []

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)

    prompt = f"""You are a professional penetration tester performing authorized 
reconnaissance on {domain}.

Target intelligence:
- Domain: {intelligence['domain']}
- TLD: {intelligence['tld']}
- Region: {intelligence['region']}
- Industry: {intelligence['industry']}

Generate a list of 200 highly relevant subdomain prefixes for this specific target.
Consider:
1. The target's industry ({intelligence['industry']}) — what subdomains would 
   this type of organization commonly use?
2. The target's region ({intelligence['region']}) — include local language terms,
   regional service names, and Africa-specific platform names where relevant
   (M-Pesa, Airtel Money, MTN MoMo, USSD, wakala, benki etc.)
3. Common internal infrastructure names for this sector
4. Developer and staging environments specific to this industry
5. API and integration endpoints common in this region
6. Government/regulatory portals if applicable

Return ONLY a JSON array of subdomain strings, nothing else.
No explanations, no markdown, no backticks.
Example format: ["mail","dev","api","loans","wakala","mpesa-gateway"]

The subdomains should be lowercase, no dots, no spaces.
Mix common ones with highly specific ones for this target."""

    try:
        message = client.messages.create(
            model=MODEL,
            max_tokens=MAX_TOKENS,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        response_text = message.content[0].text.strip()

        # Parse JSON response
        subdomains = json.loads(response_text)

        if isinstance(subdomains, list):
            print(f"    [+] AI generated {len(subdomains)} contextual subdomains")
            return subdomains
        else:
            print("[!] Unexpected response format from AI")
            return []

    except json.JSONDecodeError:
        print("[!] Could not parse AI response as JSON")
        return []
    except Exception as e:
        print(f"[!] AI generation failed: {e}")
        return []
    
    # ──────────────────────────────────────────────
#  WORDLIST MERGER
# ──────────────────────────────────────────────

def merge_wordlists(ai_words, standard_wordlist_path=DEFAULT_WORDLIST):
    """
    Merge AI generated words with the standard SecLists wordlist.
    Deduplicate and put AI words first since they're more relevant.
    """
    print(f"\n[*] Merging AI wordlist with standard wordlist...")

    standard_words = []
    if os.path.exists(standard_wordlist_path):
        with open(standard_wordlist_path, "r") as f:
            standard_words = [line.strip() for line in f if line.strip()]

    # AI words first — they're more targeted
    # Use dict.fromkeys to deduplicate while preserving order
    merged = list(dict.fromkeys(ai_words + standard_words))

    print(f"    [+] AI words: {len(ai_words)}")
    print(f"    [+] Standard words: {len(standard_words)}")
    print(f"    [+] Merged total: {len(merged)} (after deduplication)")

    return merged


# ──────────────────────────────────────────────
#  SAVE WORDLIST
# ──────────────────────────────────────────────

def save_wordlist(words, output_path=AI_WORDLIST_OUTPUT):
    """
    Save the merged wordlist to a file so the DNS module
    can use it directly.
    """
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
    Full AI wordlist generation pipeline:
      1. Extract domain intelligence
      2. Generate contextual wordlist via Claude API
      3. Merge with standard wordlist
      4. Save and return path to merged wordlist
    """
    print(f"\n{'='*60}")
    print(f"  NITAKUSAKA — AI WORDLIST MODULE")
    print(f"  Target : {domain}")
    print(f"  Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*60}")

    # 1. Extract intelligence from domain
    intelligence = extract_domain_intelligence(domain)
    print(f"\n[*] Domain intelligence:")
    print(f"    Region  : {intelligence['region']}")
    print(f"    Industry: {intelligence['industry']}")
    print(f"    TLD     : {intelligence['tld']}")

    # 2. Generate AI wordlist
    ai_words = generate_ai_wordlist(domain, intelligence)

    if not ai_words:
        print("[!] AI generation failed — falling back to standard wordlist")
        return DEFAULT_WORDLIST

    # 3. Merge with standard wordlist
    merged = merge_wordlists(ai_words)

    # 4. Save merged wordlist
    output_path = save_wordlist(merged)

    print(f"\n[*] AI wordlist ready — {len(merged)} total candidates")
    print(f"{'='*60}\n")

    return output_path