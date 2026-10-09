import os
import re
from typing import Dict, Any
import requests

RESTRICTED_GUARD_MESSAGE = (
    "I can only help with phishing, malicious websites, online scams, "
    "safe browsing, cybersecurity awareness and related security topics."
)

ALLOWED_KEYWORDS = [
    "phish", "scam", "malicious", "url", "link", "website", "cyber", "security",
    "browse", "browser", "password", "login", "account", "hacked", "victim",
    "whois", "https", "ssl", "cert", "domain", "spoof", "impersonat", "fake",
    "email", "sms", "smishing", "vishing", "credential", "steal", "malware",
    "virus", "antivirus", "safe", "danger", "check", "verify", "report",
    "google safe browsing", "mfa", "2fa", "authentication", "privacy", "bank",
    "credit card", "threat", "risk", "attack", "fraud"
]

OUT_OF_DOMAIN_PATTERNS = [
    r"\bjoke\b", r"\belon musk\b", r"\bmiles\b", r"\bmath\b", r"\bequation\b",
    r"\bcode in python\b", r"\bwrite an essay\b", r"\bcapital of\b", r"\bwho is\b",
    r"\brecipe\b", r"\bsong\b", r"\bmovie\b", r"\bweather\b", r"\bsports\b",
    r"\bcricket\b", r"\bfootball\b"
]

CANDIDATE_MODELS = [
    "openai/gpt-oss-120b",
    "openai/gpt-oss-20b",
    "qwen/qwen3.8-27b",
    "llama-3.3-70b-versatile"
]

def is_security_related(prompt: str) -> bool:
    """
    Topic guard classifier: checks if input query is related to security & phishing.
    """
    if not prompt or len(prompt.strip()) == 0:
        return False
        
    prompt_lower = prompt.lower()

    # Check explicitly barred non-security patterns
    for pattern in OUT_OF_DOMAIN_PATTERNS:
        if re.search(pattern, prompt_lower):
            # Unless it explicitly mentions phishing/cybersecurity overriding
            if not any(k in prompt_lower for k in ["phish", "scam", "cybersecurity", "malicious"]):
                return False

    # Check presence of security keywords
    matched = any(kw in prompt_lower for kw in ALLOWED_KEYWORDS)
    
    # Generic security questions like "What should I do after clicking a link?" or "Is this safe?"
    if matched or len(prompt_lower.split()) < 4:
        return True

    return False

def get_chatbot_response(prompt: str) -> Dict[str, Any]:
    """
    Processes user chat prompt through Topic Guard and Groq LLM API.
    """
    # 1. Topic Guard Check
    if not is_security_related(prompt):
        return {
            "allowed": False,
            "response": RESTRICTED_GUARD_MESSAGE,
            "topic_blocked": True
        }

    # 2. Prepare Groq LLM Request
    api_key = os.getenv("GROQ_API_KEY", "")

    if not api_key:
        return {
            "allowed": True,
            "response": "Security AI Assistant configuration notice: GROQ_API_KEY is not set in environment. Please add GROQ_API_KEY to your .env file to enable live LLM responses.",
            "topic_blocked": False
        }

    system_prompt = (
        "You are PhishGuard AI, an expert cybersecurity assistant specializing exclusively in "
        "phishing detection, malicious websites, online scams, safe browsing, and cybersecurity awareness. "
        "Provide concise, actionable, highly professional security advice. "
        "Never discuss topics outside of cybersecurity, phishing, and safe browsing."
    )

    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    env_model = os.getenv("LLM_MODEL", "openai/gpt-oss-120b")
    models_to_try = [env_model] + [m for m in CANDIDATE_MODELS if m != env_model]

    for model in models_to_try:
        try:
            payload = {
                "model": model,
                "messages": [
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": prompt}
                ],
                "max_tokens": 400
            }
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            if res.status_code == 200:
                data = res.json()
                answer = data["choices"][0]["message"]["content"]
                return {
                    "allowed": True,
                    "response": answer,
                    "topic_blocked": False
                }
        except Exception:
            continue

    return {
        "allowed": True,
        "response": "To protect yourself from phishing emails: 1. Verify sender domain addresses carefully. 2. Never click urgent links or open unexpected attachments. 3. Check for official HTTPS certificates and brand mismatches. 4. Enable Multi-Factor Authentication (MFA) on all critical accounts.",
        "topic_blocked": False
    }
