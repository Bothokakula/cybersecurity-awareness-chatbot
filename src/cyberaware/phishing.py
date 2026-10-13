"""Rule-based phishing message analyser.

This is an explainable heuristic, not a machine-learning classifier: each rule
that fires adds a weighted score and a plain-language explanation, so users
learn *why* a message looks suspicious. No message is sent anywhere; all
checks run locally.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit

URL_PATTERN = re.compile(
    r"(?:https?://|www\.)[^\s<>\"')\]]+"  # explicit links
    r"|\b(?:[a-z0-9-]+\.)+[a-z]{2,}/[^\s<>\"')\]]*",  # bare domains with a path, e.g. bit.ly/abc
    re.IGNORECASE,
)

URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "cutt.ly",
    "rebrand.ly",
    "shorturl.at",
    "tiny.cc",
    "rb.gy",
    "s.id",
}

SUSPICIOUS_TLDS = {
    "xyz",
    "top",
    "click",
    "zip",
    "mov",
    "icu",
    "buzz",
    "rest",
    "cam",
    "gq",
    "tk",
    "ml",
    "cf",
    "ga",
    "work",
    "support",
}

# Brands that are commonly impersonated, mapped to their official domains.
BRANDS: dict[str, tuple[str, ...]] = {
    "fnb": ("fnb.co.za",),
    "absa": ("absa.co.za",),
    "capitec": ("capitecbank.co.za",),
    "standardbank": ("standardbank.co.za",),
    "nedbank": ("nedbank.co.za",),
    "sars": ("sars.gov.za",),
    "takealot": ("takealot.com",),
    "vodacom": ("vodacom.co.za",),
    "paypal": ("paypal.com",),
    "netflix": ("netflix.com",),
    "microsoft": ("microsoft.com", "live.com", "office.com"),
    "apple": ("apple.com", "icloud.com"),
    "dhl": ("dhl.com", "dhl.co.za"),
}

# (name, weight, explanation, keyword patterns)
TEXT_RULES: list[tuple[str, int, str, list[str]]] = [
    (
        "Asks for sensitive details",
        25,
        "Legitimate organisations never ask for your OTP, PIN, password or full card details by message.",
        [
            r"\botp\b",
            r"one[- ]time (pin|password)",
            r"\bpin\b",
            r"password",
            r"\bcvv\b",
            r"card (number|details)",
            r"banking details",
            r"login details",
            r"verify your (account|identity|details)",
            r"confirm your (account|details|identity)",
            r"verification code",
        ],
    ),
    (
        "Creates urgency",
        15,
        "Pressure to act fast is designed to stop you from thinking or checking.",
        [
            r"\burgent",
            r"immediately",
            r"within \d+ ?(hours|hrs|minutes|mins)",
            r"act now",
            r"final (notice|warning)",
            r"expires? (today|soon)",
            r"last chance",
            r"as soon as possible",
            r"\btoday only\b",
            r"on hold",
            r"failed delivery",
            r"unable to deliver",
        ],
    ),
    (
        "Uses threats",
        15,
        "Threats of suspension, fines or arrest are a classic scare tactic.",
        [
            r"suspend",
            r"\bblocked\b",
            r"deactivat",
            r"legal action",
            r"\barrest",
            r"penalt",
            r"\bfined?\b",
            r"locked out",
            r"will be (closed|terminated)",
        ],
    ),
    (
        "Promises a prize or refund",
        15,
        "Unexpected winnings, refunds or rewards are bait.",
        [
            r"you('ve| have)? won",
            r"\bwinner\b",
            r"\bprize\b",
            r"\breward\b",
            r"\brefund\b",
            r"claim (your|now)",
            r"free (gift|data|airtime|voucher)",
            r"congratulations",
            r"you('ve| have)? been selected",
        ],
    ),
    (
        "Requests payment",
        10,
        "Requests for fees, gift cards or crypto are common in scams.",
        [
            r"delivery fee",
            r"customs fee",
            r"outstanding (amount|balance)",
            r"gift ?cards?",
            r"bitcoin|crypto",
            r"pay (now|a fee|the fee)",
            r"\bR ?\d+[.,]?\d*\b.*\b(fee|payment)\b",
            r"proof of payment",
        ],
    ),
    (
        "Generic greeting",
        10,
        "Real organisations usually address you by name.",
        [r"dear (customer|client|user|valued|sir|madam|account holder)"],
    ),
]


@dataclass
class Flag:
    name: str
    weight: int
    detail: str


@dataclass
class PhishingReport:
    score: int
    level: str
    flags: list[Flag] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)


def contains_url(text: str) -> bool:
    return bool(URL_PATTERN.search(text))


def extract_urls(text: str) -> list[str]:
    return [m.group(0).rstrip(".,;:!?") for m in URL_PATTERN.finditer(text)]


def _host(url: str) -> str:
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.IGNORECASE):
        url = "http://" + url
    return (urlsplit(url).hostname or "").lower()


def _is_official(host: str, domains: tuple[str, ...]) -> bool:
    return any(host == d or host.endswith("." + d) for d in domains)


def _url_flags(urls: list[str], text: str) -> list[Flag]:
    flags: dict[str, Flag] = {}

    def add(name: str, weight: int, detail: str) -> None:
        flags.setdefault(name, Flag(name, weight, detail))

    # Look for brand names in the wording only, not inside the links themselves.
    lowered_text = URL_PATTERN.sub(" ", text).lower().replace("standard bank", "standardbank")
    mentioned_brands = [b for b in BRANDS if re.search(rf"\b{b}\b", lowered_text)]

    for url in urls:
        host = _host(url)
        if not host:
            continue
        squashed = host.replace("-", "").replace(".", "")

        if host in URL_SHORTENERS:
            add("Shortened link", 15, f"`{host}` hides the real destination of the link.")

        try:
            ipaddress.ip_address(host)
            add("Link uses an IP address", 25, f"`{host}` is a raw IP address instead of a company website.")
        except ValueError:
            pass

        if "xn--" in host:
            add("Look-alike characters", 20, f"`{host}` uses encoded characters that can imitate real letters.")

        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            add("Hidden destination", 20, "An `@` in a link can disguise where it really goes.")

        if url.lower().startswith("http://"):
            add("Not encrypted (http)", 10, "The link doesn't use HTTPS.")

        tld = host.rsplit(".", 1)[-1]
        if tld in SUSPICIOUS_TLDS:
            add("Unusual domain ending", 15, f"`.{tld}` domains are cheap and often used for throwaway scam sites.")

        if host.count(".") >= 4:
            add("Many subdomains", 10, f"`{host}` stacks subdomains to look official.")

        for brand, domains in BRANDS.items():
            if brand in squashed and not _is_official(host, domains):
                add(
                    "Imitates a known brand",
                    30,
                    f"`{host}` contains **{brand}** but isn't an official {brand} domain ({', '.join(domains)}).",
                )

        for brand in mentioned_brands:
            if not _is_official(host, BRANDS[brand]) and host not in URL_SHORTENERS:
                add(
                    "Link doesn't match sender",
                    20,
                    f"The message mentions **{brand}**, but the link goes to `{host}`.",
                )

    return list(flags.values())


def analyse_message(text: str) -> PhishingReport:
    """Score a message from 0 (no red flags found) to 100 (many red flags)."""
    lowered = text.lower()
    flags: list[Flag] = []

    for name, weight, detail, patterns in TEXT_RULES:
        if any(re.search(p, lowered) for p in patterns):
            flags.append(Flag(name, weight, detail))

    urls = extract_urls(text)
    flags.extend(_url_flags(urls, text))

    asks_for_action = {"Asks for sensitive details", "Requests payment", "Promises a prize or refund"}
    if urls and any(f.name in asks_for_action for f in flags):
        flags.append(
            Flag(
                "Pushes you to a link",
                10,
                "It combines a request (details, payment or a prize) with a link to act on, which is "
                "the core pattern of phishing.",
            )
        )

    score = min(100, sum(f.weight for f in flags))
    level = "High" if score >= 50 else "Medium" if score >= 20 else "Low"
    flags.sort(key=lambda f: f.weight, reverse=True)
    return PhishingReport(score=score, level=level, flags=flags, urls=urls)


LEVEL_ICONS = {"High": "🔴", "Medium": "🟠", "Low": "🟢"}


def format_report(report: PhishingReport) -> str:
    lines = [f"### {LEVEL_ICONS[report.level]} {report.level} risk ({report.score}/100)"]
    if report.flags:
        lines.append("**Red flags found:**")
        lines.extend(f"- **{f.name}**: {f.detail}" for f in report.flags)
    else:
        lines.append("I didn't find common red flags, but that doesn't guarantee the message is safe.")
    lines.append(
        "\n_This is an automated heuristic check. If in doubt, contact the organisation "
        "through its official app, website or phone number, not the details in the message._"
    )
    return "\n".join(lines)
