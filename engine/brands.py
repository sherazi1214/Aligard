"""Brand lookalike detection. brand token -> asli (official) registrable domains."""
from __future__ import annotations

import re

OFFICIAL: dict[str, set[str]] = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "gmail.com", "googlemail.com", "youtube.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.co.uk", "amazon.in", "amazonses.com"},
    "facebook": {"facebook.com", "fb.com", "facebookmail.com"},
    "instagram": {"instagram.com"},
    "netflix": {"netflix.com"},
    "daraz": {"daraz.pk"},
    "easypaisa": {"easypaisa.com.pk", "telenor.com.pk"},
    "jazzcash": {"jazzcash.com.pk", "jazz.com.pk"},
    "sadapay": {"sadapay.pk"},
    "nayapay": {"nayapay.com"},
    "meezan": {"meezanbank.com"},
    "hbl": {"hbl.com", "hblmicrofinance.com"},
    "ubl": {"ubldirect.com", "ubl.com.pk"},
    "mcb": {"mcb.com.pk"},
    "alfalah": {"bankalfalah.com"},
    "nadra": {"nadra.gov.pk"},
    "fbr": {"fbr.gov.pk"},
    "pta": {"pta.gov.pk"},
    "bisp": {"bisp.gov.pk"},
}

# Chhote tokens (hbl, ubl...) sirf poore token ke taur par match hon; lambe substring bhi.
_SUBSTRING_MIN = 5
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "@": "a", "$": "s"})


def _tokens(text: str) -> list[str]:
    folded = text.lower().translate(_LEET)
    return [t for t in re.split(r"[^a-z]+", folded) if t]


def brands_in(text: str) -> set[str]:
    found: set[str] = set()
    for tok in _tokens(text):
        for brand in OFFICIAL:
            if tok == brand or (len(brand) >= _SUBSTRING_MIN and brand in tok):
                found.add(brand)
    return found


def lookalike_brand(host: str, registrable: str) -> str | None:
    """Host mein brand ka naam ho magar domain asli na ho to us brand ka naam."""
    for brand in brands_in(host):
        if registrable not in OFFICIAL[brand]:
            return brand
    return None


def display_name_brand(display_name: str, sender_registrable: str) -> str | None:
    for brand in brands_in(display_name):
        if sender_registrable not in OFFICIAL[brand]:
            return brand
    return None
