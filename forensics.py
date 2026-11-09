"""Domain forensics: how old is a domain? New domains are a strong scam signal.

Uses the public RDAP service (rdap.org), which needs no key. Failures return
"unknown" instead of raising, so the site keeps working if the lookup is down.
"""
import datetime as dt
import functools
import re

import requests

_HOST_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}$")
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu", "nic"}


def registrable(host: str) -> str:
    parts = host.lower().strip(".").removeprefix("www.").split(".")
    if len(parts) >= 3 and parts[-2] in _SECOND_LEVEL:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def valid_host(host: str) -> bool:
    return bool(_HOST_RE.match(host))


@functools.lru_cache(maxsize=512)
def _registration_date(domain: str):
    r = requests.get(f"https://rdap.org/domain/{domain}", timeout=6,
                     headers={"Accept": "application/rdap+json"})
    if r.status_code != 200:
        return None
    for ev in r.json().get("events", []):
        if ev.get("eventAction") == "registration" and ev.get("eventDate"):
            return ev["eventDate"][:10]
    return None


def check_domain(host: str) -> dict:
    domain = registrable(host)
    out = {"domain": domain, "registered": None, "age_days": None, "verdict": "unknown",
           "note": "Couldn't find registration details for this domain."}
    if not valid_host(domain):
        return out
    try:
        date = _registration_date(domain)
    except Exception:
        return out
    if not date:
        return out
    try:
        age = (dt.date.today() - dt.date.fromisoformat(date)).days
    except ValueError:
        return out
    out.update(registered=date, age_days=age)
    if age < 90:
        out.update(verdict="very_new", note=f"Registered only {age} days ago. Scam sites are usually brand new; established employers' domains are years old.")
    elif age < 365:
        out.update(verdict="new", note=f"Registered {age} days ago (under a year). Be extra careful and verify the company.")
    else:
        out.update(verdict="established", note=f"Registered {age // 365} year(s) ago. Age alone doesn't make a domain trustworthy, but new ones are riskier.")
    return out
