"""Breach detection module — free XposedOrNot API."""

import requests
from typing import Dict
from .models import BreachResult


def check_breach(email: str) -> BreachResult:
    """Check email against XposedOrNot breach database (free, no API key).

    Args:
        email: Email address to check.

    Returns:
        BreachResult with findings.
    """
    try:
        resp = requests.get(
            "https://api.xposedornot.com/v1/breach-analytics",
            params={"email": email},
            timeout=10,
        )
        if resp.status_code != 200:
            return BreachResult(error=f"HTTP {resp.status_code}")

        data = resp.json()
        breaches_raw = data.get("BreachesSummary", {}).get("site", "")
        if not breaches_raw:
            return BreachResult()

        breach_list = breaches_raw.split(";")
        risk = (
            data.get("BreachMetrics", {})
            .get("risk", [{}])[0]
            .get("risk_score", 0)
        )

        return BreachResult(
            found=True,
            count=len(breach_list),
            breaches=breach_list[:10],
            risk_score=risk,
        )

    except requests.RequestException as e:
        return BreachResult(error=f"Request failed: {e}")
    except (ValueError, KeyError, IndexError, TypeError, AttributeError) as e:
        return BreachResult(error=f"Parse failed: {e}")
