"""Webhook notifications for new alerts.

Only newly created alerts at or above the minimum severity are sent --
deduplicated repeats don't re-notify. Slack incoming-webhook URLs get a
Slack-formatted message; any other URL gets the alert as JSON.

If a secret is configured, each request carries
`X-MiniSIEM-Signature: sha256=<hex HMAC of the body>` so receivers can verify
the alert really came from this SIEM (see scripts/webhook_receiver.py).
"""

import asyncio
import hashlib
import hmac
import json
import logging

import httpx

from app.scoring import severity_at_least
from app.store import StoredAlert

log = logging.getLogger("mini-siem.notify")

SIGNATURE_HEADER = "X-MiniSIEM-Signature"
SEVERITY_EMOJI = {"low": "🔵", "medium": "🟡", "high": "🟠", "critical": "🔴"}


def sign(body: bytes, secret: str) -> str:
    return "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def slack_payload(alert: StoredAlert) -> dict:
    techniques = ", ".join(f"{t.id} {t.name}" for t in alert.mitre)
    lines = [
        f"{SEVERITY_EMOJI[alert.severity]} *{alert.title}* (risk {alert.risk_score}/100)",
        f"*Host:* {alert.host or '-'}   *Rule:* `{alert.rule_id}`",
        f"*MITRE ATT&CK:* {techniques}",
    ]
    if alert.source.ip:
        geo = f" ({alert.source.geo.country})" if alert.source.geo and alert.source.geo.country else ""
        lines.append(f"*Source:* {alert.source.ip}{geo}")
    if alert.threat.listed:
        lines.append(f"*Threat intel:* {', '.join(alert.threat.feeds)}")
    return {"text": "\n".join(lines)}


class WebhookNotifier:
    def __init__(
        self,
        urls: list[str],
        min_severity: str = "high",
        secret: str | None = None,
        retries: int = 3,
        backoff: float = 0.5,
        client: httpx.AsyncClient | None = None,
    ):
        self.urls = urls
        self.min_severity = min_severity
        self.secret = secret
        self.retries = retries
        self.backoff = backoff
        self._client = client or httpx.AsyncClient(timeout=5.0)

    async def notify(self, alerts: list[StoredAlert]) -> None:
        sends = [
            self._send(url, alert)
            for alert in alerts
            if severity_at_least(alert.severity, self.min_severity)
            for url in self.urls
        ]
        await asyncio.gather(*sends)

    async def _send(self, url: str, alert: StoredAlert) -> bool:
        if "hooks.slack.com" in url:
            payload = slack_payload(alert)
        else:
            payload = {"type": "alert.created", "alert": alert.model_dump(mode="json")}
        body = json.dumps(payload).encode()
        headers = {"Content-Type": "application/json"}
        if self.secret:
            headers[SIGNATURE_HEADER] = sign(body, self.secret)

        for attempt in range(self.retries):
            try:
                response = await self._client.post(url, content=body, headers=headers)
                if response.status_code < 400:
                    return True
                if response.status_code < 500:  # client errors won't fix themselves
                    log.error("webhook %s rejected alert %s: HTTP %d", url, alert.id, response.status_code)
                    return False
            except httpx.HTTPError as exc:
                log.warning("webhook %s attempt %d failed: %s", url, attempt + 1, exc)
            if attempt + 1 < self.retries:
                await asyncio.sleep(self.backoff * 2**attempt)
        log.error("webhook %s gave up on alert %s after %d attempts", url, alert.id, self.retries)
        return False

    async def close(self) -> None:
        await self._client.aclose()
