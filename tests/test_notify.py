import hashlib
import hmac
import json

import httpx
import pytest

from app.notify import SIGNATURE_HEADER, WebhookNotifier
from app.store import MemoryAlertStore
from tests.conftest import make_alert

pytestmark = pytest.mark.anyio


async def stored(**kwargs):
    alert, _ = await MemoryAlertStore().save(make_alert(**kwargs))
    return alert


def notifier(handler, urls=("https://siem.example/hook",), **kwargs) -> WebhookNotifier:
    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    return WebhookNotifier(list(urls), client=client, backoff=0, **kwargs)


async def test_sends_signed_json():
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(204)

    alert = await stored(severity="critical")
    await notifier(handler, secret="s3cret").notify([alert])

    assert len(requests) == 1
    body = requests[0].content
    expected = "sha256=" + hmac.new(b"s3cret", body, hashlib.sha256).hexdigest()
    assert requests[0].headers[SIGNATURE_HEADER] == expected
    payload = json.loads(body)
    assert payload["type"] == "alert.created"
    assert payload["alert"]["id"] == alert.id


async def test_unsigned_without_secret():
    requests = []
    await notifier(lambda r: requests.append(r) or httpx.Response(200)).notify([await stored()])
    assert SIGNATURE_HEADER not in requests[0].headers


async def test_slack_urls_get_slack_format():
    requests = []
    hook = "https://hooks.slack.com/services/T000/B000/XXX"
    await notifier(lambda r: requests.append(r) or httpx.Response(200), urls=[hook]).notify(
        [await stored(severity="critical", listed=True)]
    )
    text = json.loads(requests[0].content)["text"]
    assert "🔴" in text and "T1110 Brute Force" in text and "feed-a" in text


async def test_below_min_severity_is_not_sent():
    requests = []
    n = notifier(lambda r: requests.append(r) or httpx.Response(200), min_severity="high")
    await n.notify([await stored(severity="medium"), await stored(severity="low", rule_id="x")])
    assert requests == []


async def test_every_url_gets_every_alert():
    requests = []
    n = notifier(lambda r: requests.append(r) or httpx.Response(200), urls=["https://a/x", "https://b/y"])
    await n.notify([await stored(), await stored(rule_id="other")])
    assert len(requests) == 4


async def test_retries_server_errors():
    responses = iter([httpx.Response(503), httpx.Response(502), httpx.Response(200)])
    n = notifier(lambda r: next(responses))
    assert await n._send(n.urls[0], await stored())


async def test_does_not_retry_client_errors():
    calls = []
    n = notifier(lambda r: calls.append(r) or httpx.Response(400))
    assert not await n._send(n.urls[0], await stored())
    assert len(calls) == 1


async def test_gives_up_without_raising():
    def handler(request):
        raise httpx.ConnectError("refused")

    n = notifier(handler, retries=2)
    assert not await n._send(n.urls[0], await stored())
    await n.notify([await stored()])  # must not raise either
