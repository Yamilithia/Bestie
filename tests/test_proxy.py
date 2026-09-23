from __future__ import annotations

import json
import re

import httpx
import pytest
from conftest import DICTIONARY, FIXTURES, SENSITIVE
from fastapi.testclient import TestClient

from bestie.config import Settings, write_dictionary
from bestie.proxy.app import create_app

ALERT = (FIXTURES / "edr_alert.json").read_text()
REAL = SENSITIVE["edr_alert.json"]


class ChunkedStream(httpx.AsyncByteStream):
    def __init__(self, chunks: list[bytes]) -> None:
        self.chunks = chunks

    async def __aiter__(self):
        for c in self.chunks:
            yield c


class FakeAnthropic:
    """Captures what Bestie sends upstream and answers with a canned reply that
    references the tokens it received."""

    def __init__(self, chunk_size: int = 7) -> None:
        self.requests: list[dict] = []
        self.headers: list[httpx.Headers] = []
        self.chunk_size = chunk_size
        self.override = None

    def reply_text(self, body: dict) -> str:
        sent = json.dumps(body)
        tokens = sorted(set(re.findall(r"(?:HOST|IP|USER|DOMAIN|ORG)_\d{3}", sent)))
        return "Isolate " + ", ".join(tokens) + "."

    def __call__(self, request: httpx.Request) -> httpx.Response:
        if self.override is not None:
            return self.override(request)
        body = json.loads(request.content)
        self.requests.append(body)
        self.headers.append(request.headers)
        text = self.reply_text(body)
        tool_input = {"command": "ping HOST_001", "target": "ORG_001\\USER_001"}
        if not body.get("stream"):
            return httpx.Response(
                200,
                json={
                    "id": "msg_1",
                    "type": "message",
                    "role": "assistant",
                    "model": body["model"],
                    "content": [
                        {"type": "text", "text": text},
                        {"type": "tool_use", "id": "toolu_1", "name": "shell", "input": tool_input},
                    ],
                    "stop_reason": "end_turn",
                    "usage": {"input_tokens": 1, "output_tokens": 1},
                },
            )
        events = [
            (
                "message_start",
                {
                    "type": "message_start",
                    "message": {
                        "id": "msg_1",
                        "type": "message",
                        "role": "assistant",
                        "content": [],
                        "model": body["model"],
                        "usage": {"input_tokens": 1, "output_tokens": 0},
                    },
                },
            ),
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                },
            ),
        ]
        step = 5
        for i in range(0, len(text), step):
            events.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": 0,
                        "delta": {"type": "text_delta", "text": text[i : i + step]},
                    },
                )
            )
        events.append(("content_block_stop", {"type": "content_block_stop", "index": 0}))
        events.append(
            (
                "content_block_start",
                {
                    "type": "content_block_start",
                    "index": 1,
                    "content_block": {
                        "type": "tool_use",
                        "id": "toolu_1",
                        "name": "shell",
                        "input": {},
                    },
                },
            )
        )
        raw = json.dumps(tool_input)
        for i in range(0, len(raw), 4):
            events.append(
                (
                    "content_block_delta",
                    {
                        "type": "content_block_delta",
                        "index": 1,
                        "delta": {"type": "input_json_delta", "partial_json": raw[i : i + 4]},
                    },
                )
            )
        events.append(("content_block_stop", {"type": "content_block_stop", "index": 1}))
        events.append(("message_stop", {"type": "message_stop"}))
        payload = "".join(f"event: {n}\ndata: {json.dumps(d)}\n\n" for n, d in events).encode()
        chunks = [payload[i : i + self.chunk_size] for i in range(0, len(payload), self.chunk_size)]
        return httpx.Response(
            200, headers={"content-type": "text/event-stream"}, stream=ChunkedStream(chunks)
        )


@pytest.fixture
def setup(tmp_path):
    settings = Settings(home=tmp_path, api_key="sk-ant-real-key")
    write_dictionary(settings.dictionary_path, DICTIONARY)
    fake = FakeAnthropic()
    app = create_app(settings, transport=httpx.MockTransport(fake))
    with TestClient(app) as client:
        yield client, fake, settings


def request_body(**extra) -> dict:
    return {
        "model": "claude-sonnet-5",
        "max_tokens": 100,
        "system": "You are assisting the Acme SOC.",
        "messages": [
            {"role": "user", "content": [{"type": "text", "text": "Triage this alert:\n" + ALERT}]}
        ],
        **extra,
    }


def assert_clean(sent: dict) -> None:
    blob = json.dumps(sent, ensure_ascii=False).lower()
    for value in REAL:
        assert value.lower() not in blob, f"{value!r} reached upstream"


def test_non_streaming_round_trip(setup):
    client, fake, _ = setup
    resp = client.post(
        "/v1/messages",
        json=request_body(),
        headers={"x-api-key": "bestie", "anthropic-version": "2023-06-01"},
    )
    assert resp.status_code == 200, resp.text
    assert_clean(fake.requests[0])
    assert fake.headers[0]["x-api-key"] == "sk-ant-real-key"
    content = resp.json()["content"]
    assert "WKS-FIN-042" in content[0]["text"]
    assert "10.20.4.17" in content[0]["text"]
    # Case-insensitive types restore to their first-seen spelling ("Acme" here).
    assert content[1]["input"] == {"command": "ping WKS-FIN-042", "target": "Acme\\jdoe"}


def test_streaming_round_trip(setup):
    client, fake, _ = setup
    with client.stream("POST", "/v1/messages", json=request_body(stream=True)) as resp:
        assert resp.status_code == 200
        raw = b"".join(resp.iter_bytes()).decode()
    assert_clean(fake.requests[0])
    text, partial_json = "", ""
    for block in raw.split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data:"):
                data = json.loads(line[5:])
                delta = data.get("delta") or {}
                text += delta.get("text", "")
                partial_json += delta.get("partial_json", "")
    assert "WKS-FIN-042" in text and "10.20.4.17" in text
    assert "HOST_" not in text
    assert json.loads(partial_json) == {"command": "ping WKS-FIN-042", "target": "Acme\\jdoe"}


def test_multi_turn_history_is_re_redacted_consistently(setup):
    client, fake, _ = setup
    first = client.post("/v1/messages", json=request_body()).json()
    body = request_body()
    body["messages"] += [
        {"role": "assistant", "content": first["content"]},
        {
            "role": "user",
            "content": [
                {
                    "type": "tool_result",
                    "tool_use_id": "toolu_1",
                    "content": "Reply from 10.20.4.17: bytes=32",
                }
            ],
        },
    ]
    client.post("/v1/messages", json=body)
    second = fake.requests[1]
    assert_clean(second)
    assistant = second["messages"][1]["content"]
    assert assistant[1]["input"] == {"command": "ping HOST_001", "target": "ORG_001\\USER_001"}
    assert second["messages"][2]["content"][0]["content"] == "Reply from IP_001: bytes=32"


def test_image_blocked_fail_closed(setup):
    client, fake, _ = setup
    body = request_body()
    body["messages"][0]["content"].append(
        {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAA"}}
    )
    resp = client.post("/v1/messages", json=body)
    assert resp.status_code == 400
    assert resp.json()["error"]["message"].startswith("[Bestie]")
    assert fake.requests == []


def test_unsupported_endpoint_blocked(setup):
    client, fake, _ = setup
    resp = client.post("/v1/messages/batches", json={"requests": [{"params": request_body()}]})
    assert resp.status_code == 404
    assert fake.requests == []


def test_named_vault_header_isolates_mappings(setup):
    client, fake, settings = setup
    client.post("/v1/messages", json=request_body(), headers={"x-bestie-vault": "IR-1"})
    client.post(
        "/v1/messages",
        json={
            "model": "m",
            "max_tokens": 5,
            "messages": [{"role": "user", "content": "10.99.99.99 then 10.20.4.17"}],
        },
        headers={"x-bestie-vault": "IR-2"},
    )
    assert fake.requests[1]["messages"][0]["content"] == "IP_001 then IP_002"
    assert settings.vault_path("IR-1").exists() and settings.vault_path("IR-2").exists()


def test_audit_log_has_no_values(setup):
    client, _, settings = setup
    client.post("/v1/messages", json=request_body())
    log = settings.audit_path.read_text()
    assert '"forwarded"' in log
    for value in REAL:
        assert value.lower() not in log.lower()


def test_thinking_signature_preserved(setup):
    client, fake, _ = setup

    def reply(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        fake.requests.append(body)
        return httpx.Response(
            200,
            json={
                "id": "m",
                "type": "message",
                "role": "assistant",
                "model": "m",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": "HOST_001 looks compromised; maybe 45.1.2.3 too",
                        "signature": "sig123",
                    },
                    {"type": "text", "text": "done"},
                ],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 1, "output_tokens": 1},
            },
        )

    fake.override = reply
    first = client.post("/v1/messages", json=request_body()).json()
    assert "WKS-FIN-042 looks compromised" in first["content"][0]["thinking"]
    body = request_body()
    body["messages"] += [
        {"role": "assistant", "content": first["content"]},
        {"role": "user", "content": "go on"},
    ]
    resp = client.post("/v1/messages", json=body)
    assert resp.status_code == 200, resp.text
    # The signed thinking goes back exactly as the model wrote it.
    sent_thinking = fake.requests[-1]["messages"][1]["content"][0]["thinking"]
    assert sent_thinking == "HOST_001 looks compromised; maybe 45.1.2.3 too"
