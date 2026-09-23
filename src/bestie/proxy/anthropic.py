"""Apply redaction / restoration to Anthropic Messages API payloads."""

from __future__ import annotations

import codecs
import copy
import json
from collections import Counter, OrderedDict
from collections.abc import Iterator
from dataclasses import dataclass, field

from ..redactor import Redactor
from ..stream import StreamRehydrator

# Keys whose values are protocol structure, never user content.
STRUCTURAL_KEYS = frozenset(
    {
        "type",
        "id",
        "tool_use_id",
        "signature",
        "media_type",
        "cache_control",
        "role",
        "name",
        "encrypted_content",
        "encrypted_index",
        "file_id",
        "citations_enabled",
    }
)


class Blocked(Exception):
    """Request refused before anything was sent upstream."""


class ThinkingCache:
    """Thinking blocks are signed by the API over the *tokenized* text. We keep the
    original (tokenized) text by signature so it can be sent back unchanged."""

    def __init__(self, size: int = 2048) -> None:
        self._data: OrderedDict[str, str] = OrderedDict()
        self._size = size

    def put(self, signature: str | None, thinking: str) -> None:
        if not signature:
            return
        self._data[signature] = thinking
        self._data.move_to_end(signature)
        while len(self._data) > self._size:
            self._data.popitem(last=False)

    def get(self, signature: str | None) -> str | None:
        return self._data.get(signature) if signature else None


@dataclass
class RedactionResult:
    body: dict
    stats: Counter = field(default_factory=Counter)
    # Strings that left the machine and must pass the deep leak check.
    outgoing: list[str] = field(default_factory=list)
    # Model-authored text restored from cache: known-value check only.
    passthrough: list[str] = field(default_factory=list)


class RequestRedactor:
    def __init__(
        self, redactor: Redactor, thinking: ThinkingCache, *, allow_binary: bool = False
    ) -> None:
        self.r = redactor
        self.thinking = thinking
        self.allow_binary = allow_binary

    def redact(self, body: dict) -> RedactionResult:
        body = copy.deepcopy(body)
        self._res = res = RedactionResult(body)
        if "system" in body:
            body["system"] = self._content(body["system"])
        for message in body.get("messages") or []:
            if isinstance(message, dict) and "content" in message:
                message["content"] = self._content(message["content"])
        for tool in body.get("tools") or []:
            if isinstance(tool, dict):
                self._tool(tool)
        if isinstance(body.get("stop_sequences"), list):
            body["stop_sequences"] = [self._text(s) for s in body["stop_sequences"]]
        return res

    # -- helpers ---------------------------------------------------------
    def _text(self, value):
        if not isinstance(value, str):
            return value
        out = self.r.redact(value, self._res.stats)
        self._res.outgoing.append(out)
        return out

    def _deep(self, value, skip=STRUCTURAL_KEYS):
        if isinstance(value, str):
            return self._text(value)
        if isinstance(value, list):
            return [self._deep(v, skip) for v in value]
        if isinstance(value, dict):
            return {k: (v if k in skip else self._deep(v, skip)) for k, v in value.items()}
        return value

    def _content(self, content):
        if isinstance(content, str):
            return self._text(content)
        if isinstance(content, list):
            return [self._block(b) for b in content]
        return content

    def _binary(self, what: str) -> None:
        if not self.allow_binary:
            raise Blocked(
                f"{what} content can't be inspected for sensitive data, so Bestie blocked "
                "it. Paste the text instead, or set allow_binary: true in config.yaml."
            )

    def _block(self, block):
        if not isinstance(block, dict):
            return self._deep(block)
        kind = block.get("type")
        if kind == "text":
            block["text"] = self._text(block.get("text"))
            if "citations" in block:
                block["citations"] = self._deep(block["citations"])
            return block
        if kind in ("image", "document"):
            source = block.get("source") or {}
            stype = source.get("type")
            if kind == "document" and stype == "text":
                source["data"] = self._text(source.get("data"))
            elif kind == "document" and stype == "content":
                source["content"] = self._content(source.get("content"))
            else:
                self._binary(f"{kind} ({stype or 'unknown'} source)")
            for key in ("title", "context"):
                if key in block:
                    block[key] = self._text(block[key])
            return block
        if kind == "tool_result":
            if "content" in block:
                block["content"] = self._content(block["content"])
            return block
        if kind == "thinking":
            original = self.thinking.get(block.get("signature"))
            if original is not None:
                block["thinking"] = original
                self._res.passthrough.append(original)
            else:
                block["thinking"] = self._text(block.get("thinking"))
            return block
        if kind == "redacted_thinking":
            return block  # opaque, encrypted by the API
        if kind in ("tool_use", "server_tool_use") and "input" in block:
            block["input"] = self._deep(block["input"], skip=frozenset())
        # tool_use, server tool blocks, search results, unknown future blocks:
        # redact every non-structural string.
        return self._deep(block)

    def _tool(self, tool: dict) -> None:
        if "description" in tool:
            tool["description"] = self._text(tool["description"])
        if "input_schema" in tool:
            tool["input_schema"] = self._schema(tool["input_schema"])

    def _schema(self, node):
        if isinstance(node, list):
            return [self._schema(v) for v in node]
        if not isinstance(node, dict):
            return node
        out = {}
        for k, v in node.items():
            if k in ("description", "title", "examples", "default", "enum", "const"):
                out[k] = self._deep(v)
            else:
                out[k] = self._schema(v)
        return out


# ------------------------------------------------------------------ responses

_RESPONSE_SKIP = STRUCTURAL_KEYS | {"data", "model", "stop_reason", "stop_sequence"}


def _rehydrate_deep(r: Redactor, value, skip=_RESPONSE_SKIP):
    if isinstance(value, str):
        return r.rehydrate(value)
    if isinstance(value, list):
        return [_rehydrate_deep(r, v, skip) for v in value]
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k == "input" and value.get("type") in ("tool_use", "server_tool_use"):
                out[k] = _rehydrate_deep(r, v, frozenset())  # tool arguments: all user data
            elif k in skip:
                out[k] = v
            else:
                out[k] = _rehydrate_deep(r, v, skip)
        return out
    return value


def rehydrate_response(r: Redactor, body: dict, thinking: ThinkingCache) -> dict:
    for block in body.get("content") or []:
        if isinstance(block, dict) and block.get("type") == "thinking":
            thinking.put(block.get("signature"), block.get("thinking", ""))
    if "content" in body:
        body["content"] = _rehydrate_deep(r, body["content"])
    if "error" in body:
        body["error"] = _rehydrate_deep(r, body["error"])
    return body


class _Block:
    def __init__(self, r: Redactor, kind: str) -> None:
        self.kind = kind
        escape = kind in ("tool_use", "server_tool_use")
        self.stream = StreamRehydrator(lambda s: r.rehydrate(s, json_escape=escape))
        self.raw_thinking: list[str] = []


_DELTA_FIELDS = {
    "text_delta": "text",
    "thinking_delta": "thinking",
    "input_json_delta": "partial_json",
}
_FLUSH_DELTA = {
    "text": "text_delta",
    "thinking": "thinking_delta",
    "tool_use": "input_json_delta",
    "server_tool_use": "input_json_delta",
}


class SSERewriter:
    """Parses the upstream SSE byte stream and re-emits it with tokens restored."""

    def __init__(self, r: Redactor, thinking: ThinkingCache) -> None:
        self.r = r
        self.thinking = thinking
        self._decoder = codecs.getincrementaldecoder("utf-8")()
        self._buf = ""
        self._blocks: dict[int, _Block] = {}

    def feed(self, chunk: bytes) -> Iterator[bytes]:
        self._buf += self._decoder.decode(chunk).replace("\r\n", "\n")
        while "\n\n" in self._buf:
            raw, self._buf = self._buf.split("\n\n", 1)
            yield from self._event(raw)

    def close(self) -> Iterator[bytes]:
        self._buf += self._decoder.decode(b"", final=True)
        if self._buf.strip():
            yield from self._event(self._buf)
        self._buf = ""

    @staticmethod
    def _emit(name: str | None, data: dict) -> bytes:
        head = f"event: {name}\n" if name else ""
        return f"{head}data: {json.dumps(data, ensure_ascii=False)}\n\n".encode()

    def _event(self, raw: str) -> Iterator[bytes]:
        name, data_lines = None, []
        for line in raw.split("\n"):
            if line.startswith("event:"):
                name = line[6:].strip()
            elif line.startswith("data:"):
                data_lines.append(line[5:].lstrip())
        try:
            data = json.loads("\n".join(data_lines))
        except ValueError:
            yield (raw + "\n\n").encode()
            return
        if not isinstance(data, dict):
            yield (raw + "\n\n").encode()
            return
        etype = data.get("type")
        if etype == "content_block_start":
            block = data.get("content_block") or {}
            self._blocks[data.get("index", 0)] = _Block(self.r, block.get("type", "text"))
            data["content_block"] = _rehydrate_deep(self.r, block)
        elif etype == "content_block_delta":
            state = self._blocks.get(data.get("index", 0))
            delta = data.get("delta") or {}
            dtype = delta.get("type")
            fld = _DELTA_FIELDS.get(dtype)
            if state is not None and fld:
                piece = delta.get(fld, "")
                if dtype == "thinking_delta":
                    state.raw_thinking.append(piece)
                delta[fld] = state.stream.feed(piece)
                if not delta[fld]:
                    return  # held back until the token completes
            elif state is not None and dtype == "signature_delta":
                self.thinking.put(delta.get("signature"), "".join(state.raw_thinking))
            else:
                data["delta"] = _rehydrate_deep(self.r, delta)
        elif etype == "content_block_stop":
            state = self._blocks.pop(data.get("index", 0), None)
            if state is not None:
                rest = state.stream.flush()
                dtype = _FLUSH_DELTA.get(state.kind, "text_delta")
                if rest:
                    delta = {"type": dtype, _DELTA_FIELDS[dtype]: rest}
                    yield self._emit(
                        "content_block_delta",
                        {
                            "type": "content_block_delta",
                            "index": data.get("index", 0),
                            "delta": delta,
                        },
                    )
        elif etype == "error":
            data = _rehydrate_deep(self.r, data)
        yield self._emit(name, data)
