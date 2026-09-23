from __future__ import annotations

from bestie.stream import StreamRehydrator
from bestie.tokens import partial_token_start


def test_partial_token_start():
    assert partial_token_start("see HOST_0") == 4
    assert partial_token_start("see HOS") == 4
    assert partial_token_start("see HOST_001") == 4  # digits may continue
    assert partial_token_start("see the") is None
    assert partial_token_start("see XYZ_1") is None
    assert partial_token_start("fooHOST_") is None


def test_every_split_point(redactor):
    redactor.redact("dc01.corp.acme.com 10.20.4.17 ACME\\jdoe")
    tokenized = "Isolate HOST_001.DOMAIN_001 (IP_001), reset ORG_001\\USER_001 now."
    expected = redactor.rehydrate(tokenized)
    for i in range(len(tokenized) + 1):
        for j in range(i, len(tokenized) + 1):
            s = StreamRehydrator(redactor.rehydrate)
            out = s.feed(tokenized[:i]) + s.feed(tokenized[i:j]) + s.feed(tokenized[j:])
            out += s.flush()
            assert out == expected, (i, j)


def test_char_by_char(redactor):
    redactor.redact("10.20.4.17")
    s = StreamRehydrator(redactor.rehydrate)
    text = "IP_001 is IP_001"
    out = "".join(s.feed(c) for c in text) + s.flush()
    assert out == "10.20.4.17 is 10.20.4.17"
