import html as _html

from atar.dashboard import render_dashboard_html


def test_dashboard_escapes_agent_name_xss():
    """Regression: a malicious agent name must NOT execute as HTML (stored XSS)."""
    evil_name = "<script>alert('xss')</script>"
    net = {
        "agents": {evil_name: "did:agent:AAAA", "bob": "did:agent:BBBB"},
        "seed_did": "did:agent:AAAA",
        "vouches": [
            {
                "payload": {
                    "type": "vouch",
                    "issuer": "did:agent:AAAA",
                    "subject": "did:agent:BBBB",
                    "score": 0.9,
                    "scope": "intelligence",
                    "claim": None,
                    "ts": 1,
                },
                "signature": "deadbeef",
            },
        ],
    }
    out = render_dashboard_html(net, scope="intelligence")
    # the raw script tag must be escaped, not present literally
    assert "<script>alert('xss')</script>" not in out
    assert _html.escape(evil_name) in out


def test_dashboard_escapes_did_field():
    """Regression: a DID containing HTML markup is escaped, not rendered raw.
    The seed DID is rendered verbatim in the dashboard, so we put the evil
    markup there."""
    evil_did = 'did:agent:BBBB"><img src=x onerror=alert(1)>'
    net = {
        "agents": {"bob": evil_did},
        "seed_did": evil_did,
        "vouches": [],
    }
    out = render_dashboard_html(net, scope="intelligence")
    assert "<img src=x onerror=alert(1)>" not in out
    assert "&lt;img" in out
