"""Know-Your-Agent dashboard — the value layer *above* the ATAR protocol.

Renders your private trust network as a dark, corporate HTML page
(near-black bg, gift-green accents, GitHub-blue DIDs).
This is the application that captures value while the ATAR protocol itself
stays free — the Google/FB model: own the surface, give away the pipes.

Private, local, $0. No server required; open the file in any browser.
"""

from __future__ import annotations

from atar.transparency import graph_from_vouches

# ATAR design tokens — dark theme with gift-green + GitHub-blue.
_CSS = """
:root{--bg:#0a0a0b;--card:#141416;--accent:#39ff14;--accent-dim:#1f7a12;
--accent-blue:#2f81f7;--text:#e8e8ea;--muted:#8a8a90;}
*{box-sizing:border-box;}
body{margin:0;background:var(--bg);color:var(--text);
font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;
line-height:1.5;-webkit-font-smoothing:antialiased;}
.wrap{max-width:640px;margin:0 auto;padding:20px 16px 48px;}
.hero{text-align:center;padding:32px 0 24px;border-bottom:1px solid #222;}
.hero h1{margin:0;font-size:26px;letter-spacing:1px;font-weight:800;}
.hero .brand{color:var(--accent);text-transform:uppercase;font-size:13px;
letter-spacing:4px;}
.hero .sub{color:var(--muted);font-size:13px;margin-top:6px;}
.card{background:var(--card);border:1px solid #222;border-radius:14px;
margin:18px 0;overflow:hidden;}
.card-head{display:flex;align-items:center;justify-content:space-between;
padding:16px 18px;background:linear-gradient(90deg,#161,#0f0f11);
border-bottom:1px solid #222;}
.card-head h2{margin:0;font-size:18px;font-weight:700;}
.badge{font-size:11px;color:var(--accent);border:1px solid var(--accent-dim);
border-radius:999px;padding:2px 10px;text-transform:uppercase;letter-spacing:1px;}
.badge.revoked{color:#ff4d4d;border-color:#5c1a1a;background:#1a0808;}
.card.revoked{border-color:#5c1a1a;box-shadow:0 0 14px rgba(255,77,77,0.15);}
.card.revoked .a-name{color:#ff6b6b;text-decoration:line-through;}
.agent{padding:14px 18px;border-bottom:1px solid #1c1c1f;}
.agent:last-child{border-bottom:none;}
.a-top{display:flex;align-items:center;justify-content:space-between;gap:10px;}
.a-name{font-size:16px;font-weight:700;color:var(--text);}
.a-did{font-size:11px;color:var(--accent-blue);font-family:ui-monospace,monospace;
word-break:break-all;margin-top:2px;}
.score{font-size:13px;font-weight:700;color:var(--accent);
background:#0c1f08;border:1px solid var(--accent-dim);border-radius:6px;
padding:2px 9px;white-space:nowrap;}
.seed .card-head{background:linear-gradient(90deg,#0a2a06,#0f0f11);
border-color:var(--accent-dim);box-shadow:0 0 14px rgba(57,255,20,0.18);}
.seed .score{box-shadow:0 0 8px var(--accent);}
.paths{font-size:11px;color:var(--muted);margin-top:4px;font-style:italic;}
.empty{padding:24px 18px;color:var(--muted);font-style:italic;text-align:center;}
.scope-sec{margin:28px 0;border-top:1px solid #222;padding-top:18px;}
.scope-title{font-size:13px;text-transform:uppercase;letter-spacing:2px;color:var(--accent);margin-bottom:10px;}
.tab{display:inline-block;border:1px solid var(--accent-dim);border-radius:999px;padding:2px 10px;font-size:11px;color:var(--accent);margin-right:6px;}
"""


def dashboard_data(net: dict, *, scope: str) -> dict:
    """Compute the ranked agent list + paths + revocation state for the dashboard."""
    # revocation awareness (Phase 16/17): load the local revocation list
    revoked_by = {}
    try:
        from atar.revocation import RevocationList
        rl = RevocationList.load(_revocations_path_for(net))
        for e in rl.all():
            revoked_by[e["vid"]] = e["revoked_by"]
    except Exception:
        rl = None

    # SPEC §8.1/8.2: trust flows only through valid, unrevoked, unexpired
    # vouches, discounted by disputes from inside the trusted graph - the
    # dashboard must show the same numbers `atar graph` computes.
    from atar.dispute import DisputeList
    from atar.freshness import VOUCH_TTL_DEFAULT
    g = graph_from_vouches(net["vouches"])
    trust = g.compute_trust(seed_did=net["seed_did"], scope=scope,
                            revocations=rl,
                            disputes=DisputeList.load(_disputes_path_for(net)),
                            ttl=VOUCH_TTL_DEFAULT)
    name_by_did = {v: k for k, v in net["agents"].items()}

    # build incoming-edge map: subject -> list of (issuer_name, score)
    edges = {}
    for v in net["vouches"]:
        p = v["payload"]
        if p.get("scope") != scope:
            continue
        edges.setdefault(p["subject"], []).append(
            (name_by_did.get(p["issuer"], "?"), float(p["score"]))
        )

    from atar.transparency import TrustGraph as _TG
    agents = []
    listed: set[str] = set()
    for did, score in sorted(trust.items(), key=lambda kv: kv[1], reverse=True):
        paths = edges.get(did, [])
        # an agent is "revoked" if any incoming vouch to it is on the list
        agent_revoked = False
        revoker = None
        for v in net["vouches"]:
            p = v["payload"]
            if p.get("subject") != did:
                continue
            from atar.revocation import revoke_payload_id as _rid
            # issuer-bound (SPEC §6): only a revocation by the vouch's issuer applies
            if rl is not None and rl.is_revoked_for(v):
                agent_revoked = True
                revoker = name_by_did.get(revoked_by.get(_rid(v), ""), "?")
                break
        agents.append({
            "name": name_by_did.get(did, "?"),
            "did": did,
            "trust": 0.0 if agent_revoked else round(score, 3),
            "is_seed": did == net["seed_did"],
            "paths": [{"via": n, "score": s} for n, s in paths],
            "revoked": agent_revoked,
            "revoked_by": revoker,
        })
        listed.add(did)

    # Revoked vouches no longer propagate trust (SPEC §8.1), so an agent
    # whose only incoming vouches are revoked drops out of the trust dict -
    # but it must still be VISIBLE, flagged REVOKED with trust 0, not
    # silently disappeared.
    for v in net["vouches"]:
        p = v["payload"]
        if p.get("scope") != scope:
            continue
        did = _TG._alias(p["subject"])
        if did in listed:
            continue
        if rl is None or not rl.is_revoked_for(v):
            continue
        from atar.revocation import revoke_payload_id as _rid
        agents.append({
            "name": name_by_did.get(did, name_by_did.get(p["subject"], "?")),
            "did": did,
            "trust": 0.0,
            "is_seed": did == net["seed_did"],
            "paths": [],
            "revoked": True,
            "revoked_by": name_by_did.get(revoked_by.get(_rid(v), ""), "?"),
        })
        listed.add(did)
    return {"seed_did": net["seed_did"], "scope": scope, "agents": agents}


def _revocations_path_for(net: dict) -> str:
    """Resolve the revocations.json path (net may carry an override)."""
    import os
    if net.get("_revocations_path"):
        return net["_revocations_path"]
    home = os.environ.get("ATAR_HOME",
                          os.path.join(os.path.expanduser("~"), ".atar"))
    return os.path.join(home, "revocations.json")


def _disputes_path_for(net: dict) -> str:
    """Resolve the disputes.json path (net may carry an override)."""
    import os
    if net.get("_disputes_path"):
        return net["_disputes_path"]
    home = os.environ.get("ATAR_HOME",
                          os.path.join(os.path.expanduser("~"), ".atar"))
    return os.path.join(home, "disputes.json")


def render_cards(net: dict, *, scope: str) -> str:
    """Render only the agent cards (no HTML page wrapper). Shared by the
    single-scope and multi-scope renderers."""
    import html as _html
    data = dashboard_data(net, scope=scope)
    cards = []
    for a in data["agents"]:
        cls = "card seed" if a["is_seed"] else "card"
        if a["revoked"]:
            cls += " revoked"
        badge = "seed" if a["is_seed"] else "agent"
        if a["revoked"]:
            badge = "REVOKED"
        path_txt = ""
        if a["paths"]:
            parts = [f"via {_html.escape(str(p['via']))} ({p['score']:.2f})" for p in a["paths"]]
            path_txt = f'<div class="paths">trust path: {", ".join(parts)}</div>'
        rev_txt = ""
        if a["revoked"]:
            rev_txt = (f'<div class="paths" style="color:#ff6b6b;">'
                       f'revoked by {_html.escape(str(a["revoked_by"]))}</div>')
        trust_label = "REVOKED" if a["revoked"] else f"trust={a['trust']:.3f}"
        cards.append(f'''
  <div class="{cls}">
    <div class="card-head">
      <h2>{_html.escape(str(a["name"]))}</h2>
      <span class="badge {"revoked" if a["revoked"] else ""}">{badge}</span>
    </div>
    <div class="agent">
      <div class="a-top">
        <div>
          <div class="a-name">{_html.escape(str(a["name"]))}</div>
          <div class="a-did">{_html.escape(str(a["did"]))}</div>
        </div>
        <span class="score">{trust_label}</span>
      </div>
      {path_txt}
      {rev_txt}
    </div>
  </div>''')
    return "".join(cards)


def render_dashboard_html(net: dict, *, scope: str) -> str:
    """Render the Know-Your-Agent dashboard as a standalone HTML page."""
    data = dashboard_data(net, scope=scope)
    cards = render_cards(net, scope=scope)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ATAR — Know Your Agent</title>
<style>{_CSS}</style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div class="brand">ATAR</div>
      <h1>Know Your Agent</h1>
      <div class="sub">trust network &middot; scope: {data['scope']}</div>
    </div>
    {cards if cards else '<div class="empty">No agents in this scope yet.</div>'}
  </div>
</body>
</html>"""


def render_multi_scope_html(net: dict, *, scopes: list[str]) -> str:
    """Render the dashboard with one section per scope (tabs in the hero)."""
    import html as _html
    sections = []
    for scope in scopes:
        data = dashboard_data(net, scope=scope)
        cards = render_cards(net, scope=scope)
        sections.append(f'<section class="scope-sec">\n'
                        f'<div class="scope-title">scope: {_html.escape(scope)}'
                        f' &middot; {len(data["agents"])} agents</div>\n'
                        f'{cards}\n</section>')
    tabs = " &middot; ".join(f'<span class="tab">{_html.escape(s)}</span>' for s in scopes)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>ATAR — Know Your Agent (multi-scope)</title>
<style>{_CSS}</style>
</head>
<body>
  <div class="wrap">
    <div class="hero">
      <div class="brand">ATAR</div>
      <h1>Know Your Agent</h1>
      <div class="sub">trust network &middot; scopes: {tabs}</div>
    </div>
    {''.join(sections)}
  </div>
</body>
</html>"""
