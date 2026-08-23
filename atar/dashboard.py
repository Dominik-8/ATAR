"""Know-Your-Agent dashboard — the value layer *above* the ATAR protocol.

Renders your private trust network as a dark, ATAR-corporate HTML page (same
design language as ATAR: near-black bg, gift-green accents, GitHub-blue DIDs).
This is the application that captures value while the ATAR protocol itself
stays free — the Google/FB model: own the surface, give away the pipes.

Private, local, $0. No server required; open the file in any browser.
"""

from __future__ import annotations

from atar.transparency import graph_from_vouches

# ATAR design tokens (1:1 with ATAR's analyze.py CSS) so the two projects
# read as one family.
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
"""


def dashboard_data(net: dict, *, scope: str) -> dict:
    """Compute the ranked agent list + paths for the dashboard."""
    g = graph_from_vouches(net["vouches"])
    trust = g.compute_trust(seed_did=net["seed_did"], scope=scope)
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

    agents = []
    for did, score in sorted(trust.items(), key=lambda kv: kv[1], reverse=True):
        paths = edges.get(did, [])
        agents.append({
            "name": name_by_did.get(did, "?"),
            "did": did,
            "trust": round(score, 3),
            "is_seed": did == net["seed_did"],
            "paths": [{"via": n, "score": s} for n, s in paths],
        })
    return {"seed_did": net["seed_did"], "scope": scope, "agents": agents}


def render_dashboard_html(net: dict, *, scope: str) -> str:
    """Render the Know-Your-Agent dashboard as a standalone HTML page."""
    data = dashboard_data(net, scope=scope)

    cards = []
    for a in data["agents"]:
        cls = "card seed" if a["is_seed"] else "card"
        path_txt = ""
        if a["paths"]:
            parts = [f"via {p['via']} ({p['score']:.2f})" for p in a["paths"]]
            path_txt = f'<div class="paths">trust path: {", ".join(parts)}</div>'
        cards.append(f'''
  <div class="{cls}">
    <div class="card-head">
      <h2>{a["name"]}</h2>
      <span class="badge">{"seed" if a["is_seed"] else "agent"}</span>
    </div>
    <div class="agent">
      <div class="a-top">
        <div>
          <div class="a-name">{a["name"]}</div>
          <div class="a-did">{a["did"]}</div>
        </div>
        <span class="score">trust={a["trust"]:.3f}</span>
      </div>
      {path_txt}
    </div>
  </div>''')

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
    {''.join(cards) if cards else '<div class="empty">No agents in this scope yet.</div>'}
  </div>
</body>
</html>"""
