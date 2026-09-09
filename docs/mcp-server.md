# ATAR as an MCP server

`atar mcp` runs ATAR's read-only trust surface as an
[MCP](https://modelcontextprotocol.io) server over stdio, so any MCP host
(Claude, ChatGPT, Cursor, Copilot, ...) can verify agent trust artifacts and
query your local trust graph as native tools.

## Install

```bash
pip install "atar-trust[mcp]"
```

## Point your host at it

Any MCP host configuration that launches a stdio server:

```json
{
  "mcpServers": {
    "atar": { "command": "atar", "args": ["mcp"] }
  }
}
```

The server reads the operator's normal local store (`$ATAR_HOME`,
default `~/.atar`): the vouches, revocations, disputes and identities you
already built with the CLI are what the tools report on.

## Tools

| Tool | What it does |
| --- | --- |
| `verify_vouch` | Verify a native vouch blob (`{payload, signature}`) offline against the issuer's `did:key`; returns validity plus the decoded summary. |
| `verify_vouch_token` | Verify an ATC vouch token (base64url, SPEC §11.1) and decode it. |
| `verify_agent_card` | Verify an A2A agent card with the ATAR trust extension: every vouch token plus the card signature (SPEC §11.2). |
| `trust_scores` | Transitive trust from a seed DID (or local identity name) for a scope, over the local store — the same computation as `atar graph`, honoring revocation, TTL and disputes (SPEC §8). |
| `vouches_for` | Vouches a DID (or local name) issued or received, from the local store. |
| `list_known_agents` | Known identity names → DIDs, plus store size. |

## Trust model: read-only on purpose

The server **never signs or issues** anything. Reputation is minted by the
operator through the CLI after human judgment; a connected MCP client must
not be able to mint trust. Verification is offline (keys come from the
DIDs), so a host can check artifacts without phoning anywhere.

## Errors

Tools report structured results (`{"ok": false, "error": ...}` or
`{"valid": false}`) instead of raising — a malformed card or token from an
untrusted peer must never crash the session.
