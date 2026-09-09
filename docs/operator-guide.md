# Operator Guide

How to run ATAR as infrastructure: a long-lived gossip peer, monitoring,
backups, key rotation, and recovery. Everything below uses only the shipped
CLI — no extra services, no blockchain, no accounts.

Throughout, `$ATAR_HOME` is the local store (default `~/.atar`). It contains
`keys.json` (private keys — secret), the vouch store, revocations, and
`atar_peers.json` (your known peers). Back it up like a wallet.

## 1. Running a peer

```bash
atar peer --port 8790            # serve this store over HTTP gossip
atar peer --port 8790 --bind 127.0.0.1   # localhost only (default bind)
```

Every peer is equal: the endpoint exposes GET/POST of vouches and revocations
so operators on different machines sync without a shared filesystem. It is
read/gossip only — it cannot issue or revoke on your behalf; signing always
happens locally via the CLI.

Tell your counterparties your URL (`http://host:8790`) and add theirs:

```json
// $ATAR_HOME/atar_peers.json
{"peers": ["http://peer-a.example:8790", "/shared/nfs/peer-b-home"]}
```

A peer URL may also be passed directly: `atar sync --with http://host:8790`.

## 2. Keeping the graph fresh (cron)

```cron
# gossip with all known peers every 15 minutes
*/15 * * * *  atar auto-sync >>/var/log/atar-sync.log 2>&1
# single health check every hour; alert on failure
0 * * * *     atar watch --once || notify-send "ATAR network unhealthy"
```

`auto-sync` is a no-op (exit 0) when the peer list is missing or empty, and it
skips unreachable peers — safe to run blindly from cron or as an agent hook
after each task your agents complete.

For an always-on terminal/ops channel instead of cron, run `atar watch`
(default interval 1h; `--interval N` for N seconds). It prints one healthy
line per check and an `ALERT` line on stderr the moment the network flips
unhealthy (a vouch expired, was revoked, or fails verification).

## 3. Health checks

`atar audit` reports counts by state — valid / revoked / expired / invalid —
plus a per-scope breakdown, and exits non-zero (2) when anything is revoked,
expired, or invalid:

```bash
atar audit                      # exit 0 = healthy, exit 2 = needs attention
atar audit --max-age 7776000    # also flag vouches older than 90 days
```

How to read it:

- **invalid > 0** — a signature or structure failed. Investigate immediately:
  either the store was corrupted or someone gossiped a forged blob. The blob
  is ignored by every consumer; find its source peer.
- **revoked > 0** — normal lifecycle (you or an issuer revoked). No action
  unless unexpected: check `atar list` / `atar disputes` for context.
- **expired > 0** — vouches older than `--max-age` (off unless you pass it).
  Renew by re-vouching from the issuer, or after key rotation use
  `atar reissue --name N --commit`.

## 4. Backup and migration

```bash
atar export backup.atpkg                  # trust graph only (safe to store)
atar export --include-keys full.atpkg     # graph + private keys (SECRET)
```

- A plain export is portable reputation: share or archive it freely.
- `--include-keys` is for full machine migration only. The bundle says so on
  export ("WITH PRIVATE KEYS — keep secret"). Encrypt it at rest, transfer it
  out-of-band, delete it after `atar import`.
- Restore on a new machine: `atar import backup.atpkg` (keys restore only if
  the bundle has them).

Without a keys backup there is no recovery: a lost key cannot sign a
rotation statement, so the identity is dead — you start a new one and re-earn
your vouches. Back up `keys.json`.

## 5. Key rotation drill

Run this periodically and immediately on any suspected compromise:

```bash
atar rotate --name myagent                 # new key, signed rotation statement
atar reissue --name myagent --commit       # re-sign outgoing vouches, revoke old
atar auto-sync                             # propagate rotation + revocations
```

`rotate` binds the new key to the identity with a signed statement; consumers
verifying old vouches follow the rotation chain. `reissue --commit` carries
your outgoing trust forward and retires the old key. Until `reissue` runs,
your old-key vouches still verify but score as pre-rotation.

On suspected compromise, order matters: rotate on the *secure* machine first
(if the attacker still holds the old key, your rotation statement signed with
the new key outranks anything they sign later — but anything they signed
*before* your rotation timestamp stays valid; dispute those with
`atar dispute`).

## 6. Security checklist

- `keys.json` is mode-0600 material. Never commit `$ATAR_HOME`, never export
  `--include-keys` to shared storage.
- The peer endpoint serves your store to anyone who can reach it. Vouches are
  public-by-design (they are meant to gossip), but bind to `127.0.0.1` or
  firewall the port if you only sync over a private path.
- All verification is offline and content-addressed; a malicious peer can
  withhold vouches but cannot forge them. Cross-check surprising scores by
  syncing with a second peer.
- `atar verify` / `verify-card` / `verify-claim` never touch the network and
  never trust the store's index — they re-check signatures from the blob
  bytes. Use them before acting on a vouch that matters.
