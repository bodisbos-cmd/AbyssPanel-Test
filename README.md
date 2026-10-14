# AbyssPanel-Test

A responsive Xray control panel designed to run on Railway. It includes a Persian-first administrator dashboard, persistent SQLite state, per-client credentials, a branded subscription portal with QR codes, configurable connection profiles, quota/expiry enforcement, Xray configuration validation, and process recovery.

> **Status:** test-stage build, not production-audited. Automated tests cannot replace real connectivity checks from the target networks and supported client apps.

## Features

- Responsive dark dashboard with Persian (RTL) and English language support.
- Unique random initial administrator password on fresh installs. It is written to `/data/INITIAL_ADMIN_PASSWORD.txt` and startup logs; change it immediately. Existing database credentials are not overwritten during upgrades.
- Signed HTTP-only session cookie, CSRF protection on mutations, login throttling, security headers, and scrypt password hashing.
- SQLite database in `/data` for persistent Railway Volume storage.
- Create, edit, pause/enable, revoke, and reset recorded usage for clients.
- Hierarchical reseller accounts: the root admin allocates a finite GB pool to a reseller; resellers can delegate part of their remaining pool to sub-resellers and create finite-quota clients. Each account sees and manages only its own clients; over-allocation is rejected.
- Optional expiry and traffic quota, with automatic disabling after expiry or quota exhaustion.
- Settings page to enable/disable each connection profile; updates are rolled back if Xray cannot apply the configuration.
- A single private subscription URL per client. `/sub/<token>` serves the branded responsive page in browsers and Base64 subscription content to compatible VPN clients; the standard `Subscription-Userinfo` header carries usage, quota, and expiry metadata to compatible apps. QR and help pages remain available.
- Usage counters are flushed before Xray restarts to reduce traffic-accounting loss.
- Owner-only ZIP backup/restore with integrity/schema checks and rollback attempt; backup includes credential hashes and client data, so keep it private.
- Twelve supported profiles: ten VLESS paths across WebSocket, HTTPUpgrade, XHTTP auto/packet-up/stream-up/stream-one and alternate paths, plus Trojan and VMess over WebSocket. The known-invalid Shadowsocks-over-WebSocket profile was removed instead of being advertised as working. XHTTP stream-up/stream-one use their actual modes; all four stream-mode paths are attempted by CI and marked experimental because Railway’s HTTP/1.1 edge may limit them.
- Separate owner/admin/viewer accounts, scoped bot API keys, protected Swagger/ReDoc, resource diagnostics, official client download links, and a hamburger navigation drawer.
- Operator-aware diagnostics with carrier-specific profile feedback aggregation, recent success-rate recommendations, Xray/Nginx validation, safe self-repair, route diagnostics and a health endpoint. Feedback is based on user-reported results; local route checks do not claim to be real carrier ping tests.

## Railway deployment

1. Deploy this repository to a Railway service using the included Dockerfile.
2. Add a Railway Volume mounted at `/data`. It is required to preserve clients, admin credentials, session secret, and the database across deploys.
3. Generate a public domain for port `8080`.
4. Open the service after its first successful deployment. On a fresh database, retrieve the random initial administrator password from the first-boot logs or `/data/INITIAL_ADMIN_PASSWORD.txt`; sign in as `admin` and change it immediately.
5. Set `BASE_URL` to the intended public HTTPS URL only if the automatically detected Railway domain is not the one you want to use for subscriptions.

The app is intended to remain on Railway. Its HTTP transports are routed through Railway's HTTPS edge to local Xray inbounds; no separate public Xray TCP port is used in this design. Railway region changes can require volume migration and downtime, so do not change regions casually.

## Local Docker test

```sh
docker build -t abysspanel-test .
docker run --rm -p 8080:8080 -e COOKIE_SECURE=0 -v "$PWD/data:/data" abysspanel-test
```

Open `http://localhost:8080`. The initial password is written to `data/INITIAL_ADMIN_PASSWORD.txt` and printed to the container logs on a fresh database.

## Security and operational notes

- Never commit `/data`, initial credentials, cookies, or subscription URLs.
- A subscription token grants access to that client's connection profiles. Treat it like a password; revoking or disabling the client invalidates its subscription page, QR, and raw subscription endpoint.
- The dashboard is a control plane, not an uptime guarantee. Railway edge/protocol compatibility and real client traffic must be tested in the target region.
- TLS for public HTTPS is terminated at Railway's edge. Xray listens only on loopback behind Nginx.
- Still not production-audited: real end-to-end client connectivity must be tested in the target region and networks. Direct WireGuard UDP service is not implemented: Railway's public HTTP/HTTPS edge does not expose a general public UDP listener for this deployment design. Do not present WireGuard as working unless deployed on UDP-capable infrastructure. Automated tests cover API lifecycle, profile settings and rollback, quota enforcement, subscription links, and QR rendering; real network latency and every third-party client app must still be validated from the intended user networks.
