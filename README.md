# AbyssPanel-Test

A separate test-stage control panel for Xray/VLESS on Railway. It includes an administrator dashboard, persistent SQLite state, per-client credentials, subscription links, Xray configuration validation, and basic process recovery.

> **Status:** first implementation / test build. Do not treat this as production-audited. Validate actual client connectivity, Railway WebSocket behavior, resource limits, and subscription compatibility before relying on it for paid users.

## What it currently does

- Dark responsive admin dashboard.
- Random initial administrator password; no hard-coded default password.
- Signed, HTTP-only session cookie, CSRF protection on mutations, login throttling, security headers, password hashing with scrypt.
- SQLite database in `/data` with WAL mode for persistent Railway Volume storage.
- Create, pause/enable, and revoke VLESS clients.
- One private subscription token per client; subscription returns Base64-encoded VLESS links.
- Xray config is generated from active clients and validated with `xray run -test` before process restart.
- Nginx routes `/ws`, `/httpupgrade`, and `/xhttp` to local Xray inbounds; admin/API traffic is routed to FastAPI.
- Health endpoint and basic Xray process recovery.

## Railway deployment

1. Upload/push this repository to a **new private GitHub repository**.
2. In Railway, deploy the repository using the included Dockerfile.
3. Set the service region to Amsterdam/Netherlands if available on your plan.
4. Add a Railway Volume mounted at `/data`. This is mandatory for persistence of clients, sessions, and the generated initial password file.
5. Generate a public domain for port `8080`.
6. Wait for the deployment and open the domain. Retrieve the one-time initial administrator password from the first-boot logs (the password is also written to `/data/INITIAL_ADMIN_PASSWORD.txt` with restricted file permissions). Sign in as `admin` and change the password immediately.

No Xray public inbound TCP port is required for the HTTP transports in this build; Railway's HTTPS edge must pass WebSocket traffic to the service. Test with a real client after deployment. `BASE_URL` can be set to the public HTTPS URL if Railway's forwarded host is not the one intended for subscriptions.

## Local Docker test

```sh
docker build -t abysspanel-test .
docker run --rm -p 8080:8080 -e COOKIE_SECURE=0 -v "$PWD/data:/data" abysspanel-test
```

Open `http://localhost:8080`. The generated initial password is printed to container logs and stored under `data/INITIAL_ADMIN_PASSWORD.txt`.

## Security / operational notes

- Keep the repository private until a security review is complete.
- Never commit `/data`, initial credentials, cookies, or subscription URLs.
- Configure a strong, unique administrator password after first login.
- The dashboard/API is a control plane, not an uptime guarantee. Railway edge/protocol compatibility and real client traffic must be tested in the target region.
- TLS for public HTTPS is terminated at Railway's edge. The generated VLESS link uses TLS at the public endpoint; Xray listens only on loopback behind Nginx.
- This initial version does not yet implement traffic accounting, quotas, expiry, multiple admins, backups/restore UI, or Reality/TCP inbound. Those require additional work and tests before production use.
