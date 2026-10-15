# AbyssPanel → Marzban production cutover checklist

This is a controlled cutover procedure, not a claim that a private Marzban instance has already been tested. Do not enable the Marzban backend on a production volume until every **GO** check below passes.

## 1. Required before deployment

- [ ] A reachable, HTTPS Marzban base URL (not a dashboard-only account or subscription URL).
- [ ] A dedicated Marzban API administrator account with permission to create, update, disable, delete users, and reset traffic.
- [ ] Exact inbound tags copied from the target Marzban instance.
- [ ] A profile-to-inbound mapping for every profile the Abyss UI will allow users to select.
- [ ] A fresh Railway test service and a new Railway Volume mounted at `/data`. Do not point the first test at the existing production volume.
- [ ] Strong, unique Marzban and Abyss administrator credentials. Change the default Abyss `admin/admin` credentials immediately on first login.
- [ ] A backup and a rollback plan for the current service and its volume.

## 2. Railway environment variables

Set these on the **test** service. Use the exact tags from Marzban; examples are placeholders and must not be copied blindly.

```env
MARZBAN_BACKEND=1
MARZBAN_BASE_URL=https://YOUR-MARZBAN-HOST
MARZBAN_ADMIN_USERNAME=YOUR_DEDICATED_API_ADMIN
MARZBAN_ADMIN_PASSWORD=YOUR_LONG_UNIQUE_SECRET
MARZBAN_TIMEOUT_SECONDS=12
MARZBAN_INBOUNDS_JSON={"vless":["EXACT_VLESS_INBOUND_TAG"]}
MARZBAN_PROFILE_INBOUNDS_JSON={"ws":{"vless":["EXACT_VLESS_INBOUND_TAG"]}}
```

If more profiles/protocols are enabled in the UI, add explicit entries for each profile key and exact corresponding inbound tags. A profile without a mapping should fail closed; do not map it to an unrelated inbound just to make creation succeed. JSON must be valid JSON on one line.

Keep `COOKIE_SECURE=1` in Railway. Attach a Volume at `/data`, expose port `8080`, and use the healthcheck path `/health`. Do not put credentials in GitHub, source files, or logs.

## 3. Required test sequence on the isolated service

1. Confirm Railway reports the deployment healthy and `/health` returns HTTP 200 with the Marzban backend connected.
2. Sign in to AbyssPanel, change the initial password, then sign in again.
3. Create a test user with a short expiry and low quota. Confirm it appears in Marzban with the expected inbounds, expiry, quota, and disabled/enabled status.
4. Open the branded Abyss subscription page and confirm the links come from the created Marzban user. Import one link into a supported client and test a real connection from the intended network.
5. Change the user's name/note, quota, expiry, and enabled status; verify each change in Marzban and test that a disabled user cannot connect.
6. Reset traffic and verify the Marzban usage counter resets.
7. Delete the test user and verify the Marzban user and its Abyss subscription are both gone.
8. Restart/redeploy the Railway service and repeat health and subscription checks to confirm the `/data` volume preserves Abyss metadata and credentials.
9. Review logs for API errors and verify that an unreachable/invalid Marzban service makes the healthcheck fail instead of silently serving local-Xray mode.

## 4. Existing users and rollback

Switching an existing Abyss SQLite volume to Marzban does **not** automatically recreate old local-Xray users or migrate historical traffic. Do not flip `MARZBAN_BACKEND=1` on a volume with real users until a deliberate migration has been completed and reconciled by user ID, expiry, quota, traffic, and subscription.

Rollback means redeploying the previous known-good code **with its matching data volume and environment**. Turning off the Marzban flag does not recreate or resynchronize remote users. Do not delete either database or Marzban users during rollback.

## 5. Release gate

The repository CI verifies unit/regression tests, a Docker build, container smoke tests, and static/dependency security scans. Those checks do not prove a real Marzban API or client tunnel works. Mark this release operational only after all checks in section 3 pass on the target Railway region and intended client networks.
