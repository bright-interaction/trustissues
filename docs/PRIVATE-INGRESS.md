# Optional private ingress (Tailscale or Headscale)

TrustIssues can serve the same authenticated application through two
application-owned ingress zones:

- **Public:** the existing TCP listener. It is always stamped `public`.
- **Private:** an optional Unix-domain socket. It is stamped `private` only by
  the server that owns that listener.

The private listener is disabled unless both of these are configured:

```dotenv
TRUSTISSUES_PRIVATE_SOCKET_PATH=/run/trustissues/private.sock
TRUSTISSUES_PRIVATE_BASE_URL=https://vault-internal.example.ts.net
```

The URL must be an HTTPS origin with no path, query, credentials, or fragment,
and it must use a different hostname from `TRUSTISSUES_BASE_URL`. A different
port on the same hostname is not enough: host-only cookies are not isolated by
port. Web Storage is origin/port scoped, but the ambient session cookie is the
security boundary that requires a separate host, so TrustIssues refuses that
configuration.
When private ingress is enabled, spell internationalized hostnames in their
ASCII punycode form so browser cookie-origin equivalence is explicit and can be
validated at startup. IP literals and numeric ports must also use canonical
browser spelling; ambiguous shorthand is refused at startup.
Public cookie-authenticated browser mutations accept only
`TRUSTISSUES_BASE_URL` as their origin; private cookie-authenticated browser
mutations accept only `TRUSTISSUES_PRIVATE_BASE_URL`. Cookie-less API/service
key callers carry no ambient browser credential and remain exempt from the
browser CSRF check. A request cannot change zones with `Host`,
`X-Forwarded-For`, a Tailscale identity header, or any other request value.

This is an additional transport gate, not an authentication system. Sessions,
MFA, API keys, roles, collection membership, rate limits, and audit logging all
remain active on both listeners. Administrators are not exempt from a
collection's private-access policy.

## Security properties

- The feature is off by default. Leaving both variables unset creates no
  private listener and opts no collection into a private policy; ordinary
  public/client vault behavior remains available. This release also narrows
  forwarding-header trust independently of the VPN feature: Docker deployments
  behind a host proxy must set the proxy's exact direct-peer `/32` as described
  in the README upgrade note.
- The socket is mode `0600`. Its containing directory must be owned by the
  TrustIssues process and not writable by group or other users. Every configured
  and resolved ancestor must also resist replacement (no writable non-sticky
  ancestor or foreign symlink), otherwise the server refuses to start. Safe
  root/process-owned system symlinks such as `/tmp` or `/var/run` remain usable.
- A regular file, symlink, foreign-owned socket, live socket, or ambiguously
  unreachable socket is never deleted. Only an owned socket proven stale by
  `ECONNREFUSED` is removed after a crash.
- If private ingress is configured but cannot be created, startup fails. It
  never silently starts as public-only while an operator believes private
  enforcement is available.
- If Tailscale, Headscale, or the TLS connector later goes offline, the public
  listener stays available. Operations whose collection policy requires
  private ingress remain unavailable; there is no silent public fallback.
- Any local process able to connect to this socket receives the **transport**
  admission signal. Keep the directory private. App authentication and
  authorization still decide what that process's request may do.

## Collection policy behavior

Choose the policy per collection; client-facing collections normally remain
`standard` even when the optional connector is enabled.

| Policy | Public ingress | Private ingress |
| --- | --- | --- |
| `standard` | Metadata and authorized secret operations work | Same behavior |
| `sensitive_private` | Metadata remains visible; reveal, export, rotation, capability use, and protected mutations are refused | Authorized operations work |
| `fully_private` | Collection and entry metadata are omitted; direct probes look missing | Authorized operations work |

Personal vault entries are standard/public unless moved into a protected
collection. A mixed vault stays useful on the public URL: bulk unlock and export
include personal plus standard client entries and explicitly omit protected
internal entries. Use the private URL for a complete internal backup.

### Browser extension routing

The extension keeps the existing public HTTPS URL and accepts a second,
optional private HTTPS origin supplied by the instance operator. Both origins
must point to the same TrustIssues instance and use different hostnames. Saving
either origin or the API key locks and purges the current decrypted extension
session so plaintext from one connection identity cannot cross into another.

Safe reads and unlock prefer the private origin when it is configured. They
fall back to public only when the private request has a transport failure; an
HTTP response from the private origin is never hidden behind public fallback.
This is what keeps Personal and `standard` client vaults usable off-VPN.

Immediately before every reachable mutation, the extension refreshes both vault
metadata and collection policy. A known protected source/destination, a missing
entry from that fresh view, or an unknown collection policy goes to private
ingress exactly once. Personal and known-`standard` mutations go to public. If
a concurrent promotion makes that public request receive the server's canonical
`private_ingress_required` response or the intentionally concealed
fully-private 404, it may switch once to private. A timeout, lost response,
401, 5xx, or other ambiguous failure is never replayed on the other origin.

The extension cannot detect or join an overlay itself. Leaving the private URL
empty is supported; protected actions then fail with an actionable instruction
while ordinary client work remains on the public origin.

### Instance-wide control planes

When the optional listener is configured, first-run administrator bootstrap,
administrator creation/invitation/redemption, promotion, account re-enable,
administrator password reset, hard deletion that changes protected collection
authority/custody, activity and capability audit readers/exports, and vault-key
status/re-key operations are private control-plane actions. Their
public refusal is selected from the request shape or deployment configuration
before resolving a target, so it does not become an account, role, or protected-
state oracle. Account disable and demotion remain public emergency reductions;
choosing a replacement password does not, because it establishes a new login
credential for the caller-selected account. Deployments with no connector retain
public compatibility, while historical or live protected state still keeps the
corresponding global operation fail-closed.

External-client onboarding remains on the public origin. The supported flow is
web-first: invite the client as `vault_only`, require them to choose a password
on `/invite`, let them explicitly accept only their dedicated `standard`
collection, and have their authenticated browser session create a named API key
in Settings after any required TOTP enrolment. The extension receives only the
public URL and that key. It never redeems an invitation code itself, and a client
is never given the private connector URL merely to reach a client collection.

### Promotion and background-work semantics

Policy is checked in the same database snapshot as authorization and the state
an operation uses. A promotion committed before that snapshot blocks a public
operation. An operation already admitted may finish after a concurrent
promotion: provider calls release the database transaction before network I/O
instead of locking SQLite for seconds. Promotion is therefore a boundary for
new work, not a remote cancellation mechanism for work already in flight.

Scheduled rotation is server-initiated and continues for protected collections
under the server's configured network and destination controls, even while the
private connector is unavailable. Ingress policy gates human/API admission; it
does not make scheduler authority depend on Tailscale or Headscale uptime.
External notification metadata is stricter: policy is rechecked immediately
before each channel send, and fully-private entry names/details are suppressed.

Secrets already revealed to a browser cannot be remotely erased by a VPN
disconnect. The UI/extension lock removes reachable references and new protected
requests fail, but JavaScript cannot zero immutable strings or revoke a value
already copied elsewhere. Treat device compromise and browser memory as outside
the transport gate.

### Ingress control is not provider-traffic routing

The optional connector controls **which inbound application route may authorize
an operation**. It does not automatically put outbound rotation-provider,
webhook, SMTP, AI-provider, or delivery-target traffic inside Tailscale or
Headscale. Those destinations still use the host/container's ordinary network
route and the application's existing destination allowlists and SSRF guards.

If an organization also needs network-level egress binding, configure that at
the host/container firewall or with a dedicated outbound proxy whose route is
limited to the overlay. Treat that as a separate deployment control: do not
assume enabling `TRUSTISSUES_PRIVATE_SOCKET_PATH` changed outbound routing.

## Safe enablement order

1. Deploy this version with both private variables unset. Verify ordinary
   public and client collection workflows first.
2. Prepare the tailnet/Headscale access rules, private DNS, TLS, and connector.
   Restrict the connector's HTTPS port to the intended team identities/nodes.
3. Set both private variables and restart TrustIssues. Do not enable a
   collection's private policy yet.
4. Attach one of the connectors below.
5. Verify both paths:

   ```bash
   curl https://vault.example.com/health
   curl https://vault-internal.example.ts.net/health
   ```

   The first response must include `"ingress":"public"`; the second must
   include `"ingress":"private"`. The response also reports the base URL for
   that zone and whether the optional listener is configured. Supplying a fake
   private header to the public URL must still report `public`.
6. Sign in through the private URL and exercise create, reveal, export, and a
   test rotation. The private origin gets its own host-only session cookie.
7. Enable private policy on one non-critical internal test collection. Confirm
   its protected operation fails on the public URL and succeeds on the private
   URL. Only then migrate production internal collections.

Keep at least one tested, documented operator path to the private connector.
The local health check below proves the application listener is alive, but does
not prove the overlay or TLS route is healthy:

```bash
curl --unix-socket /run/trustissues/private.sock http://localhost/health
```

## Break-glass runbook

Private policy never falls back to the public listener. Before protecting a
production collection, record and test all of the following:

1. Two authorized team devices that can reach the private hostname.
2. Administrative access to the TrustIssues host and overlay connector.
3. A tested way to restore the Tailscale Serve or Headscale/TLS process while
   leaving the application and its socket directory intact.
4. A current encrypted backup and the separately stored vault key.

If the overlay is down, first verify the application socket locally with the
health command above, then repair DNS, TLS, or overlay access. If the socket is
down, restore the configured directory ownership and restart TrustIssues.
Policy downgrade is intentionally possible only through authenticated private
ingress; do not expose the Unix socket or database volume to manufacture a
public bypass.

## Managed Tailscale

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) is
tailnet-only and applies the tailnet's access rules. Do **not** use Tailscale
Funnel for this route; Funnel is public.

Run Serve on the same host/namespace that can see the Unix socket:

```bash
sudo tailscale serve --https=443 --bg unix:/run/trustissues/private.sock
sudo tailscale serve status --json
```

Use Tailscale 1.98.9 or newer. Tailscale's
[TS-2026-005 security bulletin](https://tailscale.com/security-bulletins)
fixed a privilege check for Serve Unix-socket proxy targets; current versions
require appropriate local privilege for this target type. The socket remains
the application's trust boundary. TrustIssues does not consume Tailscale
identity headers as authentication.

Enable HTTPS for the tailnet and make `TRUSTISSUES_PRIVATE_BASE_URL` exactly
the Serve URL shown by the CLI. Tailscale access rules are additive: adding a
narrow rule does not cancel an existing broad or initial allow-all rule. Replace
or remove every broad rule that reaches this node, establish a deny-by-default
policy, and then add a narrow
[Tailscale Grant](https://tailscale.com/docs/features/access-control/grants)
permitting only the intended team users/devices to this node's HTTPS port.

For Docker, do not expose a new TCP port. Bind-mount a dedicated socket-only
directory into TrustIssues and a root Tailscale sidecar at `/run/trustissues`.
Never mount the `trustissues_data` volume into the connector: that volume holds
the vault database and is unrelated to transport. The socket directory must be
pre-created, owned by the TrustIssues container UID, and mode `0700`; the root
sidecar can traverse it without receiving database access. Find the image UID
with:

```bash
docker compose run --rm --entrypoint id trustissues -u
```

Persist the Tailscale sidecar's state separately and inject its auth key through
your container secret mechanism, not the Compose file or command line.

## Open-source Headscale

[Headscale](https://headscale.net/stable/) is an open-source, self-hosted
control server for Tailscale clients. Register the connector host with the
Headscale control URL using the documented
[`tailscale up --login-server` flow](https://headscale.net/stable/usage/getting-started/),
and restrict reachability with an explicit Headscale policy. Headscale allows
node-to-node traffic when no policy is loaded, and a policy that omits both
`grants` and `acls` is also allow-all. Do not treat membership in the Headscale
network as sufficient restriction: load and test a deny-by-default policy that
grants only the intended team principals access to this connector and HTTPS
port before protecting a collection. Follow the stable
[Headscale policy reference](https://headscale.net/stable/ref/policy/) for the
version you deploy.

Managed Tailscale's automatic `*.ts.net` certificate flow should not be assumed
for a Headscale deployment. Terminate TLS in a local reverse proxy that binds
**only** to the connector's overlay address and dials the TrustIssues Unix
socket. For example, with Caddy and a certificate valid for the private name:

```caddyfile
https://vault-internal.example.com {
    bind 100.64.0.10
    tls /etc/trustissues-tls/fullchain.pem /etc/trustissues-tls/private-key.pem

    reverse_proxy unix//run/trustissues/private.sock {
        header_up Host {hostport}
    }
}
```

The `unix//...` upstream syntax is documented by
[Caddy's reverse proxy reference](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).
Run the proxy as the TrustIssues OS user (or as root with a tightly scoped
service unit), because the socket deliberately has no group/world access. If
the proxy cannot bind port 443 without broader privilege, use an unprivileged
port such as 8443 and include it in `TRUSTISSUES_PRIVATE_BASE_URL`.

Use a publicly trusted certificate obtained through a DNS challenge, a
pre-provisioned organizational certificate, or Caddy's internal CA with that CA
installed on every team device. Never disable certificate verification, and do
not publish the overlay-bound listener on a public or LAN wildcard address.

## Other overlay providers

The application connector is intentionally provider-neutral. Another VPN or
zero-trust overlay can be used when its local connector can:

1. bind an HTTPS listener only on the overlay interface/address;
2. restrict that listener to the intended team identities or devices;
3. present a certificate valid for the distinct private hostname; and
4. proxy directly to the TrustIssues Unix socket as the application user or
   root.

Do not translate an overlay identity header into application access and do not
proxy the private hostname to the public TCP port. The Unix socket, not a header,
IP range, or vendor name, is what selects the private application zone.

## Disable or roll back

Order matters when private policies already exist:

1. While connected through private ingress, change protected collections back
   to `standard` and verify their required workflows through the public URL.
2. Remove/disable the Tailscale Serve or Headscale TLS connector.
3. Unset both `TRUSTISSUES_PRIVATE_SOCKET_PATH` and
   `TRUSTISSUES_PRIVATE_BASE_URL`, then restart.

Clearing the listener first intentionally does not unlock protected
collections; it leaves them fail-closed until a private route is restored or
their policy is changed through an authorized private session.

## Known operational limits

- `fully_private` hides collection/entry metadata from public application
  ingress; it is not a second encryption-at-rest mode. Collection names,
  descriptions, membership, roles, and policy remain operational metadata in
  SQLite, so backups still require whole-file encryption and restricted access.
- `/health` proves which TrustIssues listener handled that request. It cannot
  prove that every authorized team device can traverse the VPN policy.
- A Unix-socket reverse proxy does not preserve a meaningful source IP by
  itself. Authentication and the application audit identity remain available,
  but private requests may share an IP-based rate-limit bucket unless the
  connector path later adds a separately reviewed, sanitized attribution
  mechanism. Private headers are never used to grant vault access.
- Tailscale/Headscale availability is now a dependency for private-required
  work. Monitor the external connector and test the break-glass route after
  every networking or certificate change.
- Policy promotion stops newly admitted public work; it does not cancel a
  provider request already admitted from a coherent pre-promotion snapshot.
- Scheduled rotations continue under server authority while the connector is
  down. If that is not acceptable, stop the TrustIssues scheduler/process or
  enforce the separate host-level egress control before maintenance.
