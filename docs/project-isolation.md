# k8tre — project isolation model and how to test it

This doc describes the four layers that keep one k8tre Project's resources
out of reach of another Project's users, and the
[`tests/test-project-isolation.sh`](../tests/test-project-isolation.sh)
script that exercises all four end-to-end.

## The isolation model

A *Project* in k8tre is more than a row in a database — it is materialized
across four independent enforcement layers. Each layer can fail on its
own without breaking the others, so the test below treats them
separately.

### Layer 1 — UX (`/projects` filtering)

When a logged-in user opens
`https://portal.<domain>/projects`, the backend walks the user's
`User CR (spec.groups[]) → Group CR (spec.projects[]) → Project CR` graph
and renders only the projects reachable from that user's identity. This is
a **convenience layer**, not a security boundary: it only controls what
the menu shows. The endpoint
`/projects/<other>/apps` is not protected by the authorization check
(`_is_user_authorised_project()` is **not** called there), so a
logged-in user who knows another project's name can still GET that
page and see its app list. That's a metadata leak, not a data leak —
see the *Weak spots* section below.

### Layer 2 — Backend authorization gate (`/auth/validate`)

This is the **real security boundary**. Every request the browser makes
to a non-portal subdomain (`jupyter.<domain>`, `guacamole.<domain>`, …)
is intercepted by an auth-proxy nginx that issues a subrequest to
`https://portal.<domain>/auth/validate`. That handler:

1. Extracts the project from the `k8tre-project` cookie or
   `?project=` URL parameter,
2. Extracts the token from `k8tre-auth-token-<project>` cookie or
   `?token=` parameter,
3. Verifies the JWT signature and the `aud` claim (the `audience`
   protocol mapper on the Keycloak client is what makes this work —
   see [`keycloak-post-install-setup.md`](troubleshooting/keycloak-post-install-setup.md#add-the-aud-audience-protocol-mapper)),
4. Calls **`_is_user_authorised_project(username, project)`**
   (`ci/backend/main.py:301`) which re-walks the User/Group/Project
   graph from the OIDC `preferred_username` claim,
5. Returns 200 + auth headers (`X-Auth-User`, `X-Auth-Groups`, …) on
   success, **403** on authorization failure.

Same check is repeated at `/vdi/sso/<token>/<project>/<app>` for VDI
shortcut authentication, and inside `/launch/<project>/<app>` for the
in-VDI lockout (a user inside a VDI for project A can't `/launch` an
app for project B — `launch_app()` checks `vdi_context` + `vdi_project`).

### Layer 3 — Kubernetes RBAC

Each project runs in its own namespace, named
`project-<project>` by convention (see `get_proj_namespace()` in
`ci/backend/main.py:216`). Pods spawned by JupyterHub spawners or
VDIInstance CRs land in that namespace. The default Kubernetes RBAC
policy gives a workload's ServiceAccount no implicit cross-namespace
permissions, so a pod in `project-alpha` cannot list, read, create or
delete resources in `project-bravo` without an explicit RoleBinding
or ClusterRoleBinding granting it. The test asserts this with
`kubectl auth can-i --as=system:serviceaccount:project-alpha:default`
against `project-bravo`.

### Layer 4 — Cilium network policy

Once Cilium is the cluster CNI (see
[`k8tre-install-guide.md`](troubleshooting/k8tre-install-guide.md)),
the `CiliumClusterwideNetworkPolicy` and `CiliumNetworkPolicy`
resources shipped by `apps/jupyterhub/base/network_policy.yaml` are
**enforced** instead of inert. The pre-Cilium install (default k3s
flannel) accepted the manifests but no controller honored them. With
Cilium, pods in project namespaces can't reach pods in other project
namespaces — and, importantly, they can't reach the Kubernetes API
server (`10.43.0.1:443`) either, because Cilium treats it as `host`
entity, not `cluster`. This is the reason the RBAC test in layer 3
uses `kubectl auth can-i --as=...` from outside the pod rather than
running `kubectl` from inside it.

## The test script

[`tests/test-project-isolation.sh`](../tests/test-project-isolation.sh)
sets up two parallel projects (`alpha`, `bravo`) plus two users
(`alice` in `alpha-team`, `bob` in `bravo-team`) and walks each
isolation layer in turn. The setup phase is idempotent — re-running
the script just verifies state.

### Run

```sh
# Default: domain 188.34.94.28.nip.io, projects alpha/bravo, users alice/bob
./tests/test-project-isolation.sh

# Override any of these:
DOMAIN=foo.nip.io PROJECT_A=cardio PROJECT_B=onco \
  USER_A=anna USER_B=bruno \
  ./tests/test-project-isolation.sh
```

Requires `kubectl` pointed at the cluster (the script runs the heavy
checks against the apiserver from the host) plus `curl`, `python3` and
`jq` locally.

### What it asserts

| Test | Layer | Expected on a healthy cluster |
|---|---|---|
| Token issuance + `aud` claim | Authn / Keycloak | both users get a JWT, `aud` contains `backend` |
| `alice → alpha` `/auth/validate` | Layer 2 | **200** |
| `alice → bravo` `/auth/validate` | Layer 2 | **403** |
| `bob → bravo` `/auth/validate` | Layer 2 | **200** |
| `bob → alpha` `/auth/validate` | Layer 2 | **403** |
| Anonymous `/projects/<other>/apps` | Layer 1 (negative) | 401 / 302 |
| Logged-in `/projects/<other>/apps` (manual) | Layer 1 (**weak**) | reachable, no authz — flagged as WEAK |
| `kubectl auth can-i list/create/delete pods+secrets -n project-bravo --as=…project-alpha:default` | Layer 3 | every answer is `no` |
| Pod in `project-alpha` curl to pod IP in `project-bravo:8080` | Layer 4 | code 000 (connection denied) |
| User CR `spec.groups[]` exists for both users | Layer 1 source-of-truth | non-empty |

Output uses three states: `PASS` (the assertion held), `FAIL` (it
didn't), `WEAK` (enforcement is incomplete by design — documented but
not yet fixed upstream). On a clean cluster you should see **14 PASS,
0 FAIL, 2 WEAK** today.

### What it does NOT cover

- **Token replay across projects.** The cookie name encodes the
  project (`k8tre-auth-token-<project>`), but the JWT itself is
  identical per user. An attacker with the JWT can mint a cookie for
  any project the user is authorized for. Limit token TTLs to
  mitigate.
- **JupyterHub spawner & VDIInstance RBAC** — pods spawned by these
  components run under their own ServiceAccounts (`hub`,
  `user-scheduler`, `vdi-spawner`) which DO have RoleBindings that
  cross namespace boundaries. The test only checks the *default* SA;
  audit those spawner SAs separately.
- **Cilium policies for inter-pod traffic *within* a single project
  namespace.** Today everything in `project-alpha` can talk to
  everything else in `project-alpha`. Tighten with per-pod
  `endpointSelector` policies if needed.
- **The control plane / Keycloak realm itself.** A misconfigured
  Keycloak protocol mapper (missing `groups` claim, missing `aud`)
  can defeat the whole stack — see *Setup bugs the script surfaced*
  below.

## Weak spots (the two `WEAK` results today)

### 1. Project enumeration via `/projects/<other>/apps`

A logged-in user can GET
`https://portal.<domain>/projects/<any-project-name>/apps` and the
backend will render the list of apps for that project regardless of
whether the user is authorized. The data fetched on subsequent
clicks is gated by `/auth/validate`, so no payload leaks — but the
existence of arbitrary project names is exposed. Fix is one line in
`get_apps()` in `ci/backend/main.py`: add the same
`_is_user_authorised_project(username, project)` check the
`/auth/validate` handler uses, return 403 if not authorized.

### 2. `/launch/<other>/<app>` sets cookies it shouldn't

Same shape, same fix: `launch_app()` mints a project-scoped token
and writes the `k8tre-auth-token-<other>` cookie before checking
authorization. The next request to the subdomain is then rejected by
`/auth/validate`, so a real attack only ever gets a dead cookie —
but it pollutes the user's cookie jar and consumes a Keycloak token
refresh.

## Setup bugs the script surfaced

The first runs failed for reasons that are themselves worth
documenting; the script now handles them in its setup phase:

1. **`kcadm.sh set-password` defaults to `--temporary=true`**, which
   marks the password as needing a change on next login. The OIDC
   *Resource Owner Password Credentials* (password grant) flow then
   rejects the login with `Account is not fully set up`. The script
   always passes `--temporary=false`.
2. **Users created without `firstName`/`lastName`** trigger the same
   `Account is not fully set up` error even when the password is
   permanent. The script always sets both on create and runs an
   `update users/<id>` on existing users to backfill them.
3. **In-pod `kubectl get …` against another namespace fails before
   it can reach the API server** because the project-namespace
   network policy prevents the pod from connecting to
   `10.43.0.1:443`. The script uses
   `kubectl auth can-i --as=…` from the host instead — cleaner
   assertion and resilient to network-policy changes.

## Files

- [`tests/test-project-isolation.sh`](../tests/test-project-isolation.sh)
  — the script.
- [`ci/backend/main.py`](../ci/backend/main.py) — `get_apps()`,
  `launch_app()`, `_is_user_authorised_project()`,
  `get_proj_namespace()`.
- [`apps/jupyterhub/base/network_policy.yaml`](../apps/jupyterhub/base/network_policy.yaml)
  — the Cilium policies enforced under layer 4.
- [`docs/troubleshooting/keycloak-post-install-setup.md`](troubleshooting/keycloak-post-install-setup.md)
  — Keycloak client and audience mapper setup that the authz check depends on.
