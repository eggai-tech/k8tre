# k8tre — architecture & isolation diagrams

Two diagrams that describe the cluster as deployed on the StackIT environment (single-node k3s + Cilium + Longhorn).

1. Focuses on how project tenants are kept apart from each other and from the infrastructure.
1. Cooms out to the end-to-end request flow from a researcher's browser down to a per-project notebook pod.

## 1. Namespace separation & tenant isolation

```mermaid
flowchart TB
    %% ─────────── Infrastructure namespaces ───────────
    subgraph INFRA["🔧  Infrastructure namespaces — managed by platform admin"]
        direction LR
        ks["kube-system<br/>Cilium · CoreDNS · metrics-server"]
        ss["storage-system<br/>Longhorn manager · CSI plugin"]
        cnpg["cnpg-system<br/>CloudNativePG operator"]
        es["external-secrets · cert-manager · argocd · metallb-system"]
    end

    %% ─────────── Platform namespaces (shared TRE services) ───────────
    subgraph PLAT["🧱  Platform namespaces — shared TRE services"]
        direction LR
        kc["keycloak<br/>(realm k8tre-app)"]
        bk["backend<br/>(portal)"]
        gw["gateway<br/>(Cilium Gateway API)"]
        nx["ingress-nginx"]
        gt["gitea"]
        jh["jupyterhub<br/>(hub + jhub-auth-proxy<br/>+ guacamole pods)"]
        os["object-storage<br/>(SeaweedFS)"]
    end

    %% ─────────── Tenant (per-project) namespaces ───────────
    subgraph TA["🟦  project-alpha — tenant A"]
        direction LR
        nbA["JupyterHub user-pod<br/>+ PVC notebook-alice-alpha"]
        vdA["VDI pod<br/>+ PVC"]
    end

    subgraph TB_["🟩  project-bravo — tenant B"]
        direction LR
        nbB["JupyterHub user-pod<br/>+ PVC notebook-bob-bravo"]
        vdB["VDI pod<br/>+ PVC"]
    end

    %% Allowed traffic (solid arrows)
    bk -- "spawn pods<br/>(spawner SA)" --> TA
    bk -- "spawn pods<br/>(spawner SA)" --> TB_
    nbA -- "intra-ns OK" --> vdA
    nbB -- "intra-ns OK" --> vdB

    %% Denied traffic (dashed arrows) — the isolation barriers we tested
    TA -. "❌ RBAC: default SA cannot list/get/create<br/>❌ Cilium NetworkPolicy drops cross-tenant TCP<br/>❌ PVC claimName resolved in own ns only" .- TB_
    TA -. "❌ Cilium: apiserver = host entity, blocked<br/>❌ Tenant SA has no ClusterRole" .- ks
    TB_ -. "❌" .- ks

    %% Style cues
    classDef tenant fill:#dde7f3,stroke:#1f4e79,stroke-width:1px,color:#000;
    classDef tenant2 fill:#dff0d8,stroke:#3c763d,stroke-width:1px,color:#000;
    classDef infra fill:#f5f0e0,stroke:#8a7032,stroke-width:1px,color:#000;
    classDef plat fill:#f0e6f3,stroke:#5a2e7a,stroke-width:1px,color:#000;
    class TA tenant;
    class TB_ tenant2;
    class INFRA infra;
    class PLAT plat;
```

**Reading the diagram**

- **Vertical separation**: cluster-scoped resources sit at the top
  (only platform admins write here); the row of infrastructure
  namespaces hosts the cluster operators (Cilium, Longhorn, CNPG,
  cert-manager, ArgoCD); below them the platform namespaces host the
  TRE services every tenant shares (Keycloak, portal, gateway, hub,
  Gitea, object-storage); at the bottom each project lives in its own
  `project-<name>` namespace.
- **Solid arrows** mark traffic that flows in production: the backend's
  spawner ServiceAccount creates user pods inside the project
  namespaces; pods within the same project talk freely.
- **Dashed lines** mark the four assertions
  [`tests/test-project-isolation.sh`](../tests/test-project-isolation.sh)
  enforces: cross-tenant RBAC `no`, cross-tenant network drops, cross-
  namespace `claimName` not resolved, and project pods cannot reach the
  apiserver (Cilium treats `10.43.0.1` as `host`, the
  `allow-pod-to-pod-via-gateway` policy only opens `cluster` entities).

## 2. End-to-end request flow

```mermaid
flowchart TB
    user(["👩‍🔬 Researcher's browser"])

    subgraph CLOUD["☁️  Cloud network (StackIT)"]
        fip["188.34.94.28 · floating IP"]
    end

    subgraph VM["🖥️  Single-node VM — k3s + Cilium"]
        direction TB
        socat["socat 0.0.0.0:80,443 → 127.0.0.1:14722"]
        envoy["cilium-envoy · Gateway API listener · 127.0.0.1:14722"]
        gw["Gateway internal-gateway<br/>HTTPRoutes for portal · keycloak · jupyter · guacamole · gitea · cr8tor"]

        subgraph TRE["TRE platform"]
            direction TB
            portal["portal (backend)"]
            keycloak[("Keycloak · realm k8tre-app")]
            cnpg[("CloudNativePG · postgres")]
            apiserver["kube-apiserver"]
            hub["JupyterHub + jhub-auth-proxy"]
            guac["Guacamole + guacamole-auth-proxy"]
            gitea["Gitea"]
            longhorn[("Longhorn · volumes & replicas")]
        end

        subgraph TENANTS["Per-project workload namespaces"]
            direction TB
            pa["project-alpha · user-notebook · VDI · PVC"]
            pb["project-bravo · user-notebook · VDI · PVC"]
        end
    end

    user -->|"HTTPS<br/>*.&lt;domain&gt;.nip.io"| fip
    fip -->|"DNAT to VM"| socat
    socat --> envoy
    envoy --> gw

    gw -->|"portal.<br/>&lt;domain&gt;"| portal
    gw -->|"keycloak.<br/>&lt;domain&gt;"| keycloak
    gw -->|"jupyter.<br/>&lt;domain&gt;"| hub
    gw -->|"guacamole.<br/>&lt;domain&gt;"| guac
    gw -->|"gitea.<br/>&lt;domain&gt;"| gitea

    portal -->|"OIDC code flow<br/>+ JWKS"| keycloak
    portal -->|"reads User /<br/>Group / Project CRs"| apiserver
    portal -->|"creates VDIInstance<br/>updates JupyterHub<br/>profile via API"| apiserver
    keycloak --> cnpg

    hub -->|"spawn user-notebook"| pa
    hub -->|"spawn user-notebook"| pb
    guac -->|"open VDI"| pa
    guac -->|"open VDI"| pb

    pa -->|"PVC binds<br/>project-alpha only"| longhorn
    pb -->|"PVC binds<br/>project-bravo only"| longhorn

    %% Auth subrequest loop (every subdomain hit)
    hub <-->|"/auth/validate<br/>(subrequest)"| portal
    guac <-->|"/auth/validate"| portal

    classDef ext fill:#cfe2f3,stroke:#0b5394,color:#000;
    classDef net fill:#e6f4ea,stroke:#137333,color:#000;
    classDef plat fill:#fff2cc,stroke:#bf9000,color:#000;
    classDef tenant fill:#f4cccc,stroke:#990000,color:#000;
    class user,fip ext;
    class socat,envoy,gw net;
    class portal,keycloak,cnpg,apiserver,hub,guac,gitea,longhorn plat;
    class pa,pb tenant;
```

**Reading the diagram**

- **Ingress chain (top-left to top-right)**: browser → floating IP →
  cloud NAT → VM's `enp3s0:443` → `socat` systemd unit → Cilium-Envoy
  loopback listener → `Gateway internal-gateway` (Cilium Gateway API).
  This is the path documented in
  [`docs/troubleshooting/k8tre-install-guide.md`](troubleshooting/k8tre-install-guide.md#5-expose-the-gateway-on-the-host-ip)
  and the reason `socat` exists on the host: every HTTPS hit traverses
  it.
- **HTTPRoutes** fan out to the platform services. Three (Keycloak,
  portal, Gitea) serve directly; two (JupyterHub, Guacamole) are
  fronted by their auth-proxy nginx which calls back to
  `portal:/auth/validate` for every request to translate the user's
  Keycloak session into the per-project authorization decision.
- **portal ↔ Keycloak** is OIDC over the **internal-resolved** public
  hostname — see the CoreDNS hosts override in
  [`docs/troubleshooting/keycloak-post-install-setup.md`](troubleshooting/keycloak-post-install-setup.md#make-the-backend-reach-keycloak-from-inside-the-cluster)
  for why a pod hitting `keycloak.<domain>` is rewritten to the VM's
  primary private IP rather than hairpinning out the cloud NAT.
- **portal ↔ apiserver** is how the User → Group → Project CR graph is
  read at every `/projects` and `/auth/validate` call, and how the
  backend mints a `VDIInstance` when a researcher clicks *Launch*.
- **JupyterHub & Guacamole spawn pods inside the tenant namespace** —
  per-project PVCs are created/bound here, never across; the dotted
  isolation boundaries of Diagram 1 apply.
