# Volume isolation between projects

Operational write-up of the storage-isolation posture on a single-node
k8tre cluster (Longhorn + k3s) as observed on the StackIT dev cluster.
Pairs with [`docs/project-isolation.md`](../project-isolation.md), which
covers the identity / network / RBAC layers; this doc covers the volume
layer specifically and the one gap that came out of the probes.

## TL;DR

The defaults give you four solid isolation guarantees and one critical
gap:

| Probe | Result | Note |
| --- | --- | --- |
| PVC RBAC cross-namespace | ✅ blocked | default SA cannot `get/list/create/delete` PVCs in another `project-*` namespace |
| Cluster-scoped Longhorn (`volumes.longhorn.io`, `persistentvolumes`) | ✅ blocked | same SA has no access |
| Pod creation under the default SA | ✅ blocked | apiserver returns `Forbidden` — a notebook user cannot spawn its own pod |
| `claimName` reference into another namespace | ✅ blocked | scheduler resolves `claimName` in the pod's own namespace and the pod stays `Pending` with `persistentvolumeclaim "X" not found` |
| Reachability of `longhorn-frontend` / `longhorn-manager` from a project pod | ✅ blocked | Cilium NetworkPolicy returns 000 (no connection) |
| `hostPath: /var/lib/longhorn` mount in a `project-*` namespace | ❌ **allowed** | no Pod Security Admission enforcement → cluster-admin (or anything able to create pods directly) can read every project's raw volume blocks |

The last row is the one that matters — see *The hostPath gap* below.

## How to reproduce — the six probes

The whole block can be pasted into a shell with the cluster's kubectl
context active.

```sh
SA_A=system:serviceaccount:project-alpha:default
SA_B=system:serviceaccount:project-bravo:default

# 1) PVC RBAC cross-namespace
for verb in get list create delete; do
  echo "  $verb pvc -n project-bravo : $(kubectl auth can-i $verb pvc -n project-bravo --as=$SA_A)"
done

# 2) Cluster-scoped Longhorn + PV
for verb in get list create delete patch; do
  echo "  $verb volumes.longhorn.io : $(kubectl auth can-i $verb volumes.longhorn.io --as=$SA_A)"
done
for verb in get list create patch; do
  echo "  $verb persistentvolumes : $(kubectl auth can-i $verb persistentvolumes --as=$SA_A)"
done

# 3) Pod creation under the default SA — must fail Forbidden
kubectl apply --as=$SA_A -f - <<'POD'
apiVersion: v1
kind: Pod
metadata: {name: vol-steal, namespace: project-alpha}
spec:
  containers:
  - {name: t, image: alpine:3.20, command: ["sleep","30"]}
POD

# 4) Cross-ns claimName — admin creates the pod, scheduler must refuse
kubectl apply -f - <<'POD'
apiVersion: v1
kind: Pod
metadata: {name: vol-steal-admin, namespace: project-alpha}
spec:
  containers:
  - {name: t, image: alpine:3.20, command: ["sleep","30"],
     volumeMounts: [{name: v, mountPath: /s}]}
  volumes:
  - {name: v, persistentVolumeClaim: {claimName: notebook-bob-bravo}}
POD
sleep 4
kubectl get pod -n project-alpha vol-steal-admin \
  -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].message}{"\n"}'

# 5) hostPath mount — the gap
kubectl apply -f - <<'POD'
apiVersion: v1
kind: Pod
metadata: {name: host-escape, namespace: project-alpha}
spec:
  containers:
  - {name: t, image: alpine:3.20, command: ["sleep","30"],
     volumeMounts: [{name: host, mountPath: /host}]}
  volumes:
  - {name: host, hostPath: {path: /var/lib/longhorn}}
POD
sleep 3
kubectl get pod -n project-alpha host-escape -o jsonpath='{.status.phase}{"\n"}'
# expected on a hardened cluster:  the apply itself fails with
#   pods "host-escape" is forbidden: violates PodSecurity "restricted:v1.32"
# observed today: phase=Running

# 6) Longhorn UI/API reachability from a project pod
LH_UI_IP=$(kubectl get svc -n storage-system longhorn-frontend \
  -o jsonpath='{.spec.clusterIP}')
kubectl run lh-probe -n project-alpha --image=curlimages/curl:8.10.1 \
  --restart=Never --command -- sleep 30 >/dev/null
# (wait for ready, then)
kubectl exec -n project-alpha lh-probe -- curl -s -o /dev/null \
  --max-time 5 -w '%{http_code}' "http://$LH_UI_IP/"

# cleanup
kubectl delete pod -n project-alpha vol-steal-admin host-escape lh-probe \
  --force --grace-period=0
```

## The `hostPath` gap

Anything that can create pods in a `project-*` namespace — directly or
through a spawner — can mount the node's `/var/lib/longhorn` and read
the raw replica files for every project's Longhorn volumes. The
mount-namespace separation is irrelevant: Longhorn keeps replicas as
ordinary files (`volume-head-NNN.img`, `volume-snap-X.img`) under that
directory, and once they're visible to the attacker's pod they are
copyable and parseable.

A user inside a JupyterHub notebook cannot today create such a pod
(its bearer token is its own ServiceAccount, which lacks `create pods`
in its namespace — see Probe 3). The realistic attack surface is:

- **anything running with the JupyterHub or VDI spawner ServiceAccount**
  (those *do* have `create pods` in the project namespace, otherwise
  they couldn't spawn user environments);
- **anything with cluster-admin** kubeconfig access (people, CI jobs,
  ArgoCD app SAs with cluster-scoped permissions);
- **future apps wired into the Project model** that may need a different
  ServiceAccount with broader pod-creation rights.

The defense is to *make `hostPath` (and other escapes) inadmissible at
the namespace level*, not to rely on no one having the verb. That's
what Pod Security Admission (PSA) does.

## Mitigation — Pod Security Admission on `project-*` namespaces

Kubernetes' built-in PSA enforces a profile at namespace level — no
controller needed. Three profiles: `privileged` (default; allows
everything), `baseline` (no obviously dangerous fields), `restricted`
(strictly locked down). `hostPath`, `privileged: true`,
`hostNetwork: true`, and most capabilities are rejected by both
`baseline` and `restricted`.

Label every project namespace:

```sh
for ns in project-alpha project-bravo project-demo-project; do
  kubectl label ns "$ns" \
    pod-security.kubernetes.io/enforce=baseline \
    pod-security.kubernetes.io/enforce-version=v1.32 \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted \
    --overwrite
done
```

Start with `enforce=baseline` (it kills `hostPath` and the worst gear
but is friendly to most controller-spawned pods). Run the workloads
for a few days, watch the `audit`/`warn` reports for what *would* fail
under `restricted`, then promote `enforce` to `restricted` once those
are fixed.

Verify the gap closes:

```sh
kubectl apply -f - <<'POD' 2>&1 || echo "(blocked, as expected)"
apiVersion: v1
kind: Pod
metadata: {name: host-escape, namespace: project-alpha}
spec:
  containers:
  - {name: t, image: alpine:3.20, command: ["sleep","30"]}
  volumes:
  - {name: host, hostPath: {path: /var/lib/longhorn}}
POD
# expected:
#   pods "host-escape" is forbidden: violates PodSecurity "baseline:v1.32":
#   hostPath volumes (volume "host")
```

### Caveats before promoting to `restricted`

The `restricted` profile demands `runAsNonRoot: true`, drops every
capability except `NET_BIND_SERVICE`, requires `allowPrivilegeEscalation:
false`, and pins `seccompProfile.type` to `RuntimeDefault` or
`Localhost`. Things to verify before flipping the switch:

- **JupyterHub user pod spec** (`apps/jupyterhub/.../values.yaml` —
  `singleuser.cloudMetadata.blockWithIptables`, init containers, image
  user) must satisfy all four constraints.
- **VDI spawner pod spec** (`apps/guacamole/...` or whichever
  controller materialises `VDIInstance`s) — desktop sessions often
  need additional capabilities (e.g. `SYS_ADMIN` for FUSE) and won't
  pass `restricted` without explicit `securityContext` tuning.
- **Init containers** added by Longhorn (`engine-image-ei-*`) — those
  live under `storage-system`, not the project namespaces, so they're
  not affected, but any sidecar that the spawner injects into the
  user pod is.

Easiest path: bake the PSA labels into the Project provisioning logic
(today there is no controller — the labels would have to be added
manually each time a Project namespace is created), so a new Project
boots with `enforce=baseline` from second zero.

## What's still not tested

- **Spawner ServiceAccount surface.** The JupyterHub `hub`
  ServiceAccount has `create pods` on the project namespace. If an
  attacker pops the hub, they can spawn arbitrary pods including a
  hostPath escape — until PSA is on. A separate test should impersonate
  the spawner SA and verify that PSA blocks the escape there too.
- **Longhorn snapshots & `BackingImage` cross-project leak.** A
  `BackingImage` is cluster-scoped and stores blob data under
  `/var/lib/longhorn/backing-images/`. If one project's data is ever
  promoted to a BackingImage by mistake, every project can mount it as
  a read-only source. Probably accidental, worth checking once a
  backup/restore workflow is wired up.
- **`subPath` traversal inside a single namespace.** PVC content
  containing `..` segments could let one pod's mount expose another
  pod's files inside the same namespace. Out of scope for cross-project
  isolation but a useful adversarial test inside JupyterHub.
- **`VolumeSnapshot` / `VolumeSnapshotContent` RBAC.** Same shape as
  PV vs PVC: snapshot contents are cluster-scoped. Today no SA in
  `project-*` has access, but it's worth re-checking after any future
  Velero / volume-restore integration.

## Where this fits

The findings on this page extend
[`docs/project-isolation.md`](../project-isolation.md) with a 5th
enforcement layer (volume / node-storage) that the current
`tests/test-project-isolation.sh` does not yet cover. Next iteration
of the test script should add probes 1–6 above and a final assertion
that the `hostPath` pod is denied by PodSecurity. Until PSA is
applied, that assertion is *expected to fail* — which is exactly the
signal we want from the test.
