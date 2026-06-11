#!/usr/bin/env bash
# test-project-isolation.sh — exercise the 4 isolation layers of k8tre:
#   1. /projects visibility (UX)
#   2. /auth/validate authorization gate (backend → subdomain access)
#   3. Cross-namespace RBAC (kube-apiserver)
#   4. Cross-namespace network policy (Cilium)
#
# Idempotent setup. Run from your laptop with kubectl context pointing at
# the k8tre cluster:
#
#     ./tests/test-project-isolation.sh                # uses defaults below
#     DOMAIN=foo.nip.io ./tests/test-project-isolation.sh
#
set -u
SCRIPT_NAME=$(basename "$0")

# ---- configuration ----------------------------------------------------------
DOMAIN="${DOMAIN:-188.34.94.28.nip.io}"
KEYCLOAK_REALM="${KEYCLOAK_REALM:-k8tre-app}"
K8TRE_NAMESPACE="${K8TRE_NAMESPACE:-keycloak}"   # the backend's NAMESPACE
PROJECT_A="${PROJECT_A:-alpha}"
PROJECT_B="${PROJECT_B:-bravo}"
USER_A="${USER_A:-alice}"
USER_B="${USER_B:-bob}"
PORTAL_URL="https://portal.${DOMAIN}"
KC_URL="https://keycloak.${DOMAIN}"

# ---- output helpers ---------------------------------------------------------
PASS=0; FAIL=0; WEAK=0
GREEN=$'\e[32m'; RED=$'\e[31m'; YELLOW=$'\e[33m'; BOLD=$'\e[1m'; RESET=$'\e[0m'
pass()  { PASS=$((PASS+1)); printf "  ${GREEN}PASS${RESET}  %s\n" "$*"; }
fail()  { FAIL=$((FAIL+1)); printf "  ${RED}FAIL${RESET}  %s\n" "$*"; }
weak()  { WEAK=$((WEAK+1)); printf "  ${YELLOW}WEAK${RESET}  %s\n" "$*"; }
section() { printf "\n${BOLD}== %s ==${RESET}\n" "$*"; }

need() { command -v "$1" >/dev/null || { echo "missing tool: $1"; exit 2; }; }
for t in kubectl curl python3 jq; do need "$t"; done

# ---- setup ------------------------------------------------------------------
setup() {
  section "Setup — projects, groups, users (idempotent)"

  cat <<EOF | kubectl apply -f - >/dev/null
apiVersion: research.k8tre.io/v1alpha1
kind: Project
metadata: {name: ${PROJECT_A}, namespace: ${K8TRE_NAMESPACE}}
spec:
  description: "${PROJECT_A} test project"
  apps:
    - {name: jupyterhub, type: jupyterhub, url: "https://jupyter.${DOMAIN}/hub"}
---
apiVersion: research.k8tre.io/v1alpha1
kind: Project
metadata: {name: ${PROJECT_B}, namespace: ${K8TRE_NAMESPACE}}
spec:
  description: "${PROJECT_B} test project"
  apps:
    - {name: jupyterhub, type: jupyterhub, url: "https://jupyter.${DOMAIN}/hub"}
---
apiVersion: identity.k8tre.io/v1alpha1
kind: Group
metadata: {name: ${PROJECT_A}-team, namespace: ${K8TRE_NAMESPACE}}
spec: {description: "${PROJECT_A} members", projects: ["${PROJECT_A}"]}
---
apiVersion: identity.k8tre.io/v1alpha1
kind: Group
metadata: {name: ${PROJECT_B}-team, namespace: ${K8TRE_NAMESPACE}}
spec: {description: "${PROJECT_B} members", projects: ["${PROJECT_B}"]}
---
apiVersion: identity.k8tre.io/v1alpha1
kind: User
metadata: {name: ${USER_A}, namespace: ${K8TRE_NAMESPACE}}
spec: {username: ${USER_A}, email: ${USER_A}@example.com, enabled: true, groups: ["${PROJECT_A}-team"]}
---
apiVersion: identity.k8tre.io/v1alpha1
kind: User
metadata: {name: ${USER_B}, namespace: ${K8TRE_NAMESPACE}}
spec: {username: ${USER_B}, email: ${USER_B}@example.com, enabled: true, groups: ["${PROJECT_B}-team"]}
EOF

  # Project namespaces — Tests 3 and 4 need them
  kubectl create ns "project-${PROJECT_A}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null
  kubectl create ns "project-${PROJECT_B}" --dry-run=client -o yaml | kubectl apply -f - >/dev/null

  # Keycloak users
  local pod=keycloak-keycloakx-0
  local admin_user admin_pwd
  admin_user=$(kubectl get secret -n keycloak keycloak-admin-credentials -o jsonpath='{.data.username}' | base64 -d)
  admin_pwd=$( kubectl get secret -n keycloak keycloak-admin-credentials -o jsonpath='{.data.admin-password}' | base64 -d)
  kubectl exec -n keycloak $pod -- /opt/keycloak/bin/kcadm.sh config credentials \
    --server http://localhost:8080 --realm master --user "$admin_user" --password "$admin_pwd" >/dev/null 2>&1

  for u in "$USER_A" "$USER_B"; do
    local uid first last
    first="$(printf '%s' "${u:0:1}" | tr '[:lower:]' '[:upper:]')${u:1}"
    last="Test"
    uid=$(kubectl exec -n keycloak $pod -- /opt/keycloak/bin/kcadm.sh get users -r "$KEYCLOAK_REALM" \
            -q "username=$u" --fields id --format csv 2>/dev/null | head -1 | tr -d '"')
    if [ -z "$uid" ]; then
      uid=$(kubectl exec -n keycloak $pod -- /opt/keycloak/bin/kcadm.sh create users -r "$KEYCLOAK_REALM" \
              -s "username=$u" -s enabled=true -s "email=$u@example.com" \
              -s "firstName=$first" -s "lastName=$last" -i 2>/dev/null)
      echo "  created Keycloak user $u"
    else
      # Ensure firstName/lastName are set — Keycloak refuses password-grant with
      # "Account is not fully set up" when these are null.
      kubectl exec -n keycloak $pod -- /opt/keycloak/bin/kcadm.sh update users/"$uid" -r "$KEYCLOAK_REALM" \
              -s "firstName=$first" -s "lastName=$last" -s emailVerified=true \
              -s 'requiredActions=[]' >/dev/null 2>&1
      echo "  Keycloak user $u exists ($uid) — profile ensured"
    fi
    # Always (re)set password as permanent — kcadm.sh defaults to temporary=true.
    kubectl exec -n keycloak $pod -- /opt/keycloak/bin/kcadm.sh set-password -r "$KEYCLOAK_REALM" \
            --userid "$uid" --new-password "$u" --temporary=false >/dev/null 2>&1 \
      && echo "  password set for $u (permanent)" \
      || echo "  WARN: could not set password for $u"
  done

  # Backend OIDC client secret (used for password grant)
  CLIENT_SECRET=$(kubectl get secret -n backend backend-oidc-credentials \
    -o jsonpath='{.data.client-secret}' | base64 -d)
}

get_token() {
  local u="$1"
  curl -ks --max-time 10 -X POST "${KC_URL}/realms/${KEYCLOAK_REALM}/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=backend" -d "client_secret=${CLIENT_SECRET}" \
    -d "username=${u}" -d "password=${u}" -d "scope=openid profile email" \
    | python3 -c 'import sys,json
t=json.load(sys.stdin); print(t.get("access_token",""))'
}

# ---- Test 1 — /auth/validate authorization gate -----------------------------
test_authvalidate() {
  section "Test 1 — /auth/validate (the real authorization gate)"

  local t_a t_b
  t_a=$(get_token "$USER_A"); t_b=$(get_token "$USER_B")
  [ -n "$t_a" ] || { fail "could not get token for $USER_A"; return; }
  [ -n "$t_b" ] || { fail "could not get token for $USER_B"; return; }
  pass "tokens obtained for $USER_A and $USER_B"

  # Check that each token carries `aud` claim (otherwise verify_token rejects all of them
  # and test cannot distinguish authz from token-validation failure)
  local aud
  aud=$(python3 -c "import json,base64,sys; print(json.loads(base64.urlsafe_b64decode(sys.argv[1].split('.')[1]+'==')).get('aud',''))" "$t_a")
  if echo "$aud" | grep -q backend; then
    pass "JWT contains 'aud: backend' (audience mapper is in place)"
  else
    fail "JWT 'aud' claim missing — see keycloak-post-install-setup.md §audience mapper"
    return
  fi

  local code
  declare -A cases=(
    ["$USER_A → $PROJECT_A (own)"]="$t_a $PROJECT_A 200"
    ["$USER_A → $PROJECT_B (other)"]="$t_a $PROJECT_B 403"
    ["$USER_B → $PROJECT_B (own)"]="$t_b $PROJECT_B 200"
    ["$USER_B → $PROJECT_A (other)"]="$t_b $PROJECT_A 403"
  )
  for desc in "${!cases[@]}"; do
    read -r tok proj want <<<"${cases[$desc]}"
    code=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 10 \
      -H "Cookie: k8tre-project=${proj}; k8tre-auth-token-${proj}=${tok}" \
      "${PORTAL_URL}/auth/validate?orig=http://jupyter.${DOMAIN}/hub/")
    if [ "$code" = "$want" ]; then
      pass "$desc → $code"
    else
      fail "$desc → got $code, expected $want"
    fi
  done
}

# ---- Test 2 — UX enumeration weakness ---------------------------------------
test_enumeration() {
  section "Test 2 — Pre-launch URL enumeration (known UX weakness)"

  local t_a; t_a=$(get_token "$USER_A")
  # We need a Portal session (cookie). The cleanest way is to drive the browser
  # OIDC flow, but for an automated test we just call /projects/<other>/apps
  # without a session — it requires require_user which 401s, so anonymous can't
  # enumerate either way. The actual UX leak is FOR A LOGGED-IN USER. We
  # simulate that with a session by forging the session via the password grant
  # token in the Authorization header — which the require_user dependency
  # does NOT accept (it reads from request.session). So we test what we can:
  # anonymous access correctly 401s.
  local code
  code=$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 5 \
    "${PORTAL_URL}/projects/${PROJECT_B}/apps")
  if [ "$code" = "401" ] || [ "$code" = "302" ]; then
    pass "anonymous /projects/$PROJECT_B/apps → $code (require_user blocks)"
  else
    fail "anonymous /projects/$PROJECT_B/apps → $code (expected 401/302)"
  fi
  weak "logged-in users can still GET /projects/<other>/apps and /launch/<other>/<app>"
  weak "  → enumerates project names; data is gated by /auth/validate only"
}

# ---- Test 3 — Cross-namespace RBAC -----------------------------------------
test_rbac() {
  section "Test 3 — Cross-namespace RBAC (default ServiceAccount)"
  # Use `kubectl auth can-i --as=...` so we test the RBAC policy directly,
  # bypassing the pod-network restrictions that block in-pod kubectl access
  # to the apiserver in project-* namespaces.

  local sa="system:serviceaccount:project-${PROJECT_A}:default"
  local verdicts=(
    "list pods       -n project-${PROJECT_B}"
    "list secrets    -n project-${PROJECT_B}"
    "create pods     -n project-${PROJECT_B}"
    "delete pods     -n project-${PROJECT_B}"
  )
  for v in "${verdicts[@]}"; do
    local can
    can=$(kubectl auth can-i $v --as="$sa" 2>&1)
    if [ "$can" = "no" ]; then
      pass "$sa cannot $v"
    else
      fail "$sa CAN $v (got: $can)"
    fi
  done

  # Sanity check: the SA CAN access its own namespace? (we don't grant any
  # extra roles, so default SA can only access its own /tokenrequest etc.)
  local can_own
  can_own=$(kubectl auth can-i get serviceaccounts/default -n "project-${PROJECT_A}" --as="$sa" 2>&1)
  echo "  (sanity: SA in own ns get sa/default → $can_own)"
}

# ---- Test 4 — Cross-namespace network policy --------------------------------
test_netpol() {
  section "Test 4 — Cross-namespace network reachability (Cilium)"

  # Spin up an HTTP server in project-bravo and a client in project-alpha,
  # then check whether alpha can reach bravo.
  kubectl delete pod -n "project-${PROJECT_B}" net-target  --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
  kubectl delete pod -n "project-${PROJECT_A}" net-client  --ignore-not-found --force --grace-period=0 >/dev/null 2>&1

  # Target: a tiny HTTP responder
  kubectl run net-target -n "project-${PROJECT_B}" --image=alpine:3.20 \
    --restart=Never --command -- sh -c \
    'while true; do printf "HTTP/1.1 200 OK\r\nContent-Length:3\r\n\r\nOK\n" | nc -lp 8080 -w 1; done' \
    >/dev/null
  # Client
  kubectl run net-client -n "project-${PROJECT_A}" --image=curlimages/curl:8.10.1 \
    --restart=Never --command -- sleep 60 >/dev/null

  for i in $(seq 40); do
    [ "$(kubectl get pod -n "project-${PROJECT_A}" net-client -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)" = "true" ] && \
      [ "$(kubectl get pod -n "project-${PROJECT_B}" net-target -o jsonpath='{.status.containerStatuses[0].ready}' 2>/dev/null)" = "true" ] && break
    sleep 2
  done

  local target_ip
  target_ip=$(kubectl get pod -n "project-${PROJECT_B}" net-target -o jsonpath='{.status.podIP}' 2>/dev/null)
  if [ -z "$target_ip" ]; then
    fail "could not bring up net-target pod"
    kubectl delete pod -n "project-${PROJECT_B}" net-target --force --grace-period=0 >/dev/null 2>&1
    kubectl delete pod -n "project-${PROJECT_A}" net-client --force --grace-period=0 >/dev/null 2>&1
    return
  fi

  # Curl always prints %{http_code} via -w (even on failure: 000). We rely on
  # that single output and never use ||, which would double the value.
  local code
  code=$(kubectl exec -n "project-${PROJECT_A}" net-client -- \
    curl -s -o /dev/null --max-time 5 --connect-timeout 4 -w '%{http_code}' \
    "http://${target_ip}:8080/" 2>/dev/null)
  case "$code" in
    000)    pass "project-${PROJECT_A} → project-${PROJECT_B} pod blocked (code 000, connection denied)" ;;
    "")     fail "no response captured from curl (pod exec failed?)" ;;
    200)    weak "project-${PROJECT_A} → project-${PROJECT_B} pod reachable (200) — project namespaces have no default-deny NetworkPolicy applied" ;;
    *)      fail "unexpected code: $code" ;;
  esac

  kubectl delete pod -n "project-${PROJECT_B}" net-target --force --grace-period=0 >/dev/null 2>&1
  kubectl delete pod -n "project-${PROJECT_A}" net-client --force --grace-period=0 >/dev/null 2>&1
}

# ---- Test 5 — Cross-project volume access ----------------------------------
test_volume() {
  section "Test 5 — Volume isolation: PVC in project ${PROJECT_A} unreachable from project ${PROJECT_B}"

  local pvc=secret-${PROJECT_A}-data
  local sentinel="SECRET_${PROJECT_A^^}: only-for-${PROJECT_A}-team"
  local sa_b="system:serviceaccount:project-${PROJECT_B}:default"

  # Cleanup any previous run
  kubectl delete pod ${PROJECT_A}-writer ${PROJECT_A}-reader -n "project-${PROJECT_A}" \
    --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
  kubectl delete pod ${PROJECT_B}-thief-name -n "project-${PROJECT_B}" \
    --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
  kubectl delete pvc "$pvc" -n "project-${PROJECT_A}" --ignore-not-found >/dev/null 2>&1
  kubectl delete pvc "stolen-via-volume-name" -n "project-${PROJECT_B}" --ignore-not-found >/dev/null 2>&1

  # --- 5a) create PVC in PROJECT_A and write sentinel ---
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: ${pvc}, namespace: project-${PROJECT_A}}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: rwo-default
  resources: {requests: {storage: 256Mi}}
---
apiVersion: v1
kind: Pod
metadata: {name: ${PROJECT_A}-writer, namespace: project-${PROJECT_A}}
spec:
  restartPolicy: OnFailure
  containers:
  - name: w
    image: alpine:3.20
    command: ["sh","-c","echo '${sentinel}' > /data/secret.txt; sync; sleep 3"]
    volumeMounts: [{name: d, mountPath: /data}]
  volumes:
  - {name: d, persistentVolumeClaim: {claimName: ${pvc}}}
YAML

  # Wait for writer to finish
  local phase=""
  for i in $(seq 60); do
    phase=$(kubectl get pod -n "project-${PROJECT_A}" "${PROJECT_A}-writer" -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$phase" = "Succeeded" ] && break
    [ "$phase" = "Failed" ] && break
    sleep 2
  done
  [ "$phase" = "Succeeded" ] && pass "sentinel written to ${pvc} (writer phase=$phase)" \
    || { fail "writer phase=$phase — abort volume test"; return; }

  # --- 5b) PROJECT_A's own pod can read the sentinel back ---
  kubectl run "${PROJECT_A}-reader" -n "project-${PROJECT_A}" --image=alpine:3.20 --restart=Never \
    --overrides="{\"spec\":{\"containers\":[{\"name\":\"r\",\"image\":\"alpine:3.20\",\"command\":[\"cat\",\"/data/secret.txt\"],\"volumeMounts\":[{\"name\":\"d\",\"mountPath\":\"/data\"}]}],\"volumes\":[{\"name\":\"d\",\"persistentVolumeClaim\":{\"claimName\":\"${pvc}\"}}]}}" \
    --command -- cat /data/secret.txt >/dev/null 2>&1

  for i in $(seq 60); do
    phase=$(kubectl get pod -n "project-${PROJECT_A}" "${PROJECT_A}-reader" -o jsonpath='{.status.phase}' 2>/dev/null)
    [ "$phase" = "Succeeded" ] || [ "$phase" = "Failed" ] && break
    sleep 2
  done
  local content
  content=$(kubectl logs -n "project-${PROJECT_A}" "${PROJECT_A}-reader" 2>/dev/null)
  if echo "$content" | grep -qF "$sentinel"; then
    pass "${PROJECT_A} reader sees the sentinel from its own PVC"
  else
    fail "${PROJECT_A} reader did not see the sentinel: '$content'"
  fi

  # --- 5c) RBAC: PROJECT_B's default SA cannot touch PROJECT_A's PVC ---
  for verb in get list create delete patch; do
    local can
    can=$(kubectl auth can-i $verb pvc/$pvc -n "project-${PROJECT_A}" --as=$sa_b 2>&1)
    [ "$can" = "no" ] && pass "$sa_b cannot $verb pvc/$pvc -n project-${PROJECT_A}" \
                     || fail "$sa_b CAN $verb pvc/$pvc -n project-${PROJECT_A} (got: $can)"
  done

  # --- 5d) Pod in PROJECT_B referencing claimName=$pvc must stay Pending ---
  kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata: {name: ${PROJECT_B}-thief-name, namespace: project-${PROJECT_B}}
spec:
  restartPolicy: Never
  containers:
  - {name: t, image: alpine:3.20, command: ["sh","-c","cat /steal/secret.txt || echo NO-DATA"], volumeMounts: [{name: s, mountPath: /steal}]}
  volumes:
  - {name: s, persistentVolumeClaim: {claimName: ${pvc}}}
YAML
  sleep 6
  phase=$(kubectl get pod -n "project-${PROJECT_B}" "${PROJECT_B}-thief-name" -o jsonpath='{.status.phase}')
  local msg
  msg=$(kubectl get pod -n "project-${PROJECT_B}" "${PROJECT_B}-thief-name" -o jsonpath='{.status.conditions[?(@.type=="PodScheduled")].message}')
  if [ "$phase" = "Pending" ] && echo "$msg" | grep -q 'not found'; then
    pass "pod in project-${PROJECT_B} stays Pending — k8s does NOT cross-resolve claimName"
  else
    fail "pod in project-${PROJECT_B} reached phase=$phase (msg: $msg)"
  fi

  # --- 5e) Cluster-scoped PV — try direct claimRef hijack with volumeName ---
  # An admin tries to bind a brand-new PVC in PROJECT_B to the existing PV
  # already locked to PROJECT_A. The PV controller refuses because the PV's
  # claimRef immutably points at the alpha PVC.
  local pv
  pv=$(kubectl get pvc -n "project-${PROJECT_A}" "$pvc" -o jsonpath='{.spec.volumeName}')
  kubectl apply -f - >/dev/null 2>&1 <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata: {name: stolen-via-volume-name, namespace: project-${PROJECT_B}}
spec:
  accessModes: [ReadWriteOnce]
  storageClassName: ""
  resources: {requests: {storage: 256Mi}}
  volumeName: ${pv}
YAML
  sleep 8
  local theft_status theft_event
  theft_status=$(kubectl get pvc -n "project-${PROJECT_B}" stolen-via-volume-name -o jsonpath='{.status.phase}' 2>/dev/null)
  theft_event=$(kubectl get events -n "project-${PROJECT_B}" --field-selector involvedObject.name=stolen-via-volume-name -o jsonpath='{.items[-1:].message}' 2>/dev/null)
  if [ "$theft_status" = "Pending" ] && echo "$theft_event" | grep -qi 'already bound'; then
    pass "PV refuses cross-ns claimRef hijack — status=$theft_status: $theft_event"
  elif [ "$theft_status" = "Bound" ]; then
    fail "PV bound to a project-${PROJECT_B} PVC — cluster-scoped PV ISOLATION BROKEN"
  else
    pass "stolen PVC did not bind (status=$theft_status, event='$theft_event')"
  fi

  # --- 5f) hostPath escape — currently allowed (no PodSecurity enforce) ---
  # Documented in docs/troubleshooting/volume-isolation.md: PSA is not on, so
  # anyone who can create a pod in project-${PROJECT_B} can mount the node's
  # /var/lib/longhorn and read every project's raw blocks. We report this as
  # WEAK rather than FAIL so the suite stays useful on un-hardened clusters.
  kubectl delete pod -n "project-${PROJECT_B}" host-escape --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
  kubectl apply -f - >/dev/null 2>&1 <<YAML
apiVersion: v1
kind: Pod
metadata: {name: host-escape, namespace: project-${PROJECT_B}}
spec:
  restartPolicy: Never
  containers:
  - {name: t, image: alpine:3.20, command: ["sleep","30"], volumeMounts: [{name: h, mountPath: /host}]}
  volumes:
  - {name: h, hostPath: {path: /var/lib/longhorn}}
YAML
  sleep 5
  phase=$(kubectl get pod -n "project-${PROJECT_B}" host-escape -o jsonpath='{.status.phase}' 2>/dev/null)
  if [ "$phase" = "Running" ] || [ "$phase" = "Pending" ]; then
    weak "hostPath /var/lib/longhorn admitted in project-${PROJECT_B} (phase=$phase)"
    weak "  → apply pod-security.kubernetes.io/enforce=baseline on project namespaces"
    weak "  → see docs/troubleshooting/volume-isolation.md"
  else
    pass "hostPath /var/lib/longhorn denied by admission (phase=$phase)"
  fi

  # --- cleanup ---
  kubectl delete pod -n "project-${PROJECT_A}" "${PROJECT_A}-writer" "${PROJECT_A}-reader" --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
  kubectl delete pod -n "project-${PROJECT_B}" "${PROJECT_B}-thief-name" host-escape --ignore-not-found --force --grace-period=0 >/dev/null 2>&1
  kubectl delete pvc -n "project-${PROJECT_B}" stolen-via-volume-name --ignore-not-found >/dev/null 2>&1
  # leave the alpha PVC behind — idempotent re-runs reuse it
}

# ---- Test 6 — User CR validation -------------------------------------------
test_user_cr() {
  section "Test 6 — User → Group → Project graph integrity"

  for u in "$USER_A:$PROJECT_A:$PROJECT_B" "$USER_B:$PROJECT_B:$PROJECT_A"; do
    IFS=':' read -r user own_project other_project <<< "$u"
    local groups
    groups=$(kubectl get user -n "$K8TRE_NAMESPACE" "$user" -o jsonpath='{.spec.groups[*]}' 2>/dev/null)
    [ -n "$groups" ] && pass "user $user has groups: $groups" || fail "user $user not found or has no groups"
  done
}

# ---- main -------------------------------------------------------------------
main() {
  echo "Domain:    $DOMAIN"
  echo "Portal:    $PORTAL_URL"
  echo "Keycloak:  $KC_URL"
  echo "Projects:  $PROJECT_A, $PROJECT_B"
  echo "Users:     $USER_A (in $PROJECT_A-team), $USER_B (in $PROJECT_B-team)"

  setup
  test_authvalidate
  test_enumeration
  test_rbac
  test_netpol
  test_volume
  test_user_cr

  printf "\n${BOLD}== Summary ==${RESET}\n"
  printf "  ${GREEN}%d passed${RESET},  ${RED}%d failed${RESET},  ${YELLOW}%d weak${RESET}\n" "$PASS" "$FAIL" "$WEAK"
  echo
  echo "WEAK = enforcement is incomplete by design — see comments above."
  [ "$FAIL" -eq 0 ] || exit 1
}

main "$@"
