# Vault policy for the AEGIS credential broker (spec §51).
#
# AEGIS may only *generate* the specific dynamic credentials its tools are mapped to,
# and revoke leases. It cannot read static secrets, change Vault configuration, or
# create tokens. Each role below (pod-restarter, dba, ...) should itself be scoped to
# the least the tool needs, with a short max TTL. For the Kubernetes pack
# (sovereign_control.tools.kubernetes), one role covering all five tools needs:
#
#   vault write kubernetes/roles/production-remediation \
#       allowed_kubernetes_namespaces="shop,payments" \
#       token_default_ttl=5m token_max_ttl=15m \
#       generated_role_rules='{"rules":[
#         {"apiGroups":[""],"resources":["pods"],"verbs":["get","list","delete"]},
#         {"apiGroups":["apps"],"resources":["replicasets","statefulsets","daemonsets"],"verbs":["get","list"]},
#         {"apiGroups":["apps"],"resources":["deployments"],"verbs":["get","patch","update"]}]}'
#
# or one role per tool, so a read-only tool's credential cannot delete anything.
#
# The Control Tower's cluster pages request credentials for the pseudo-tool "k8s.read".
# Give that its own read-only role (note pods/log, and no write verbs at all):
#
#   vault write kubernetes/roles/production-viewer \
#       allowed_kubernetes_namespaces="shop,payments" \
#       token_default_ttl=2m token_max_ttl=5m \
#       generated_role_rules='{"rules":[
#         {"apiGroups":[""],"resources":["pods","pods/log","events"],"verbs":["get","list"]},
#         {"apiGroups":["apps"],"resources":["deployments","replicasets"],"verbs":["get","list"]}]}'
#
# and map it: VaultCredentialSpec("kubernetes/creds/{environment}-viewer",
#                                 data={"kubernetes_namespace": "{param:namespace}"})
#
# Attach this policy to the AppRole or Kubernetes auth role AEGIS logs in with:
#   vault policy write aegis-broker deploy/vault/aegis-broker.hcl

# Kubernetes secrets engine: short-lived service account tokens.
path "kubernetes/creds/production-remediation" {
  capabilities = ["update"]
}
path "kubernetes/creds/staging-remediation" {
  capabilities = ["update"]
}

path "kubernetes/creds/production-viewer" {
  capabilities = ["update"]
}

# Database secrets engine: short-lived database users.
path "database/creds/production-dba" {
  capabilities = ["read"]
}

# Revoke a lease as soon as the action finishes.
path "sys/leases/revoke" {
  capabilities = ["update"]
}
