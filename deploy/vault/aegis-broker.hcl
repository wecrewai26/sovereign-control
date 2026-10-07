# Vault policy for the AEGIS credential broker (spec §51).
#
# AEGIS may only *generate* the specific dynamic credentials its tools are mapped to,
# and revoke leases. It cannot read static secrets, change Vault configuration, or
# create tokens. Each role below (pod-restarter, dba, ...) should itself be scoped to
# the least the tool needs, with a short max TTL, e.g.:
#
#   vault write kubernetes/roles/production-pod-restarter \
#       allowed_kubernetes_namespaces="shop,payments" \
#       generated_role_rules='{"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get","list","delete"]}]}' \
#       token_default_ttl=5m token_max_ttl=15m
#
# Attach this policy to the AppRole or Kubernetes auth role AEGIS logs in with:
#   vault policy write aegis-broker deploy/vault/aegis-broker.hcl

# Kubernetes secrets engine: short-lived service account tokens.
path "kubernetes/creds/production-pod-restarter" {
  capabilities = ["update"]
}
path "kubernetes/creds/staging-pod-restarter" {
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
