# Kubernetes - setup for acme

acme talks to the Kubernetes API server with a service account's bearer token and makes (`POST`) or updates (merge `PATCH`) a secret of type `kubernetes.io/tls` - `tls.crt` (the full chain), `tls.key` and optionally `ca.crt` - labelled `app.kubernetes.io/managed-by: acme`. Ingress controllers, gateways and pods that read that secret pick up the new certificate. When asked, acme also does a **rollout restart** of deployments that only read the secret at start. A dual certificate (ECDSA + RSA) goes into the same secret: the second one as `tls-rsa.crt` / `tls-rsa.key` (or `tls-ec.*`).

## What you need

- Any current Kubernetes (or OpenShift, k3s, RKE2, AKS, EKS, GKE …) with the API server reachable from acme over HTTPS (usually port 6443, or 443 for managed clusters).
- A service account with a Role in the namespace that may **get, list, create and patch secrets** (and **patch deployments** if acme is to restart them).
- The API server's CA certificate (or a public certificate on the API server).

## Set up Kubernetes

1. Create a namespace-scoped service account, Role and RoleBinding (change `web` to your namespace; repeat the Role/RoleBinding for every namespace acme writes to):

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: {name: acme-deployer, namespace: web}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: {name: acme-deployer, namespace: web}
rules:
- apiGroups: [""]
  resources: [secrets]
  verbs: [get, list, create, patch]
- apiGroups: [apps]
  resources: [deployments]
  verbs: [patch]            # only needed for "Restart these deployments"
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: {name: acme-deployer, namespace: web}
subjects:
- {kind: ServiceAccount, name: acme-deployer, namespace: web}
roleRef: {apiGroup: rbac.authorization.k8s.io, kind: Role, name: acme-deployer}
---
apiVersion: v1
kind: Secret
metadata:
  name: acme-deployer-token
  namespace: web
  annotations: {kubernetes.io/service-account.name: acme-deployer}
type: kubernetes.io/service-account-token
```

```sh
kubectl apply -f acme-deployer.yaml
```

2. Read the long-lived token and the cluster CA:

```sh
kubectl -n web get secret acme-deployer-token -o jsonpath='{.data.token}' | base64 -d; echo
kubectl -n web get secret acme-deployer-token -o jsonpath='{.data.ca\.crt}' | base64 -d
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'; echo
```

   (Instead of the long-lived token secret you can use `kubectl -n web create token acme-deployer --duration=8760h`, but then you must renew it in acme before it expires.) **The token can read every secret in the namespace - keep it like a password.**

3. Point your Ingress / Gateway at the secret name acme will use (`spec.tls[].secretName`).

## Fill in acme

| acme field | What to put there |
|---|---|
| API server | e.g. `https://k8s.example.local:6443` |
| Bearer token | the service account token from step 2 |
| Namespace | the default namespace, e.g. `web` |
| Check the device's certificate | on |
| CA certificate (advanced) | the cluster CA (`ca.crt`) from step 2, when the API server's certificate is not public |
| Secret name (deployment) | the secret's name, e.g. `www-example-com-tls`; empty: the certificate's name |
| Namespace (deployment) | empty: the target's; or another namespace (it needs its own Role) |
| Add ca.crt (the chain) | on when a consumer needs `ca.crt` (e.g. for client checks) |
| Restart these deployments (advanced) | deployment names in the namespace, one a line - for apps that read the certificate only at start |
| Check what is served | `www.example.com:443`, one a line |

## Check it

- **Test** in acme reads `/version` and lists secrets in the namespace (`signed in to Kubernetes v1.x, secrets in web can be read`).
- In the cluster:

```sh
kubectl -n web get secret www-example-com-tls -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -noout -subject -enddate
kubectl auth can-i patch secrets -n web --as system:serviceaccount:web:acme-deployer
```

## Common problems

| Problem | Fix |
|---|---|
| 401 Unauthorized | wrong or expired token (tokens from `kubectl create token` expire) |
| 403 Forbidden … secrets | the Role/RoleBinding is missing in that namespace, or lacks a verb |
| 403 … deployments | add `patch` on `deployments` (apps) to the Role, or empty *Restart these deployments* |
| TLS error to the API server | put the cluster CA into *CA certificate* |
| `… is a secret of another type` | a secret of that name exists with another type; choose another name or delete it |
| The ingress serves the old certificate | the Ingress refers to another secret name / namespace, or the controller caches it - check its logs |
