# Kubernetes - nastavení pro acme

acme komunikuje s API serverem Kubernetes pomocí bearer tokenu service accountu a vytvoří (`POST`) nebo aktualizuje (merge `PATCH`) secret typu `kubernetes.io/tls` - `tls.crt` (celý řetězec), `tls.key` a volitelně `ca.crt` - se štítkem `app.kubernetes.io/managed-by: acme`. Ingress controllery, gatewaye a pody, které ten secret čtou, převezmou nový certifikát. Na požádání acme udělá i **rollout restart** deploymentů, které secret čtou jen při startu. Duální certifikát (ECDSA + RSA) jde do téhož secretu: druhý jako `tls-rsa.crt` / `tls-rsa.key` (nebo `tls-ec.*`).

## Co potřebujete

- Jakýkoli současný Kubernetes (nebo OpenShift, k3s, RKE2, AKS, EKS, GKE …) s API serverem dosažitelným z acme přes HTTPS (obvykle port 6443, u spravovaných clusterů 443).
- Service account s Role v namespace, která smí **get, list, create a patch secrets** (a **patch deployments**, má-li je acme restartovat).
- CA certifikát API serveru (nebo veřejný certifikát na API serveru).

## Nastavení Kubernetes

1. Vytvořte service account, Role a RoleBinding v rámci namespace (`web` změňte na svůj namespace; Role/RoleBinding zopakujte pro každý namespace, do kterého acme zapisuje):

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
  verbs: [patch]            # potřeba jen pro "Restart these deployments"
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

2. Přečtěte dlouhodobý token a CA clusteru:

```sh
kubectl -n web get secret acme-deployer-token -o jsonpath='{.data.token}' | base64 -d; echo
kubectl -n web get secret acme-deployer-token -o jsonpath='{.data.ca\.crt}' | base64 -d
kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}'; echo
```

   (Místo secretu s dlouhodobým tokenem můžete použít `kubectl -n web create token acme-deployer --duration=8760h`, pak ale musíte token v acme obnovit, než vyprší.) **Token může číst všechny secrety v namespace - chraňte ho jako heslo.**

3. Nasměrujte svůj Ingress / Gateway na jméno secretu, které bude acme používat (`spec.tls[].secretName`).

## Vyplnění v acme

| Pole v acme | Co do něj zadat |
|---|---|
| API server | např. `https://k8s.example.local:6443` |
| Bearer token | token service accountu z kroku 2 |
| Namespace | výchozí namespace, např. `web` |
| Check the device's certificate | zapnuto |
| CA certificate (pokročilé) | CA clusteru (`ca.crt`) z kroku 2, když certifikát API serveru není veřejný |
| Secret name (nasazení) | jméno secretu, např. `www-example-com-tls`; prázdné: jméno certifikátu |
| Namespace (nasazení) | prázdné: namespace cíle; nebo jiný namespace (potřebuje vlastní Role) |
| Add ca.crt (the chain) | zapnout, když některý konzument potřebuje `ca.crt` (např. pro kontrolu klientů) |
| Restart these deployments (pokročilé) | jména deploymentů v namespace, jedno na řádek - pro aplikace, které čtou certifikát jen při startu |
| Check what is served | `www.example.com:443`, jeden na řádek |

## Ověření

- **Test** v acme přečte `/version` a vypíše secrety v namespace (`signed in to Kubernetes v1.x, secrets in web can be read`).
- V clusteru:

```sh
kubectl -n web get secret www-example-com-tls -o jsonpath='{.data.tls\.crt}' | base64 -d \
  | openssl x509 -noout -subject -enddate
kubectl auth can-i patch secrets -n web --as system:serviceaccount:web:acme-deployer
```

## Časté problémy

| Problém | Řešení |
|---|---|
| 401 Unauthorized | špatný nebo prošlý token (tokeny z `kubectl create token` vyprší) |
| 403 Forbidden … secrets | v tom namespace chybí Role/RoleBinding, nebo jí chybí sloveso |
| 403 … deployments | přidejte do Role `patch` na `deployments` (apps), nebo vyprázdněte *Restart these deployments* |
| Chyba TLS při spojení s API serverem | vložte CA clusteru do *CA certificate* |
| `… is a secret of another type` | secret toho jména existuje s jiným typem; zvolte jiné jméno nebo ho smažte |
| Ingress podává starý certifikát | Ingress odkazuje na jiné jméno secretu / namespace, nebo ho controller drží v cache - podívejte se do jeho logů |
