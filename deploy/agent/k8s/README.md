# acme-agent for Kubernetes - a guide

acme-agent in a pod of its own writes `kubernetes.io/tls` Secrets (and restarts a Deployment that
uses one) only in the namespaces and under the names its policy allows. What it is and how it
decides: [docs/agent-fleet.md](../../../docs/agent-fleet.md), *Kubernetes*.

## 1. The image

From the folder `deploy/agent` of acme (its program and this folder):

```
cd deploy/agent
docker build -f k8s/Dockerfile --build-arg ACME_VERSION=1.0.138 \
  -t registry.example.net/acme-agent-k8s:1.0.138 .
docker push registry.example.net/acme-agent-k8s:1.0.138
```

Python's standard library and openssl, nothing else; it runs as the account 10001.

## 2. The target in acme

Targets → *Add a target* → **Server with acme-agent**: a name (`k8s-shop`), the mode -

* **passive** (acme connects to the pod): the address acme reaches the Service at (a
  LoadBalancer, a NodePort) and its port (8446);
* **active** (the pod connects to acme - nothing to open in the cluster): Settings → Target agents
  → *Agents may connect to acme* first.

On its card: **Join the agent…** → the join code (`ACAG1.…`, an hour, once). Many clusters: a
company enrollment code (Settings → Target agents) - each pod becomes a target of its own.

## 3. The manifests

Edit [manifests.yaml](manifests.yaml):

* the image;
* **its policy** (the ConfigMap `acme-agent-policy`): the Secrets and Deployments acme may touch;
* **one Role and RoleBinding per namespace** - the Secrets named (`get`, `update`,
  `delete`), `create` (Kubernetes cannot limit it by name: the policy does), `list` only with
  `allow discover`, the Deployments it may restart (`patch`). Nothing else - not the
  ConfigMap, not its own namespace;
* passive: the Service and the NetworkPolicy (acme's addresses only); active: delete both. The
  Service keeps `externalTrafficPolicy: Local`: with the default (`Cluster`) the pod and the
  NetworkPolicy see a node's address instead of acme's, and `allow from` refuses acme.

Then the join code, and everything:

```
kubectl create namespace acme-agent
kubectl -n acme-agent create secret generic acme-agent-join --from-literal=code='ACAG1....'
kubectl apply -f manifests.yaml
kubectl -n acme-agent logs deploy/acme-agent        # the fingerprint to confirm
```

The code is read on the first start only (a pod whose volume holds a joined agent ignores it);
delete the Secret `acme-agent-join` once the agent has joined. Or join by hand:

```
kubectl -n acme-agent exec deploy/acme-agent -- \
  python3 -I /opt/acme-agent/acme_k8s_agent.py join 'ACAG1....' --no-wait
```

## 4. Confirm it in acme

The target's card shows the agent asking to join with its fingerprint - compare it with the one in
the pod's log (or `… acme_k8s_agent.py fingerprint`) and **Confirm**. The card then shows its
policy as acme reads it (folders `/k8s/NAMESPACE/NAME`), the fleet shows it as *Kubernetes*.

## 5. A certificate into a Secret

The certificate's deployment to the target, *Files*:

```
fullchain-pem /k8s/shop/web-tls/tls.crt 0644 root:root
key-pem       /k8s/shop/web-tls/tls.key 0600 root:root
```

*After the files*: `kubectl rollout restart deployment/web -n shop`. The form says whether the
policy allows it; a line missing is the line to add to the ConfigMap (`kubectl -n acme-agent edit
configmap acme-agent-policy` - the pod reads it anew for every job).

## On the pod

```
kubectl -n acme-agent exec deploy/acme-agent -- python3 -I /opt/acme-agent/acme_k8s_agent.py policy
kubectl -n acme-agent exec deploy/acme-agent -- python3 -I /opt/acme-agent/acme_k8s_agent.py status
```

Every operation, refusals too, goes to the pod's log and to `/var/lib/acme-agent/work/audit.log`
(names and hashes, never a key). Its state (its keys, its certificate, what it pinned) is the
volume `acme-agent-state`: a pod made again keeps its identity; a new volume joins again.

Updating: a new image (`kubectl -n acme-agent set image deployment/acme-agent
acme-agent=registry.example.net/acme-agent-k8s:1.0.139`) - acme never updates it.
