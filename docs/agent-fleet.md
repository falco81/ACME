# The fleet of target agents (1.0.138)

**Settings → Agent fleet** shows every server with acme-agent at once: how healthy each is, the
**policy templates** they should follow and how far each has drifted from its template, the
**versions** and **updates in rings**, and the **certificates found on the servers that acme does
not manage yet** - each taken over with a preview of what happens. And acme-agent comes as a
**pod for Kubernetes** that writes `kubernetes.io/tls` Secrets.

Nothing of it changes what an agent may do: a template, like a design
([target-agent.md](target-agent.md), *Designing the policy*), is documentation - acme never sends
a policy, root writes it on the server. An installation that uses none of it is as before: no
group, no template followed, no rollout, the pages of Target agents unchanged.

## The page

* **The hero**: the fleet's health as a ring (green answers and nothing to look at, amber to
  look at - its policy blocks a deployment, its certificate ends within 14 days, its server needs
  a look, it drifted from its template -, red not heard from or refused, grey not joined yet),
  what needs a look as tiles (a click opens the view), the agents by kind (Linux, Windows,
  Kubernetes) and the **versions** as a chart: the one acme offers green, older ones amber, with
  their share.
* **Groups** - a card a group: its health ring, its members as avatars (a click opens the
  agent's target), the template its agents follow and how many drifted, its versions, and the
  actions on all its agents: **Ask now**, **Update** (only where a newer agent is offered),
  **Compare** (the drift view). The agents in no group have a card of their own. *New group* and
  the pencil (a full administrator): name, colour, note, the template, the **canary ring** (one
  group at most), its members (found by name, host, version).
* **Agents** - every agent with its state, version (*newer offered*), groups and template
  (*matches*, *drifted*, *not asked yet*, *other platform*); filtered (in trouble, to look at,
  drifted, to update) and searched. Choose some (or all shown) for **Ask now**, **Update**,
  **Compare with the template**, **Template…** (the template each of them follows) and **Add to a
  group…**.
* **Templates** - the built-in ones and the administrators' own, each with its lines, how many
  agents follow it, **Copy** (the policy file), **Open in the builder…** and (own ones) *Delete*.
* **Updates** - the versions, and **an update in rings** (below).
* **Not managed** - the certificates discovery found (below), the most urgent first.

The page asks again every 30 seconds while it is shown; the view chosen is remembered in the
browser.

## Policy templates

A template is a whole policy for one kind of server. **Built-in** (made from the policy builder's
own templates - the same folders, owners, modes, units and tests as the deployment presets):

| Template | For | What it allows |
|---|---|---|
| nginx web | Linux | `/etc/nginx/ssl`, `nginx.service` reload, `nginx -t`, a test of what it serves |
| Apache (RHEL, Rocky, Alma) / Apache (Debian, Ubuntu) | Linux | the preset's folder, `httpd` / `apache2` reload, the config tests |
| HAProxy | Linux | `/etc/haproxy/certs`, reload, `haproxy -c` |
| Postfix + Dovecot | Linux | both folders, their checks and reloads |
| Exim, OpenLDAP, PostgreSQL | Linux | the preset's folder, unit and test |
| IIS | Windows | the machine store, every site's https bindings (`allow iis *`) |
| Remote Desktop | Windows | the machine store, the listener |
| IIS + Remote Desktop | Windows | both |

**Your own**: in the policy builder (the agent's card → *Design its policy…*), **Save as a fleet
template** (a full administrator) keeps the policy clicked together under the title given - the
same title again saves a new version of it (the last ten kept). Its text is read as the agent
reads a policy file: a line it would not read is refused. A template saved through the API
without the builder's state gets one made from its lines.

**In the builder**, the section *Templates* starts with **Fleet templates** (those of the agent's
platform): one click adds all of one to what is there (nothing taken away); a template whose
lines are all there is ticked. *Open in the builder…* on the Templates view starts the builder
from that template (*Start from: the fleet template*) with an agent of its platform - the builder
checks as that agent checks; nothing is sent.

**What the agent deploys** (1.0.140, [target-agent.md](target-agent.md) *What the agent
deploys*): a template holds `allow issuer sha256=HEX`, `allow names ...` and `require key local`
as any line - clicked together in the builder's *What it deploys* (the CAs acme knows, the names)
or written in its text; the template's state carries them (`issuers`, `names`, `key_local`), and
an agent following it drifts when its policy lacks one of them. The built-in templates have none:
the CAs and names are yours. A Kubernetes agent takes `allow issuer` and `allow names`, never
`require key local` (it makes no key).

Kept in `meta` (`fleet:tpl:<id>`): in every backup, on both nodes of a cluster, put back by a
restore, as the agents' designs are. Deleting a template: the agents and groups that followed it
follow none.

## Groups and which template an agent follows

A group (`fleet:group:<id>`) has a name, a colour, a note, its members (targets with acme-agent),
the template its members follow and whether it is the canary ring. An agent follows **its own
template** (*Template…* on the Agents view - `fleet:assign:<target id>`) when it has one, else
the template of its first group (by name) that names one.

**The drift**: the template's lines against the policy the agent last said (as `acme-agent policy
show` writes them): *matches*; *drifted* - the lines **missing on the server** (green +) and those
**on the server besides the template** (red −); *not asked yet* (the agent has not said its
policy - Ask now); *other platform* (a Windows template for a Linux agent). **Copy the lines to
make it match** copies one block for a root shell (`sudo acme-agent policy apply - <<'EOF' …`;
on Windows the policy file, applied with `acme-agent policy apply FILE` in an elevated prompt).

For other code (the agents' drift alerts): `acmelib/certs/fleet.py`

    agent_template(store, agent_id) -> {ref, title, note, platform, builtin, text, lines, via:
                                        agent | group, group, target, target_id} | None
    drift(store, row, policy=None)  -> {state: matches | differs | unknown | other, missing,
                                        extra, template: {ref, title, via, group}} | None

`agent_id` is the target's id, its name or the agent's id (`ag-…`).

## Actions on many agents

**Ask now** (a certificate administrator) and **Update** (a full administrator) run as one job
(kind *action*) whose steps say each agent: *answers (acme-agent 1.0.138)*, *not updated - its
policy has no allow self-update*, *updated to …*. The page shows the job and asks the fleet again
when it ends. An update is only ever acme's own signed package and only where the agent's policy
says `allow self-update` ([target-agent.md](target-agent.md), *Updates of the agent*).

## Updates in rings

**Updates → An update in rings** (a full administrator):

1. **the canary ring** - the canary group, or without one 5 % of the agents (at least one) - is
   updated at once;
2. **the wait** (60 minutes by default, 0 to a week);
3. then, when every canary agent runs the new version and answers (*Go on only when the canary
   ring is healthy*, on by default), **the rest**. A canary agent not updated, still on its old
   version or not answering **holds** the rollout: the card says who and why - *Go on anyway* or
   *Stop*.

Before it starts the card shows who would be in the canary ring, who in the rest and who is not
updated and why (no `allow self-update`, not answering, no signed package). *Go on now* skips the
rest of the wait; *Stop* updates nobody else (the ones updated stay); *Start another* once it
has ended. The next step is taken by the node that leads, with the agents' own tick; the rollout
is kept in `meta` (`fleet:rollout`), so the other node of a cluster carries on.

Events: *an update rollout of the agents to … was started*, *… is held*, *… was stopped*, *… is
done*.

## Certificates not managed - and their take-over

Every discovery kept for a server ([target-agent.md](target-agent.md), *Discovery*) is read for
certificates **acme does not manage** (not one of its certificates or their versions): each one a
service serves, and each loose certificate file. **Not managed** lists them across the fleet,
**by risk**: expired, ends this week, ends within 30 days, within 60 days, self-signed, fine for
now - with the server, the service and where (its configuration file), the issuer, the days
left; *Watch it* makes a test of what it serves.

**Take over…** (a certificate administrator who sees every certificate) - for a certificate a
service found serves:

* **the preview** (nothing is made yet): the certificate in acme (its name, **the same names** -
  editable -, the source it is issued from, renewed by itself), **what happens** step by step
  (the certificate made - nothing issued yet -, the deployment to the same server through its
  agent, each file with its path, mode and owner as found, the test and the reload), and **what
  the agent's policy needs**: each line green (allowed) or red, the missing ones as one block to
  copy (`sudo acme-agent allow …`);
* **Take over** makes the certificate and its deployment (the same paths, the deployment preset of
  the service). **Issue and deploy it now** is offered only when the agent's policy allows all of
  it; otherwise nothing is issued, and whenever it is, the agent refuses the deployment whole
  until root adds the lines - **nothing is written on the server** before that.

A certificate in a file no service uses (or a service acme cannot place by itself) is listed
without *Take over* (Import… or a deployment by hand, from the agent's card).

## Who may

| | read-only | certificate administrator | full administrator |
|---|---|---|---|
| see the fleet, the drift, the templates, what is not managed | yes | yes | yes |
| Ask now, Take over | - | yes | yes |
| templates, groups, *Template…*, Update, rollouts | - | - | yes |

Every route needs a session that sees every certificate: one limited to its teams' certificates
(*Certificate administrators manage every certificate* off) is refused.

## API

`GET /api/fleet` (the whole view), `GET /api/fleet/templates[?platform=]`,
`GET /api/fleet/template?ref=`, `POST /api/fleet/template_save {ref?, title, note, platform,
text, design_state}`, `POST /api/fleet/template_delete {ref}`, `POST /api/fleet/group_save {id?,
name, color, note, members, template, canary}`, `POST /api/fleet/group_delete {id}`,
`POST /api/fleet/assign {ids, template}`, `GET /api/fleet/drift?ids=`, `POST /api/fleet/act
{action: ask | update, ids}`, `GET /api/fleet/rollout_plan[?canary=]`, `POST /api/fleet/rollout
{canary, wait, healthy}`, `POST /api/fleet/rollout_step {do: continue | stop | forget}`,
`GET /api/fleet/unmanaged`, `POST /api/fleet/takeover_preview {target, service, names?, name?,
issuer?}`, `POST /api/fleet/takeover {…, confirm: true, issue_now, auto_renew}`.

## Kubernetes: acme-agent in a pod

For a cluster without cert-manager: **acme-agent for Kubernetes** runs as a pod of its own and
writes `kubernetes.io/tls` Secrets - and restarts a Deployment that uses one - **only in the
namespaces and under the names its policy allows**. It is acme-agent itself
(`deploy/agent/acme_agent.py`, imported by `deploy/agent/k8s/acme_k8s_agent.py` - not a copy): the
same join (a join code, or a company enrollment code), the same signed jobs, the private key
sealed to the agent until it is in the Secret, passive or active mode. In acme it is a target
*Server with acme-agent* like any other; the fleet shows it as *Kubernetes*.

**Two walls, both the cluster's**: the ServiceAccount's RBAC says what the pod may do at all (one
Role per namespace: the Secrets named, `create`, the Deployments it may restart); the policy - a
ConfigMap mounted read-only - says what of that acme may ask for. acme can change neither; the pod
never runs as root (it refuses), on a read-only root file system, all capabilities dropped.

### Its policy

```
allow secret shop/web-tls       the Secret web-tls in the namespace shop
allow secret intranet/*         any Secret in intranet
allow restart shop/web          the Deployment web in shop, after its Secret changed
allow discover                  acme may list the TLS Secrets of those namespaces (read-only)
allow from 192.0.2.10           passive: acme only from there
allow issuer sha256=HEX         what goes into a Secret chains to this CA (1.0.140, repeatable)
allow names *.shop.example.com  every name of it is one of these (1.0.140, repeatable)
limit files 20                  as acme-agent's
```

`allow issuer` and `allow names` are checked as acme-agent checks them (*What the agent deploys*
in [target-agent.md](target-agent.md)) before any Secret is written; `require key local` is not
read here - the pod makes no key. A line it cannot read is left out and said (`acme-k8s-agent policy`). A policy file the agent
itself could write is not believed: nothing is allowed.

acme is told it as acme-agent's own policy - a folder `/k8s/NAMESPACE/NAME` per Secret
(`/k8s/NAMESPACE` for `NAMESPACE/*`) and a test line `kubectl rollout restart deployment/NAME -n
NAMESPACE` per Deployment - so a deployment's form says before it runs what is allowed (green)
and what not (red, with the line to add to the ConfigMap).

### Its deployments

In acme, a deployment to the target with the files where the Secret's keys go:

```
fullchain-pem /k8s/shop/web-tls/tls.crt 0644 root:root
key-pem       /k8s/shop/web-tls/tls.key 0600 root:root
chain-pem     /k8s/shop/web-tls/ca.crt  0644 root:root      (optional)
After the files: kubectl rollout restart deployment/web -n shop
```

The agent checks the whole job first - every Secret allowed, certificate and key together, PEM of
what each key holds, each restart allowed, no other command or script (refused: *the Kubernetes
agent restarts a Deployment only*) - and reads every Secret: one of another type than
`kubernetes.io/tls` is never changed. Nothing is written before all of it passes. Then each
Secret is made (labelled `app.kubernetes.io/managed-by: acme-agent`) or replaced (its other keys,
labels and annotations kept); the same certificate again changes nothing and restarts nothing.
Each Deployment is restarted as `kubectl rollout restart` does (its pod template annotated
`kubectl.kubernetes.io/restartedAt`, and `acme-agent/certificate-sha256`). When the cluster
refuses a step, the Secrets as they were are put back (one just made is deleted).

The key is acme's (sealed to the agent): *Key made by the agent* is refused. The agent is updated
with its image, never by acme (`allow self-update` does not exist here). **Discovery** lists the
TLS Secrets of the namespaces the policy names - each certificate's facts only (subject, names,
issuer, end), never a key; **Not managed** and its take-over work for them as for a server's
files.

### Install (guide)

[deploy/agent/k8s/README.md](../deploy/agent/k8s/README.md) - the image, the manifests, the join.
