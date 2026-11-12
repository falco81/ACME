# Docker Swarm secrets - setup for acme

acme signs in over **SSH to a Swarm manager node**. Because a Docker secret cannot be
changed, only replaced, it creates two new secrets under dated names -
`acme-<name>-<date>-<serial>.crt` (full chain) and `.key` (labelled `managed-by=acme`) -
then rolls each service you list onto them (`docker service update --secret-rm <old>
--secret-add source=<new>,target=tls.crt,...`, a rolling update; the owner and mode the
service had for the file stay). Older acme secrets are removed; one still used stays.

For Docker Engine in Swarm mode (any supported version) on Linux.

## What you need

- SSH access from acme to a **manager** node (TCP 22 by default).
- A user who may run `docker` there: root, a member of the `docker` group, or sudo.
  **Membership of the `docker` group is equivalent to root on that host.**
- The services already exist and read the certificate and key from secrets (the files
  under `/run/secrets/`).

## Set up the Swarm manager

1. Create a user for acme on a manager and add acme's public SSH key:

   ```sh
   sudo useradd -m -s /bin/bash acme
   sudo usermod -aG docker acme
   sudo install -d -m 700 -o acme -g acme /home/acme/.ssh
   echo 'ssh-ed25519 AAAA... acme' | sudo tee /home/acme/.ssh/authorized_keys
   ```

   (Or keep it out of the `docker` group and turn on *Use sudo* in acme.)
2. Check it is a manager of an active swarm:

   ```sh
   docker info --format '{{.Swarm.LocalNodeState}} {{.Swarm.ControlAvailable}}'
   # active true
   ```

3. Let the services read the files from their secrets. In a stack file, for example:

   ```yaml
   services:
     proxy:
       secrets:
         - source: www_crt
           target: tls.crt
         - source: www_key
           target: tls.key
   ```

   acme replaces the secret mounted at `tls.crt` / `tls.key` (or an older acme secret)
   with its own. If you later `docker stack deploy` the stack file again, it puts back the
   secrets it names - point the stack file at external secrets or deploy acme again.

## Fill in acme

| acme field | What to put there |
|---|---|
| Address | A manager node's name or IP |
| SSH port / User | `22` / `acme` (or `root`) |
| Sign in with / The SSH key / Password | A key made in acme (recommended) or a password |
| Use sudo / sudo password | On if the user is not in the `docker` group and not root |
| docker command (advanced) | Default `docker` (a plain path) |
| Timeout (s) (advanced) | Default 30 |
| Services (deploy) | One a line, e.g. `web_proxy` (stack services are `<stack>_<service>`) |
| Certificate file in the container (deploy) | Default `tls.crt` (under `/run/secrets/` unless absolute); full chain |
| Key file in the container (deploy) | Default `tls.key` |
| Previous versions to keep (advanced) | Default 1 |
| Check what is served | The published service, e.g. `www.example.com:443` |

## Check it

- **Try**: `signed in: a swarm manager, Docker 27.x`.
- On the manager:

  ```sh
  docker secret ls --filter label=managed-by=acme
  docker service inspect web_proxy --format '{{json .Spec.TaskTemplate.ContainerSpec.Secrets}}'
  docker service ps web_proxy
  ```

## Common problems

| Problem | Fix |
|---|---|
| `this is not a manager of an active swarm` | Sign in to a manager node, not a worker |
| `permission denied ... docker.sock` | Add the user to the `docker` group or turn on *Use sudo* |
| `there is no service "..."` | Wrong name - use the full `<stack>_<service>` name (`docker service ls`) |
| Rolling update hangs or fails | Check `docker service ps <svc>`; the new tasks may fail to start |
| `the old secret ... stays (still used?)` | Another service still mounts it; it goes once unused |
| Old secrets back after `docker stack deploy` | The stack file names them - use external secrets or redeploy with acme |
