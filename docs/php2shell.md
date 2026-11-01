# PHP and php2shell

acme's pages are PHP, and PHP before 21 October 2026 has php2shell:
**CVE-2026-109618** and **CVE-2026-109619**, remote code execution by anybody
who can send the web server a crafted `multipart/form-data` request. PHP
parses such a body before any script runs, so it does not matter what the
page does.

Fixed upstream in **8.2.35, 8.3.36, 8.4.27 and 8.5.12**.
On AlmaLinux 9: `php:8.3` → `8.3.36-1`, `php:8.2` → `8.2.35-1`, and the
default `8.0` has the fix backported (`8.0.30-8.alma.1`).

## What install.sh does

1. A PHP already installed and fixed is left as it is (no install, no
   stream change, no restart; nothing pins a version). Installed but not
   fixed: `dnf upgrade --refresh 'php*'` (or `apt-get install --only-upgrade`)
   on the stream it is on. No PHP at all: `dnf module enable php:8.3` (or
   `--php-stream 8.2`) only when no stream is enabled yet, then
   `dnf install php-fpm php-cli php-common`.
2. Checks the version against the fixed one for its branch; for a backport
   under an old number, `rpm -q --changelog php-fpm | grep CVE-2026-109618`
   (on Debian / Ubuntu, the package changelog).
3. When AppStream has no fixed build yet, offers PHP 8.4 from Remi
   (`php:remi-8.4`), or takes it with `--remi`.
4. A guard whatever the version:
   - nginx answers 403 to any request with a multipart body — none of acme's
     pages sends one;
   - `/etc/php.d/99-php2shell.ini`: no upload progress, strict sessions;
   - acme's own pool: `enable_post_data_reading = off` (PHP never parses a
     body by itself - the pages read the JSON they are sent), `open_basedir`
     to the pages and `/run/acme`, no `allow_url_fopen`, `exec` and its kind
     disabled;
   - the pool runs as its own user, `acme-www`, which can read the pages and
     the API token and nothing else.
5. Reloads php-fpm - only when acme's pool or the guard file changed, or the
   pool's socket is not there; otherwise PHP is not touched.

`./install.sh --upgrade` does all of it again; run it when the next fix comes.

## Checking by hand

```bash
php-fpm -v
rpm -q php-fpm
rpm -q --changelog php-fpm | grep -E 'CVE-2026-10961[89]'
curl -sk -o /dev/null -w '%{http_code}\n' -F x=y https://localhost/admin/   # 403
```

The daemon checks too: `acme --status` and the administration pages say,
in red at the top, when the PHP running them is not fixed.
