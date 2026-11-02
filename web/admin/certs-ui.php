<?php
/**
 * admin/certs-ui.php - the certificate manager's part of the administration
 * pages: its tabs, its panels and its two settings panes. Markup only, in the
 * page's own pieces (the same cards, tables, filters and rail); certs.js draws
 * what is in them from the daemon's API, and decides nothing either.
 *
 * admin/index.php requires this once and calls, in order:
 *   acme_certs_tab_buttons()     after the Overview tab's button
 *   acme_certs_tab_panels()      after the Overview panel
 *   acme_certs_settings_nav()    at the top of the settings rail
 *   acme_certs_settings_panes()  inside .ctl-main
 * The Overview's own tiles are drawn into its <div id="ov-certs">.
 */
declare(strict_types=1);

if (PHP_SAPI !== 'cli' && isset($_SERVER['SCRIPT_FILENAME'])
        && realpath((string) $_SERVER['SCRIPT_FILENAME']) === realpath(__FILE__)) {
    http_response_code(404);
    exit;
}

if (!function_exists('acme_certs_tab_buttons')) {

/** The tabs: certificates, authorities, sources, validation, targets, jobs. */
function acme_certs_tab_buttons(): void
{
    ?>
  <button role="tab" aria-selected="false" data-tab="certs" data-icon="lock" data-cicon="cert"
          title="Every certificate acme keeps: when each runs out, where it comes from, where it is deployed. Click a row for everything about one - renew, deploy, export, revoke.">Certificates<span class="count" id="tabn-certs"></span></button>
  <button role="tab" aria-selected="false" data-tab="cas" data-icon="shield" data-cicon="ca"
          title="The certificate authorities of acme's own - roots and the intermediates under them, what each signed, its revocation list.">Authorities</button>
  <button role="tab" aria-selected="false" data-tab="sources" data-icon="download" data-cicon="source"
          title="Where certificates come from: Let's Encrypt or another ACME CA, an authority of acme's own, self-signed, Microsoft AD CS, SCEP.">Sources</button>
  <button role="tab" aria-selected="false" data-tab="validation" data-icon="check" data-cicon="proof"
          title="How names are proved to an ACME CA: DNS-01 through acme's own DNS server or your DNS provider, HTTP-01 here or on your web servers over SSH.">Validation</button>
  <button role="tab" aria-selected="false" data-tab="targets" data-icon="net" data-cicon="target"
          title="Where certificates go: Linux servers over SSH, F5, NetScaler, MikroTik, FortiGate and the rest - and what is deployed on each.">Targets</button>
  <button role="tab" aria-selected="false" data-tab="jobs" data-icon="history" data-cicon="job"
          title="Every piece of work - an issue, a renewal, a deployment, a test - with each of its steps. Running ones update by themselves.">Jobs<span class="count" id="tabn-jobs"></span></button>
<?php
}

/** The panels of those tabs. */
function acme_certs_tab_panels(): void
{
    ?>
<!-- ===================== Certificates ===================== -->
<section class="panel" id="tab-certs" hidden>
  <div class="card full ct-held" data-hold>
    <h2>Certificates <span class="right btnrow ct-acts">
      <button class="btn small ct-approvals" id="ct-approvals" data-icon="clock" hidden
              title="Certificates asked for on the portal that wait for an administrator: click one, then Approve or Decline."></button>
      <button class="btn cmd small" id="ct-view" data-icon="eye"
              title="Look inside any certificate, chain, request, CRL, key or keystore - PEM, DER, P7B, PFX/P12, JKS, JCEKS - dropped or pasted. Nothing is kept and nothing changes.">Show a certificate</button>
      <button class="btn cmd small ct-manage" id="ct-import" data-icon="upload"
              title="Bring in a certificate you already have - PEM, CRT, CER, DER, P7B, PFX/P12, JKS or a key - by dropping the file here.">Import</button>
      <button class="btn cmd small ct-manage" id="ct-onlineimport" data-icon="download"
              title="The certificates your account already has at a source - SSLS.cz, SSLmarket, DigiCert, Vault, an authority of acme's own… - listed and brought in, each renewed through its own order there.">Import from a source</button>
      <button class="btn cmd small ct-manage" id="ct-self" data-icon="lock"
              title="A self-signed certificate in one step: its names, its key and how long it lasts.">Self-signed</button>
      <button class="btn cmd small ct-manage" id="ct-csr" data-icon="key"
              title="A key made here and a CSR for an authority acme does not speak to; the certificate it sends back is uploaded later.">CSR for an outside CA</button>
      <button class="btn cmd small primary ct-manage" id="ct-add" data-icon="add"
              title="A new certificate: where it comes from, its names, its key, how its names are proved, when it renews and where it goes.">Add a certificate</button>
    </span></h2>
    <p class="note">Every certificate acme keeps, renewed by itself before it runs out and put
      where it is deployed. Click a row for everything about one: its names and chain, every
      version it has had, where it is deployed, its jobs - and renew, deploy, export or revoke it.</p>
    <div class="btnrow filters ct-filters">
      <input type="search" id="ct-q" placeholder="a name, a serial, a tag…" style="flex:1;min-width:200px">
      <select id="ct-state" title="Only the certificates in this state.">
        <option value="">every state</option>
        <option value="ok">valid</option>
        <option value="expiring">running out soon</option>
        <option value="due">due for renewal</option>
        <option value="renewing">being renewed</option>
        <option value="failed">renewal failed</option>
        <option value="expired">has expired</option>
        <option value="pending">waiting for an outside CA</option>
        <option value="pending-approval">waiting for approval</option>
        <option value="declined">declined</option>
        <option value="new">not issued yet</option>
        <option value="revoked">revoked</option>
        <option value="disabled">switched off</option>
      </select>
      <select id="ct-issuer" title="Only the certificates from this source."><option value="">every source</option></select>
      <select id="ct-owner" title="Only the certificates of this owner." hidden><option value="">every owner</option></select>
      <select id="ct-tag" title="Only the certificates with this tag." hidden><option value="">every tag</option></select>
      <select id="ct-per" title="How many rows a page."><option>25</option><option selected>50</option><option>100</option><option>500</option></select>
      <span class="muted small ct-said" id="ct-said"></span>
    </div>
    <div id="ct-table" class="scroll rowsonly"></div>
    <div class="pager" id="ct-pager"></div>
  </div>
</section>

<!-- ===================== Authorities ===================== -->
<section class="panel" id="tab-cas" hidden>
  <div class="card full">
    <h2>Certificate authorities <span class="right" id="ca-said"></span></h2>
    <p class="note">The authorities of acme's own: roots, and the intermediates each of them
      signed, as a tree. A source of the kind "own certificate authority" issues certificates from one of them.
      Click one for what it signed, its revocation list, where it is published, and to sign a CSR from elsewhere.
      The star makes one the default: offered first for a new source and for signing a CSR.</p>
    <div class="btnrow ct-fulladmin" style="margin-bottom:12px">
      <button class="btn cmd primary" id="ca-root" data-icon="add"
              title="A new root authority: its own key, signed by itself.">Create a root</button>
      <button class="btn cmd" id="ca-inter" data-icon="add"
              title="A new intermediate authority, signed by one of the authorities here.">Create an intermediate</button>
      <button class="btn cmd" id="ca-import" data-icon="upload"
              title="An authority you already have - its certificate and its key - to issue from here.">Import an authority</button>
      <button class="btn cmd" id="ca-sign" data-icon="key"
              title="A request made elsewhere signed by one of the authorities here - the default one first.">Sign a CSR</button>
    </div>
    <div id="ca-pki"></div>
    <div id="ca-tree"></div>
  </div>
</section>

<!-- ===================== Sources ===================== -->
<section class="panel" id="tab-sources" hidden>
  <div class="card full">
    <h2>Sources <span class="right" id="src-said"></span></h2>
    <p class="note">Where certificates come from. Each is one module - ACME (Let's Encrypt, ZeroSSL,
      your own ACME server), an authority of acme's own, self-signed, Microsoft AD CS, SCEP - with
      its own settings. Test tries it without changing anything. The star makes one the default:
      a new certificate comes from it when no source is said.</p>
    <div class="btnrow ct-fulladmin" style="margin-bottom:12px">
      <button class="btn cmd primary" id="src-add" data-icon="add">Add a source</button>
    </div>
    <div id="src-broken"></div>
    <div id="src-list"></div>
  </div>
</section>

<!-- ===================== Validation ===================== -->
<section class="panel" id="tab-validation" hidden>
  <div class="card full">
    <h2>Validation <span class="right" id="val-said"></span></h2>
    <p class="note">How names are proved to an ACME CA. DNS-01 puts a TXT record in DNS - in
      acme's own DNS server, or at your DNS provider - and is the only way for a wildcard;
      HTTP-01 answers on port 80, here or on your own web servers over SSH, so acme itself is
      never reachable from the internet. The star makes one the default: a new certificate from
      an ACME CA is proved by it.</p>
    <div class="btnrow ct-fulladmin" style="margin-bottom:12px">
      <button class="btn cmd primary" id="val-add" data-icon="add">Add a way of validation</button>
    </div>
    <div id="val-broken"></div>
    <div id="val-list"></div>
  </div>
</section>

<!-- ===================== Targets ===================== -->
<section class="panel" id="tab-targets" hidden>
  <div class="card full">
    <h2>Targets <span class="right" id="tg-said"></span></h2>
    <p class="note">Where certificates go: a Linux server over SSH, a load balancer, a firewall, a
      router. A certificate is deployed on a target with options of its own - paths, formats, the
      profile it goes into, the commands after. Click a target for what is deployed on it. The star
      makes one the default: offered first when a certificate is deployed.</p>
    <div class="btnrow filters">
      <input type="search" id="tg-q" placeholder="a name, an address, a kind…" style="flex:1;min-width:200px">
      <span class="spacer"></span>
      <button class="btn cmd primary ct-fulladmin" id="tg-add" data-icon="add">Add a target</button>
    </div>
    <div id="tg-broken"></div>
    <div id="tg-list"></div>
  </div>
</section>

<!-- ===================== Jobs ===================== -->
<section class="panel" id="tab-jobs" hidden>
  <div class="card full ct-held" data-hold>
    <h2>Jobs <span class="right" id="jb-said"></span></h2>
    <p class="note">Every piece of work acme did or is doing: issuing and renewing, deploying,
      revoking, testing - each with every step it took. Running ones update by themselves;
      click a row for its log.</p>
    <div class="btnrow filters">
      <select id="jb-kind" title="Only jobs of this kind.">
        <option value="">every kind</option>
        <option value="issue">issue</option>
        <option value="renew">renewal</option>
        <option value="deploy">deployment</option>
        <option value="revoke">revocation</option>
        <option value="import">import</option>
        <option value="test">test</option>
      </select>
      <select id="jb-ok" title="Only jobs that ended like this.">
        <option value="">however they ended</option>
        <option value="1">went well</option>
        <option value="0">failed</option>
        <option value="running">running now</option>
      </select>
      <select id="jb-cert" title="Only the jobs of one certificate."><option value="">every certificate</option></select>
      <select id="jb-per" title="How many rows a page."><option>25</option><option selected>50</option><option>100</option></select>
    </div>
    <div id="jb-table" class="scroll rowsonly"></div>
    <div class="pager" id="jb-pager"></div>
  </div>
</section>
<?php
}

/** The settings rail: a group of its own, first. */
function acme_certs_settings_nav(): void
{
    ?>
    <div class="ctl-group">Certificates</div>
    <button type="button" data-pane="certs" data-icon="lock" title="When certificates are renewed, how often a failed one is tried again, and who is told when something goes wrong.">Renewal and notices</button>
    <button type="button" data-pane="dnssrv" data-icon="globe" title="acme's own DNS server for DNS-01: the zone it answers for, its NS names, where it listens, and the records in it.">DNS server</button>
    <button type="button" data-pane="teams" data-icon="people" title="Who certificates belong to - teams and persons, their members from acme's accounts and the directory, what each may do - and the tags certificates and targets pick from.">Owners and teams</button>
<?php
}

/** The two panes those buttons open. */
function acme_certs_settings_panes(): void
{
    ?>
  <div class="ctl-pane" id="pane-certs" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Renewal and notices</h2>
      <p class="ctl-lede">How far before the end a certificate is renewed when it does not say for
        itself, how long acme waits before trying a failed one again, and who hears about it -
        by mail, SMS, syslog and isemon, as every other alert.</p></div>
    <div class="card full" id="cset-summary" hidden></div>
    <div class="card full"><div id="sect-certs"></div></div>
  </div>

  <div class="ctl-pane" id="pane-teams" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Owners and teams</h2>
      <p class="ctl-lede">Who each certificate belongs to and what its people may do with it, and the
        tags - defined once here and picked from lists everywhere else, never typed. A full
        administrator always sees and does everything.</p></div>
    <div id="teams-host"></div>
    <div class="card full"><h2>Who sees which certificates</h2><div id="sect-teams"></div></div>
  </div>

  <div class="ctl-pane" id="pane-reqprofiles" hidden>
    <div class="ctl-head"><h2 class="ctl-title">Request profiles</h2>
      <p class="ctl-lede">What people may ask for on the enrolment pages, with everything set
        beforehand - where it comes from, how its names are proved, which names, the key or their
        own CSR, the subject, renewal, approval and whose it is. They give only its names and what a
        profile leaves to them. With none defined, the portal asks as before.</p></div>
    <div id="rp-host"></div>
  </div>

  <div class="ctl-pane" id="pane-dnssrv" hidden>
    <div class="ctl-head"><h2 class="ctl-title">DNS server</h2>
      <p class="ctl-lede">acme's own DNS server, for DNS-01 without giving acme the keys to your
        DNS: delegate one zone to it (an NS record in your DNS), point the _acme-challenge name of
        each certificate name at it with a CNAME, and the TXT records are put
        here and taken away again by themselves.</p></div>
    <div class="card full" id="dns-state"></div>
    <div class="card full"><h2>Settings</h2><div id="sect-dnssrv"></div></div>
    <div class="card full">
      <h2>Records <span class="right" id="dns-said"></span></h2>
      <p class="note">What the server answers with: the challenge TXT records while a job proves a
        name (they go by themselves), and records of your own.</p>
      <div class="btnrow filters">
        <input type="search" id="dns-q" placeholder="a name, a value…" style="flex:1;min-width:200px">
        <span class="spacer"></span>
        <button class="btn cmd primary ct-fulladmin" id="dns-add" data-icon="add">Add a record</button>
      </div>
      <div id="dns-table"></div>
    </div>
  </div>
<?php
}

}
