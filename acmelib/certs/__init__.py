# -*- coding: utf-8 -*-
"""acmelib.certs - the certificate manager.

    schema     the tables (put into the engine's SCHEMA by engine part 900)
    store      reading and writing those tables: certificates, versions,
               the issuers / challenges / targets with their sealed secrets
    runtime    RunContext - what a module (acmelib/plugins) is handed - and
               SshSession over the ssh and scp programs
    jobs       the jobs: a bounded pool, every step written down while it runs
    renewer    the scheduler: one node leads (a lease in meta), finds what is
               due, renews it and deploys it
    deployer   one certificate put on one target
    api        the JSON API the pages ask (docs/architecture.md)
    portal     what people signed in on the enrolment pages may see and ask
    cli        the command line (--certs, --renew, ...)
    console    the "Certificates" menu of the console

The PKI library (pki, formats, bundle, ca) and the DNS server (dnsserver)
sit beside these. Nothing here is imported until it is needed: `acme
--version` reads none of it.
"""
