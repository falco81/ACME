# -*- coding: utf-8 -*-
from __future__ import annotations
# ---------------------------------------------------------------------------
# The command line of what 1.0.138 added to the pages (docs/command-line.md)
# ---------------------------------------------------------------------------
# History and trash, request profiles (versions, compare, restore, compliance, a dry run, the
# end of one), the agent fleet (groups, templates, drift, rings, take-over) and the governance
# of teams (health, reviews, temporary roles, separation of duties, channels, templates) -
# acmelib/certs/cli_138.py, each option the pages' own route run here as `command line`.


@_certs_hook('cli_args')
def cli_138_args(parser):
    certs_mod('cli_138').add_args(parser)


@_certs_hook('cli_run')
def cli_138_run(args):
    return certs_mod('cli_138').run(args)
