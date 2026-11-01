# One person, several domain suffixes

An Active Directory often answers to more than one suffix: `dpmo.local` (the
domain's own name) and `dpmo.cz` (the UPN suffix people know). The VPN may send
either one, depending on how the person typed their name. acme keeps **one token
per person**. This page is about making every spelling find that token.

## The way to do it: one realm, other suffixes

*Settings → Realms → (the realm) → …and also the names ending in @*

```
Takes the names ending in @          dpmo.cz
…and also the names ending in @      dpmo.local
```

From then on:

| Signed in as | Realm | The token looked up |
|---|---|---|
| `novak@dpmo.cz` | dpmo.cz | `novak@dpmo.cz` |
| `novak@dpmo.local` | dpmo.cz | `novak@dpmo.cz` |
| `novak` (with the default realm dpmo.cz) | dpmo.cz | `novak@dpmo.cz` |

- **RADIUS** finds the realm by any of its suffixes, and the token under the
  realm's own suffix. The decision says so (*the token is novak@dpmo.cz - the
  realm keeps its tokens under @dpmo.cz*).
- **The enrolment pages** make and find the token under the realm's own suffix,
  whichever one the person signed in with.
- **Make a token** in the administration, for `novak@dpmo.local`, makes
  `novak@dpmo.cz`.
- **The directory**: looked up by *sAMAccountName*, the part before the @ is
  enough. Looked up by *userPrincipalName*, the name as written is tried first,
  then under each of the realm's suffixes (a UPN of `novak@dpmo.cz` is found
  for `novak@dpmo.local`).
- The realm's groups, its answer (Class, group policy), its password mode and
  the clients allowed to use it are the same for every suffix. When the two
  suffixes need different groups or answers, keep two realms (below).

On the command line:

```bash
acme --add-realm dpmo.cz --aliases dpmo.local     # "" takes them away
acme --realms                                     # dpmo.cz +dpmo.local
```

### Merging two realms into one

Two realms `dpmo.cz` and `dpmo.local` already in use, on the same directory:

1. Open the realm to keep - say `dpmo.local`, the domain's own name - and write
   `dpmo.cz` into *…and also the names ending in @*. *Save*.
2. The page sees that `dpmo.cz` is a realm of its own and offers to **take it
   in**. Confirmed, in one step:
   - `dpmo.cz` (and any other suffixes it had) become other suffixes of this
     realm;
   - its groups are added after this realm's own (each with its own answer);
   - the clients allowed the realm `dpmo.cz` are allowed this one;
   - the realm `dpmo.cz` goes.
3. Tokens made under `@dpmo.cz` go on working as they are: when there is no
   `novak@dpmo.local`, `novak@dpmo.cz` is used. The realm's editor lists them,
   and *Move them under @dpmo.local* renames them the way *Move* on a token
   does: the key, the recovery codes and the history go with it, and nobody
   enrols again. A person with a token under both names keeps both until one
   is taken away by hand (marked ✗ in the list).
4. *The default realm* (Settings → Realms) may stay as it was: a default of
   `dpmo.cz` now means this realm.

On the command line the same is `acme --del-realm dpmo.cz` and
`acme --add-realm dpmo.local --aliases dpmo.cz` (groups and clients by hand).

### Which suffix to keep as the realm's own

The one most tokens are under already - fewer to move - or the domain's own
name (`dpmo.local`): it never changes, while a UPN suffix may. The tokens are
named by it; what people type does not have to match it.

## Two realms on one directory

Kept separate - different groups or answers per suffix - both realms read the
same directory, and the person may have signed in to the enrolment pages under
either one. The enrolment pages find a token the same account has under the
other realm's suffix and do not make a second one. Since 1.0.117 RADIUS does the
same: when there is no token under the name asked, it uses the same account's
token from another realm **on the same directory**, where **both realms look
names up by sAMAccountName**. The decision says which one (*the token is
novak@dpmo.cz - the same account (novak) in the realm dpmo.cz, on the same
directory*). The groups and the answer are still the realm's that was asked.

With UPN lookups the part before the @ is not known to be the same account, so
nothing is borrowed. Make it one realm with another suffix instead.
