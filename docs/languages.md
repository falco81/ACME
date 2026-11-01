# The pages in another language

The same engine and the same files as isemon. The pages are written in
English; a file in `web/lang/` (`/var/www/acme/lang/` once installed) says
what each piece is in another language, and the page swaps the words as they
appear. `cs.json` (Czech) comes with acme.

- `ui_lang` (Settings → About) — the language every page opens in.
- Each administrator chooses their own in the account menu; on the enrolment
  pages, the EN / CS switch at the bottom.

A file is:

```json
{
 "_meta": {"code": "cs", "name": "Čeština", "english": "Czech", "version": "1.0.209"},
 "strings":  {"s0001": {"source": "Add a client", "text": "Přidat klienta"}},
 "patterns": {"p0001": {"source": "{0} wrong code(s)", "text": "{0} {0:chybný kód|chybné kódy|chybných kódů}"}},
 "rich":     {"r0001": {"source": "Write everything into <code>/var/log/acme/acme.log</code>.", "text": "…"}}
}
```

Change only `text`, never `source`; an empty `text` shows the English.
`{0:one|two-four|five+}` picks the Czech plural by the number in `{0}`.
A new language is a new file with its own `code`; it appears in the menus
by itself. Data — names, addresses, codes, the lines isemon
reads — is never translated.
