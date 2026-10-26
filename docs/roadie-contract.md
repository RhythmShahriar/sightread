# The Roadie contract

Status: assumed until Roadie 1.0 ships. `stage/` adapts to the real output at integration; this file is what it is built and tested against until then.

`--soundcheck` installs an update on a staging copy, where its code runs. Before that, Sightread asks Roadie whether the copy is safe to break:

```
rhythm-roadie verify --target <url> [--wp "<cmd>"] --json
```

Sightread starts it through `internal/proc` with the purpose `roadie`, an argv and never a shell. It reads stdout as one JSON document.

## Output

```json
{
  "schema": "rhythm-roadie/v1",
  "kind": "verify",
  "tool": "rhythm-roadie",
  "version": "1.0.0",
  "verdict": "ok",
  "data": {
    "target": "https://staging.shop.test",
    "production_url": "https://shop.example.com",
    "signed": true,
    "sealed": true,
    "copy_created": "2026-10-25T22:10:00Z",
    "verified_at": "2026-10-26T08:55:12Z",
    "problems": []
  }
}
```

| Field | Type | Meaning |
|---|---|---|
| `schema` | string | always `rhythm-roadie/v1`; anything else is refused |
| `kind` | string | always `verify` |
| `verdict` | string | `ok`, `findings` or `error` |
| `data.target` | string | the staging URL that was checked |
| `data.production_url` | string | the production site this copy was made from; `--soundcheck` refuses a target with this host (E14) |
| `data.signed` | bool | the copy carries Roadie's signed marker |
| `data.sealed` | bool | Echo's seal is active, so nothing the update sends reaches real people |
| `data.copy_created` | string | RFC 3339 time the copy was made |
| `data.verified_at` | string | RFC 3339 time of this check; must be after `copy_created` |
| `data.problems[]` | list | `{kind, count, text}` per problem, for example `{"kind": "real-email", "count": 2, "text": "2 real-looking emails"}` |

## What Sightread accepts

The staging copy passes only when all of these hold:

- the command exits 0 and prints the document above
- `verdict` is `ok`, `signed` and `sealed` are true and `problems` is empty
- `verified_at` is later than `copy_created`

Otherwise Sightread stops with E15 and names the problems from `data.problems[].text`:

```
rhythm sightread: staging.shop.test failed rhythm roadie verify (2 real-looking emails, 1 live payment key)
  fix it with rhythm roadie prepare, or --skip-roadie-verify (the report says it was skipped)
```

## Exit codes

As every Rhythm tool (kit `cli`): 0 ok, 1 findings, 2 usage error, 3 couldn't run, 130 interrupted. Exit 1 with a `findings` document is a failed verify (E15); exit 2 or 3 is reported as Roadie failing to run, with its stderr under `-v`. A missing `rhythm-roadie` binary is E15 with `install them with: rhythm install soundcheck roadie`.
