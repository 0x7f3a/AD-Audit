# AD-Audit export format (schema 1.0)

The native format is a single JSON document produced by the LDAP collector
(`--collect --export-native`) or by converting an imported dataset
(`--export-native`). It is deliberately explicit: every object and every
relationship is present, named and traceable. Importing it never touches a
domain.

## Top level

```json
{
  "schema_version": "1.0",
  "tool": {"name": "AD-Audit", "version": "0.1.0"},
  "domain": "corp.example",
  "collected_at": "2026-01-01T00:00:00Z",
  "collection": {
    "mode": "ldap",
    "complete": true,
    "gaps": ["Sessions and logged-on users are not collected over LDAP."]
  },
  "objects": [],
  "relationships": []
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | recommended | `"1.0"`. A different major version is reported as a warning; a missing one as a note. |
| `tool` | no | informational, written for humans |
| `domain` | no | target domain (falls back to the most common object domain) |
| `collected_at` | no | UTC timestamp of the collection |
| `collection.mode` | no | `"ldap"` or `"offline"` |
| `collection.complete` | no | `false` when collection or import had errors |
| `collection.gaps` | no | human-readable data gaps, carried into the report |
| `objects` | **yes** | array of object records |
| `relationships` | **yes** | array of relationship records (alias: `edges`) |

A document without an `objects` array is rejected with a clear error. Unknown
top-level keys are ignored.

## Object records

```json
{
  "id": "S-1-5-21-1004336348-1177238915-682003330-1105",
  "type": "user",
  "name": "analyst",
  "domain": "corp.example",
  "dn": "CN=Analyst,OU=Staff,DC=corp,DC=example",
  "sid": "S-1-5-21-1004336348-1177238915-682003330-1105",
  "sam": "analyst",
  "attributes": {"description": "example attribute"}
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `id` | **yes** | stable identifier; use the SID when available, otherwise `dn:<lower-case dn>` or `name:<name>[@domain]` |
| `type` | **yes** | `user`, `group`, `computer`, `domain`, `ou`, `gpo`, `container`, `unknown` |
| `name` | **yes** | display name (`DOMAIN\name` is derived from `domain` + `name`) |
| `domain` | no | DNS domain name |
| `dn` | no | distinguished name; used for containment and reference resolution |
| `sid` | no | object SID when the object has one (GPOs and OUs do not) |
| `sam` | no | sAMAccountName |
| `attributes` | no | free-form metadata; **not** copied into the JSON report |

The same `id` may appear more than once (for example, a duplicate record from a
merged export). Records are merged; conflicting attribute values are kept under
`attributes.conflicts` so the report can show that the source data disagreed.

## Relationship records

```json
{
  "type": "MemberOf",
  "source": "S-1-5-21-1004336348-1177238915-682003330-1105",
  "target": "S-1-5-21-1004336348-1177238915-682003330-1120",
  "inherited": false,
  "evidence": [
    {
      "detail": "Listed in the group's member attribute",
      "quality": "explicit",
      "reference": "ldap:CN=Helpdesk,OU=Groups,DC=corp,DC=example"
    }
  ]
}
```

| Field | Required | Meaning |
| --- | --- | --- |
| `type` | **yes** | one of the documented relationship types (see the README catalogue) |
| `source` | **yes** | id of the object that *gains* leverage |
| `target` | **yes** | id of the affected object |
| `inherited` | no | `true` when the permission comes from an inherited ACE |
| `evidence` | no | object or array of evidence records |

`source -> target` always means "whoever controls source can leverage this
against target". A session is therefore stored as `computer -> user`.

Evidence records:

| Field | Meaning |
| --- | --- |
| `detail` | what the source data says, in one sentence |
| `quality` | `explicit` (default), `derived`, or `inferred` |
| `reference` | where it came from (file, record, LDAP DN) |

The weakest evidence quality in a path determines the path's confidence;
`inferred` evidence also downgrades the finding's severity by one step.

## Validation rules

- An unknown `type` is an **error**: the relationship is skipped and reported.
- `source` and `target` must both exist in `objects`. Missing endpoints are an
  error; the relationship is skipped rather than pointing at a phantom node.
- Self-relationships are skipped with an informational note.
- Non-object entries in `objects`, and relationship records missing `type`,
  `source` or `target`, are reported and skipped.
- Objects keep their declared `id`; no identifiers are guessed for relationships.
- Containment edges are derived from `dn` when the export does not state them,
  and are marked `derived`.

## Stability

Ids and evidence references are plain strings chosen by the producer. AD-Audit
never rewrites them, so an export can be diffed against a later collection (ids
are stable as long as the directory identifiers are). Adding fields is
backwards-compatible; removing or renaming required fields requires a schema
major version.
