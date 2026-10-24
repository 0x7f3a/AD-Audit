# AD-Audit

Read-only Active Directory privilege-path analysis with evidence-backed findings.

AD-Audit loads collected directory data, models objects and relationships as a
typed graph, searches that graph for potential paths to privileged targets, and
reports what it found in a compact terminal report or as JSON. It is built for
authorised security assessments where the question is:

> Given the collected Active Directory data, which identities or systems have
> relationships that could expose a path to a privileged target, and what
> evidence supports each path?

It is an **audit and analysis** tool. It does not exploit anything, does not
attempt authentication attacks, and does not modify a directory. Offline
analysis never contacts a domain at all.

---

## What it does

- Imports BloodHound/SharpHound JSON exports (ZIP, directory, or a combined
  JSON document) and AD-Audit's own JSON export.
- Normalises objects (users, groups, computers, domains, OUs, GPOs, unresolved
  principals) and relationships into one schema, with provenance on every edge.
- Builds a directed, typed graph and searches it with cycle-safe, bounded
  breadth-first traversal.
- Resolves privileged targets by well-known RID/SID (so it works in any
  domain), with name fallback and explicit `--target` selection.
- Produces findings with separate severity and confidence, the full path, the
  evidence behind every step, prerequisites, impact, remediation and
  limitations.
- Reports collection gaps and skipped checks, so "no path found" is never
  presented as "no path exists".
- Emits deterministic JSON suitable for saving, diffing and feeding other tools.
- Optionally collects data read-only over LDAP (with TLS and secure credential
  input) and exports it for offline analysis.

## What it does not do

- No exploitation, credential theft, password cracking, spraying, relaying or
  persistence.
- No writes of any kind to the directory, no group changes, no password resets.
- No claim that a path is exploitable. A path means "the collected data
  connects these objects this way"; every finding needs human verification.
- No automatic remediation. Recommendations are guidance for an administrator.
- No Neo4j, no database server, no bundled BloodHound installation.

## How it works

```
                 ┌─────────────────────┐
  LDAP (opt-in)  │  collector          │──┐
                 │  ada.../collection  │  │   native JSON export
                 └─────────────────────┘  ▼
  BloodHound JSON ──► importers ──► normalised dataset (objects, typed edges,
  AD-Audit JSON                     issues, collection metadata)
                                            │
                                            ▼
                                     graph builder (adjacency)
                                            │
                         targets ──► path search (BFS, bounded)
                                            │
                                            ▼
                                   finding engine (evidence,
                                   severity, confidence, IDs)
                                            │
                              ┌─────────────┴─────────────┐
                              ▼                           ▼
                      terminal report                JSON report
```

The graph engine knows nothing about collection. Any importer that produces the
normalised dataset can be analysed offline.

## Installation

Requires Python 3.9 or newer. The core has **no third-party dependencies**;
live LDAP collection needs the optional `ldap3` package.

```bash
git clone https://github.com/0x7f3a/AD-Audit
cd AD-Audit

# run without installing
python3 main.py --help

# or install it (adds the `adaudit` command)
pip install -e .

# optional: live collection support
pip install -e '.[ldap]'

# development: tests
pip install '.[dev]'
```

## Quick start

The repository ships a synthetic BloodHound export in `examples/corp-example`
(see `examples/README.md`). Nothing there is real directory data.

```bash
# analyse every non-privileged user and computer, print the terminal report
python3 main.py -i examples/corp-example

# follow one principal, one path
python3 main.py -i examples/corp-example \
    --start 'CORP.EXAMPLE\analyst' --max-paths 1

# machine-readable report
python3 main.py -i examples/corp-example --json-out report.json

# convert a BloodHound export to AD-Audit's smaller native format
python3 main.py -i examples/corp-example --export-native dataset.json

# re-analyse the native export, including INFO findings
python3 main.py -i dataset.json --verbose
```

Exit codes: `0` nothing actionable, `1` low/medium, `2` high, `3` critical,
`4` usage/input error, `130` interrupted.

### Example output

Real output from the synthetic example (trimmed for length):

```text
========================================
 Active Directory Security Analysis
========================================

Target:   corp.example
Mode:     Offline graph analysis (bloodhound)
Input:    examples/corp-example

Objects:  Users: 7 | Groups: 4 | Computers: 3 | Domains: 1 | OUs: 1 | GPOs: 1
Graph:    17 nodes | 40 relationships

[+] Imported bloodhound dataset (17 objects, 40 relationships)
[+] Resolved 3 privileged target(s) (3 by SID)
[+] Analysed 9 starting principal(s) with max depth 6

Coverage: partial
  Import issues: 0 error(s), 0 warning(s), 2 note(s)
  Data gaps:     1

Findings: 20
Critical: 0
High:     20
Medium:   0
Low:      0
Info:     0

Privileged targets:
  CORP.EXAMPLE\Domain Admins  tier 0  2 direct member(s)  [sid]
  CORP.EXAMPLE                tier 0  domain object  [sid]
  CORP.EXAMPLE\krbtgt         tier 0  user object  [sid]

Potential privilege paths:

[HIGH] AD-PATH-eab0e6d3: Potential path to privileged target: Domain Admins
  Check:      AD-PATH
  Category:   permission
  Confidence: CONFIRMED
  Start:      CORP.EXAMPLE\analyst
  Target:     CORP.EXAMPLE\Domain Admins
  Path:
    CORP.EXAMPLE\analyst
      -[MemberOf]-> CORP.EXAMPLE\Helpdesk
      -[GenericAll]-> CORP.EXAMPLE\Support-Operators
      -[MemberOf]-> CORP.EXAMPLE\Domain Admins
  Why:
    1. CORP.EXAMPLE\analyst is a member of CORP.EXAMPLE\Helpdesk; group membership is transitive and
       confers every right the group holds.
    2. CORP.EXAMPLE\Helpdesk holds full control over CORP.EXAMPLE\Support-Operators and can grant
       itself any further right on the object.
    3. CORP.EXAMPLE\Support-Operators is a member of CORP.EXAMPLE\Domain Admins; group membership is
       transitive and confers every right the group holds.
  Evidence:
    1. MemberOf: CORP.EXAMPLE\analyst -> CORP.EXAMPLE\Helpdesk  [explicit]
       Listed as a member of the group
       ref: groups.json#Helpdesk
...
NOTE: Findings are audit results requiring human verification, not proof of
exploitability. A nonzero exit code means findings were reported - it does not
mean exploitation was attempted or confirmed.
```

## Input formats

### BloodHound / SharpHound JSON

Supported:

| Input | Notes |
| --- | --- |
| `.zip` archive | per-class JSON files, optionally with a timestamp prefix (`20240101_users.json`) |
| directory | the same JSON files |
| single `.json` | top-level keys are the class names, values are the record arrays |

Recognised classes: `users`, `groups`, `computers`, `domains`, `ous`, `gpos`,
`containers`. Both `PascalCase` and lower-case field spellings are accepted
(`Members`/`members`, `ObjectIdentifier`/`objectidentifier`, ...) because the
format has drifted between SharpHound versions.

Supported versions: the classic per-class JSON collection produced by
SharpHound 2.x-5.x and bloodhound-python, which is also the archive format
BloodHound CE imports. AD-Audit reads that format directly and does not need
BloodHound or Neo4j. Newer BloodHound-native/OpenGraph bundles, Neo4j database
dumps, and CSV/XML exports from other collectors are **not** supported; they
produce a clear error naming the accepted formats rather than a partial parse.

Fields used:

- object identity: `ObjectIdentifier`, `Properties.objectsid`,
  `Properties.distinguishedname`, `Properties.name`, `Properties.domain`
- group membership: `Members[]`, `ObjectIdentifier`, `PrimaryGroup`,
  `PrimaryGroupSID`
- computer access: `LocalAdmins`, `RemoteDesktopUsers`, `PSRemoteUsers`,
  `DcomUsers`
- sessions: `Sessions`, `PrivilegedSessions`, `RegistrySessions`
  (`UserSID` / `ComputerSID`)
- permissions: `Aces[]` with `PrincipalSID`, `RightName`, `IsInherited`
- delegation: `AllowedToDelegate`, `AllowsToDelegate` targets
- SID history: `HasSIDHistory`
- policy links: `Links[].GUID`, `Links[].IsEnforced`
- containment: derived from `distinguishedname` parent/child structure

Ignored, and reported in the output as notes:

- extra export files (for example `certificates.json`) and unknown record types
- ACE right names AD-Audit does not model (e.g. `AddKeyCredentialLink`,
  `WriteSPN`, `SyncLAPSPassword`) -- listed explicitly so they are not mistaken
  for absent permissions
- domain `Trusts` (cross-domain paths are not analysed)
- `SPNTargets` (Kerberoast material) and GPO-derived local group membership

Not supported: BloodHound's newer bulk/native formats, Neo4j dumps, CSV or XML
exports from other tools. Unsupported files produce a clear error naming the
accepted formats.

### AD-Audit JSON export

A single documented JSON document. It is what the LDAP collector writes, and it
is smaller and more explicit than a BloodHound export. See
[docs/export-format.md](docs/export-format.md) for the full schema.

```json
{
  "schema_version": "1.0",
  "domain": "corp.example",
  "collection": {"mode": "offline", "complete": true, "gaps": []},
  "objects": [
    {"id": "S-1-5-21-...-1105", "type": "user", "name": "analyst",
     "dn": "CN=Analyst,OU=Staff,DC=corp,DC=example"}
  ],
  "relationships": [
    {"type": "MemberOf", "source": "S-1-5-21-...-1105",
     "target": "S-1-5-21-...-1120",
     "evidence": [{"detail": "member attribute", "quality": "explicit"}]}
  ]
}
```

Relationship types are validated against the catalogue below. An unknown type,
a missing endpoint or a malformed record is reported as an error and skipped --
never silently converted into something similar.

## CLI

```
adaudit [options]
```

| Option | Description |
| --- | --- |
| `-i, --input PATH` | offline dataset (repeatable, merged) |
| `--format {auto,bloodhound,adaudit}` | force an input format |
| `--export-native PATH` | write the loaded/collected dataset as a native export |
| `--collect` | read-only LDAP collection instead of a file |
| `--server URL` | `ldap://` or `ldaps://` domain controller |
| `--base-dn DN` | search base |
| `--bind-dn DN` | account to bind as (omit for anonymous) |
| `--password-file PATH` | read bind password from a file (preferred) |
| `--password-env VAR` | environment variable holding the password (default `ADAUDIT_PASSWORD`) |
| `--ask-password` | prompt without echo |
| `--ca-cert PATH` | CA bundle for TLS |
| `--no-tls-verify` | disable certificate verification (explicitly insecure) |
| `--start-tls` | upgrade `ldap://` with StartTLS |
| `--timeout SECONDS` | LDAP timeout (default 15) |
| `--page-size N` | LDAP page size (default 500) |
| `--max-entries N` | stop after N objects per class (default 50000) |
| `--start PRINCIPAL` | starting principal (repeatable); default: all non-privileged users and computers |
| `--target VALUE` | extra privileged target (repeatable) |
| `--no-default-targets` | ignore built-in target definitions |
| `--max-depth N` | maximum path length (default 6) |
| `--max-paths N` | maximum paths reported (default 50) |
| `--max-sources N` | maximum implicit starting principals (default 500) |
| `--max-paths-per-pair N` | keep at most N paths per source/target pair (default 3) |
| `--budget N` | maximum graph expansions (default 200000) |
| `--json` | JSON report on stdout |
| `--json-out PATH` | also write the JSON report to a file |
| `--verbose` | include INFO findings |
| `--no-color` | disable ANSI colour (also auto-off when not a TTY) |
| `--width N` | wrap width (default 100) |
| `--version`, `--help` | version and usage |

`--start` and `--target` accept a SID, an object id, `DOMAIN\name`, a
distinguished name, or a plain name/SAM account name. A token that matches
nothing is reported on stderr and in the JSON `notes`.

## How the analysis works

### One edge convention

Every edge is stored as `source -> target` and means:

> whoever controls **source** can leverage this relationship against **target**.

That one rule removes the direction ambiguity that otherwise makes ACL graphs
hard to reason about. In particular a logged-on session is exported by
BloodHound as user *has a session on* computer, but AD-Audit stores it as
`computer -> user` because compromising the host is what exposes the account.

### Relationship catalogue

| Type | Category | Meaning (source -> target) |
| --- | --- | --- |
| `MemberOf` | membership | source is a member of target group |
| `HasSIDHistory` | sid-history | source carries target's SID in its history |
| `GenericAll` | permission | source has full control of target |
| `GenericWrite` | permission | source can write target's attributes |
| `WriteDacl` | permission | source can rewrite target's permissions |
| `WriteOwner` | permission | source can take ownership of target |
| `Owns` | permission | source owns target |
| `AllExtendedRights` | permission | source holds all extended rights on target |
| `ForceChangePassword` | permission | source can reset target's password |
| `AddMember` | permission | source can add principals to target group |
| `AddSelf` | permission | source can add itself to target group |
| `DCSync` | replication | source holds replication rights over target |
| `ReadLAPSPassword` | permission | source can read target's LAPS password |
| `ReadGMSAPassword` | permission | source can read target's gMSA password |
| `AllowedToAct` | delegation | source may impersonate users to target (RBCD) |
| `AllowedToDelegate` | delegation | source has constrained delegation to target |
| `AdminTo` | remote-access | source is local admin on target computer |
| `CanRDP` | remote-access | source may use RDP on target |
| `CanPSRemote` | remote-access | source may use remote PowerShell on target |
| `ExecuteDCOM` | remote-access | source may execute code on target via DCOM |
| `Session` | session-exposure | target has a session on source host |
| `Contains` | containment | source container holds target |
| `GPOAppliesTo` | gpo | target container is linked to source policy |

Each edge keeps its evidence: the relationship, the source and target, a
human-readable detail, a reference to the record it came from, and a quality:

| Quality | Confidence | Meaning |
| --- | --- | --- |
| `explicit` | `CONFIRMED` | stated directly by the data (membership list, ACE, session record) |
| `derived` | `LIKELY` | mechanically derived (primary group, inherited ACE, DN containment) |
| `inferred` | `POSSIBLE` | depends on an assumption and drags the whole path's confidence down |

A path's confidence is the weakest edge in the chain.

### Privileged targets

Built-in definitions are matched by domain-relative RID (any domain) or
well-known SID:

| Target | Tier | Rationale |
| --- | --- | --- |
| Domain Admins, Enterprise Admins, Schema Admins, Administrators, krbtgt, the domain object | 0 | domain or forest control |
| Account/Server/Backup/Print Operators, Group Policy Creator Owners, DnsAdmins, Key Admins, Enterprise Key Admins, Domain Controllers | 1 | delegated administration |

Matching by SID is preferred. If an export has no SIDs, a group whose name
matches a definition is used and the report marks it `[name]` and adds a note.
`--target` adds definitions with tier 0. A definition that matches no object is
listed as missing; it is never invented.

### Path search

Breadth-first over **simple** paths (a node cannot repeat within a path), which
makes cycle handling explicit: revisiting a node is pruned and counted, so
traversal always terminates. Paths are returned shortest-first and deduplicated
by their exact relationship sequence. Limits are configurable (`--max-depth`,
`--max-paths`, `--max-paths-per-pair`, `--budget`), and a run that hits one says
so in the report instead of silently returning a partial answer.

Every step is explained in the terminal report and carries its own evidence,
prerequisites and remediation. A path is a **potential** privilege path: each
step's prerequisites (an enabled account, an active session, effective
permissions) are listed because they have not been verified.

### Findings

Every finding has a stable identifier, a check id, title, severity, confidence,
category, description, source and target objects, the structured path, evidence
records, impact, recommendation, limitations, prerequisites and references.

Ids are derived from the path's relationship sequence
(`AD-PATH-<sha256 prefix>`), so the same data and options produce the same ids
and reports can be diffed across assessments.

Severity and confidence are independent:

- Tier-0 target, multi-step, or non-explicit evidence: `HIGH`.
- Tier-0 target with a direct explicit control relationship (`GenericAll`,
  `WriteDacl`, `ForceChangePassword`, `DCSync`, `AddMember`, ...): `CRITICAL`.
- Tier-1 target: `MEDIUM`; direct explicit control on it: `HIGH`.
- A `POSSIBLE` confidence downgrades severity by one step (a weakly supported
  finding is shown as `MEDIUM`, not as a confirmed `HIGH`).
- `AD-DATA-001` (severity `INFO`) summarises collection/import gaps and skipped
  checks. It appears with `--verbose` and is always in the JSON report only when
  verbose is used, matching the text output.

### Missing data

AD-Audit never assumes a relationship is absent just because it was not
collected. Missing ACLs, unreadable descriptors, unresolved SIDs, omitted
sessions, unsupported ACE rights and truncated searches become recorded issues
or gaps, and the report says the relevant category of path was not analysed.

## JSON report

The report contains, in this order:

| Key | Contents |
| --- | --- |
| `schema_version` | report schema version (`1.0`) |
| `tool` | tool name and version |
| `generated_at` | UTC timestamp |
| `assessment` | target domain, collection mode and format, inputs, completeness |
| `collection` | object counts, relationship counts by type, issues, gaps |
| `analysis` | graph size, analysis configuration, search statistics, sources, targets, targets without evidence |
| `summary` | finding counts by severity |
| `findings` | findings with paths and evidence |
| `privilege_paths` | every path found, with steps, confidence and evidence |
| `limitations` | statement of what the analysis cannot establish |
| `notes` | target/start resolution notes |
| `excluded_data` | data deliberately left out of the report |

Output is deterministic for the same dataset and options: arrays and mappings
are sorted, finding ids are content-derived, and only `generated_at` (and any
timestamp inside the source export) changes between runs.

Excluded from JSON: object attribute values (descriptions, script paths,
operating system strings), passwords, hashes, Kerberos keys and any
authentication material. Nothing sensitive is added; the report still contains
account and group names, so treat it as sensitive directory information.

## Live read-only collection

```bash
python3 main.py --collect \
    --server ldaps://dc01.corp.example \
    --base-dn 'DC=corp,DC=example' \
    --bind-dn 'CN=Audit,OU=Service,DC=corp,DC=example' \
    --password-file ~/.audit.pw \
    --json-out collection-report.json \
    --export-native dataset.json
```

Safety properties:

- Only LDAP search operations are issued. No add, modify, delete or password
  operation exists in the code.
- The bind password comes from a file, an environment variable or an
  interactive prompt -- never from a command-line argument, so it does not end
  up in shell history. It is never logged or written to the export/report.
- TLS is used when the server URL is `ldaps://`, or with `--start-tls`.
  Certificate verification is on by default; `--no-tls-verify` is opt-in and
  should only be used in a lab.
- Errors, permission limits and partial reads are recorded as issues or gaps.

Permissions needed:

| Data | Access required |
| --- | --- |
| Domain, users, groups, computers, OUs, GPO objects | read access to the objects (a normal authenticated account usually suffices) |
| Security descriptors (`nTSecurityDescriptor`) | `Read Control` (READ_CONTROL) on each object; often the limiting factor |
| Group membership (`member`) | read access to the group |
| `msDS-AllowedToActOnBehalfOfOtherIdentity` | read access to the computer's attribute |
| `gPLink` | read access to the domain/OU |

Not collected, by design or by LDAP limitation: logged-on sessions (recorded as
a gap), GPO settings contents, LAPS ciphertext, domain trusts, and any
credential material. Large groups are read with ranged attribute requests; the
range-page cap is reported if hit.

## Limitations

- A finding is a lead, not a proof. Effective access is not computed: group
  expansion, deny ACEs, control-access and ownership semantics are not fully
  evaluated, and object permission inheritance is only partially modelled.
- Prerequisites (reachable host, active session, credential material) are
  listed, never verified.
- Path length is capped; long chains and paths that need relationships outside
  the collected scope are not found.
- BloodHound exports can contain data AD-Audit does not model (trusts, SPNs,
  ADCS, GPO-derived local groups, some ACE rights). Those are reported, but
  paths relying on them are absent -- absence of a path is not evidence of
  safety.
- LDAP collection is untested against a live domain in this repository; the
  parsing and mapping logic is covered by offline unit tests, but a first run
  should be validated in a lab.
- GPO settings are not parsed; only policy links and their ACLs are analysed.
- Severity ordering is a prioritisation aid, not a CVSS score.

## Security considerations

- Run only against domains you are authorised to assess.
- Prefer `ldaps://` with a CA bundle and an account with the least access that
  still returns the data you need.
- Reports and native exports contain account names, group names, distinguished
  names, permission evidence and collection metadata. Store and share them
  accordingly; review before attaching to a ticket.
- No passwords, hashes or authentication secrets are written anywhere.
- The tool never modifies the directory, never attempts to authenticate as a
  collected account, and never contacts a host other than the LDAP server you
  name.

## Testing

The test-suite is synthetic; it requires no domain and no optional
dependencies.

```bash
pip install '.[dev]'
python -m pytest
```

156 tests cover the graph engine (direct/indirect paths, direction, cycles,
duplicates, depth/path/budget limits, no-path cases), both importers (ZIP,
directory, combined JSON, duplicate records, malformed data, unsupported files
and rights, placeholders, round-trip), target resolution, the finding engine
(severity vs confidence, stable ids, data gaps, pruning), terminal rendering
(layout, counts, verbosity, colour, wrapping), JSON determinism and schema,
security-descriptor parsing (SDDL and binary), CLI exit codes and collection
settings.

## Project layout

```
adaudit/
  models.py            data model: objects, edges, evidence, paths, findings
  relationships.py     relationship catalogue (meaning, prerequisites, remediation)
  normalize.py         SID/DN/GUID/name normalisation
  importers/           BloodHound and native JSON import, format detection
  graph.py             adjacency graph and bounded path search
  targets.py           privileged-target definitions and resolution
  analysis.py          orchestration and the finding engine
  export.py            native export writer
  report/              terminal and JSON renderers
  collection/          read-only LDAP collection and security-descriptor parsing
  cli.py               command-line interface
examples/corp-example  synthetic BloodHound export used in the docs and tests
tests/                 pytest suite with synthetic fixtures
docs/                  export format and design notes
main.py                launcher for running from a checkout
```

## License

MIT. See [LICENSE](LICENSE).
