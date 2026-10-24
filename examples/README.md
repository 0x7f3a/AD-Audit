# Synthetic example dataset

`corp-example/` is a hand-written, entirely fictional BloodHound-style export
for the domain `corp.example`. It contains no real directory data. It exists so
the README, the tests and anyone reading the source can see a complete
assessment without touching a live domain.

Objects:

- users: `analyst`, `helpdesk1`, `contractor`, `svcbackup`, `svcapp`,
  `Administrator`, `krbtgt`
- groups: `Domain Admins`, `Domain Users`, `Helpdesk`, `Support-Operators`
- computers: `DC01`, `WS01`, `FS01`
- one domain object, one OU (`Staff`), one GPO (`Baseline Policy`)

Deliberate relationships and the paths they create:

| Setup | Demonstrates |
| --- | --- |
| `analyst` is in `Helpdesk`; `Helpdesk` has `GenericAll` on `Support-Operators`; `Support-Operators` is in `Domain Admins` | multi-hop path through nested groups and a permission |
| `Support-Operators` holds `DCSync` on the domain object | replication-rights path |
| `contractor` has `GenericWrite` on the domain-linked `Baseline Policy` GPO | GPO control path |
| `contractor` has an inherited `GenericAll` on `WS01`, where `analyst` is logged on | inherited permission (lower confidence) + session exposure |
| `DC01` has an `Administrator` session and `Domain Admins` as local admins | computer-to-account analysis |
| `svcapp` has constrained delegation to `FS01`, which leads nowhere privileged | a path that correctly does not exist |
| the domain record lists a trust | a reported, unmodelled data category |

Try it:

```bash
python3 main.py -i examples/corp-example
python3 main.py -i examples/corp-example --start 'CORP.EXAMPLE\analyst' --max-paths 1
python3 main.py -i examples/corp-example --json --max-paths 2 | jq '.findings[0].id'
```

To exercise the ZIP import path, archive the directory:

```bash
(cd examples/corp-example && zip ../corp-example.zip *.json)
python3 main.py -i examples/corp-example.zip
```

The tests use these files plus programmatically built datasets, so changing the
example data can change findings and expected test counts. Keep the scenario
consistent if you edit it.
