# Scanner Configs

A scanner is defined by one JSON file in `src/mulitaminer/configs/scanners/`
plus one prompt file in `configs/prompts/`. Users can plug additional scanners
with no Python: drop `<name>.json` and `<name>.txt` into a folder and point
the `MULITAMINER_SCANNERS_DIR` env var at it. This document is the config
reference and records why each built-in value is what it is. All of it was
verified empirically against the baseline reports.

## Adding a scanner

Start minimal:

```json
{
  "name": "acmescan",
  "source": "ACMESCAN",
  "max_vulns_per_chunk": 4,
  "marker_pattern": "^FINDING\\s+(CRITICAL|HIGH|MEDIUM|LOW)\\b"
}
```

The prompt file defaults to `<name>.txt` next to the JSON (or in a sibling
`prompts/` folder). An explicit `prompt` key overrides.

Then look at your report and answer three questions. Each "yes" adds one key:

1. Is the finding's name on the line above the marker? Add `name_above_marker`
   (plus `name_stop_pattern` if that line is sometimes previous-block content).
2. Is there information valid for several findings printed above them, like
   port headers or a single host line? Add `context`.
3. Is one finding printed as two or more blocks that must be re-joined? Add
   `pair`.

Verify offline, free, no LLM:

```bash
uv run mulitaminer segment report.pdf --scanner acmescan
```

The block count must equal the report's finding count. Too many blocks means
the marker also matches summary/TOC lines; too few means the marker line
varies. Iterate on the config until it matches.

For the prompt, copy the closest built-in from `configs/prompts/` and adapt
the INPUT FORMAT and field rules. Keep the `### BLOCK` / `block_id` contract
untouched and keep one worked example.

## Field reference

| Key | Meaning |
| --- | --- |
| `name` | CLI name, and the scanner a report is assigned to when its folder is named this (the `resources/<scanner>/report.pdf` convention) |
| `source` | Stamped into every record's `source` field |
| `fields` | Scanner-specific record fields, `{"<name>": "<type>"}`. Types: `str`, `list` (list[str]), `int`, `float`, `number` (int-or-float), a model `PluginDetails` / `Instance`, or `[Instance]` (list of). Added on top of the shared core (name, description, solution, impact, references, severity, host, port, protocol, source). They flow automatically into the LLM contract, per-field evaluation, and (as the union across scanners) the tabular output columns. Inspect the effective schema with `mulitaminer schema` |
| `prompt` | Optional prompt filename, defaults to `<name>.txt` |
| `max_vulns_per_chunk` | Max blocks per LLM call |
| `marker_pattern` | Regex; one match line = one block. Capture group 1 becomes the severity hint. Prefix `(?i)` for case-insensitive |
| `name_above_marker` | The finding name is the single line above the marker and is pulled into the block |
| `marker_join` | `{"start", "until", "max_lines"}`: a table row the PDF text wrapped is rejoined before the marker is tested. A line matching `start` that does not satisfy `until` absorbs the next lines until one does, within `max_lines`. For reports whose `<id> <name> <severity>` row breaks when the name is long (Tenable VM) |
| `name_stop_pattern` | A line matching it is never taken as the name |
| `discard_patterns` | Regexes (case-insensitive); a line the pattern fully matches is dropped before segmentation. For pure report noise (e.g. a `2 Results per Host 7` table cell) that would otherwise pollute a block or its name. Never matches a marker, so block count is unchanged |
| `context.header_patterns` | Regexes with named groups `sev`/`port`/`proto`; the latest match above a marker becomes that block's context |
| `context.host_anchor` / `host_line` | Host recovery: `host_line` group 1, matched on the nearest non-blank line above the anchor |
| `pair` | Structural pairing: `strip_name_suffix`, `by` (fields), `merge_instances`. Always runs |

## Record fields: shared core + per-scanner `fields`

The record model is a small **canonical core** (`models.py`: name, description,
solution, impact, references, severity, host, port, protocol, source) plus the
fields each scanner declares in its `fields`. So OpenVAS declares `cvss` (number)
and its detection lists; Tenable declares `cvss` (list), `plugin`, `plugin_details`,
`instances`; Qualys declares `category` and `plugin` (its QID). Structured
sub-schemas (`PluginDetails`, `Instance`) stay as code models and are referenced by
name; simple fields are pure config.

Output columns are the **union** across all scanners, so every scanner writes the
same tabular shape (a field it does not declare is empty). The prompt must mention
**exactly** that scanner's fields: the LLM contract is closed (`extra="forbid"`), so
naming a field the record does not have makes the whole extraction fail.

## Scanner resolution (no content auto-detection)

A report's scanner is taken from an explicit `--scanner`, or from its **parent
folder name** when that is a registered scanner (`resources/<scanner>/report.pdf`).
`mulitaminer experiment resources/` runs every scanner in one go, each report using
its folder. There is no marker-census guessing (it did not scale as scanners grew and
could silently skip a report); an unresolvable report fails with an actionable message.

## OpenVAS (`openvas.json`)

Marker `^\s*(Critical|High|Medium|Low|Log)\s+\(CVSS:`. One match line is one
finding. The marker is the `Severity (CVSS: X.Y)` line that sits immediately
above each `NVT:` line, so the severity header travels with its NVT. Marking
at `NVT:` instead leaves the header in the previous block and the LLM guesses
severity (usually LOG).

`context.header_patterns`: port/protocol headers like `High 443/tcp` appear
in three layouts (plain, reversed order, section-numbered prefix). The latest
header above a marker becomes that block's port/protocol context, rendered
into its `### BLOCK` prompt line. OpenVAS also emits pseudo-protocols in
headers (`general/CPE-T`); those stay LLM context but never enter the typed
`protocol` field.

`context.host_anchor` / `host_line`: the scanned IP sits on the nearest
non-blank line above `Host scan start`, in the report preamble before any
marker. Context tracking is the only way to recover it.

`discard_patterns`: OpenVAS PDFs carry a `2 Results per Host <page>` table cell
that wraps onto the line right after some `NVT:` names; the name-continuation
rule would otherwise append it to the finding name. The pattern drops that whole
line so the name stays clean.

`max_vulns_per_chunk: 2`, calibrated against field fill, not against
failures. At 4 nothing broke (no timeouts, no fatal JSON errors), which is
why it stood, but the tuned 1.5B silently filled fewer fields: on
openvas_raesene_bwapp, recall 0.906 and description 0.407 at 4 against
recall 1.000 and description 0.741 at 1. At 2 recall already reaches 1.000
and the run is the fastest of the three. `insight` and `cvss` decline
monotonically as the chunk shrinks (0.683/0.644 at 4, 0.611/0.577 at 2,
0.528/0.462 at 1), which is the cost of the change.

## Tenable WAS (`tenable.json`)

Marker `VULNERABILITY <SEV> PLUGIN ID <n>`, case-insensitive via `(?i)`. One
match line is one block; a finding appears as two consecutive blocks, Base
(Description/Solution/Risk/Plugin Details) and `Name Instances (N)` (per-URL
evidence).

`name_above_marker: true` plus `name_stop_pattern`: the vulnerability name is
the one line immediately before the VULNERABILITY header. Names never wrap
(max 56 chars in the ground truth); a multi-line walk-back pollutes names
with the previous block's reference tail (`BID -`, `CVE -`), breaking
pairing. The stop pattern rejects section headers and reference-content lines
as a second guard. Long `<name> Instances (N)` titles DO wrap, so the engine
climbs past a lone `(1)` or `Instances` fragment to the real name.

`pair`: base and instances blocks are merged by normalized name (with the
`Instances (N)` suffix stripped) and the fields in `by` (`plugin`, Tenable's
stable numeric ID). Pairing is structure, not deduplication; it always runs.
Without it every finding is two broken halves.

`max_vulns_per_chunk: 3`, empirical calibration.

## Nessus (`nessus.json`)

Marker `^\s*\d+ - .+$`, the `<plugin id> - <name>` line that opens each finding.
No capture group, so no severity hint: Nessus severity comes from the `Risk
Factor` section inside the block, not the marker. The prompt maps it verbatim
(`Critical->CRITICAL`, ..., `None->NONE`) and never derives it from CVSS, since
Nessus `Risk Factor` (CVSS v2 scale) routinely disagrees with the block's CVSS
v3.0 score.

`context.host_anchor` / `host_line`: each per-host section opens with a severity
count line (`0 0 1 1 11`), and the scanned IP is the line just above it. That
anchor recovers the host for every block in the section.

`discard_patterns`: the trial-license PDFs repeat a `For Trial Use Only` banner
and a `<host ip> <page>` footer that lands mid-field on page breaks; both are
dropped before segmentation.

Field mapping (in the prompt): Synopsis to `description`, Description to
`insight`, Risk Factor to `severity`, Plugin Output to `detection_result`, the
per-CVSS lines to `cvss` (a list), Plugin Information to `plugin_details`. There
is no Impact section, so `impact` is always empty.

`evaluation.field_metrics` forces `protocol` to `exact` (it is a free str, so the
inferred metric would be fuzzy text). The baseline XLSX is built from the HTML
export by `tools/nessus_html_to_baseline.py`, because a trial license cannot
produce the CSV export.

`max_vulns_per_chunk: 3`, empirical calibration.

## Tenable VM (`tenable-vm.json`)

Tenable Vulnerability Management's "Vulnerabilities by Asset" PDF, a
different product and layout from Tenable WAS even though both run Nessus
plugins: findings are grouped per asset, each opening with a table row
`<plugin id> <plugin name> <severity>` and carrying `Plugin Description:`,
`Solution:`, `See Also:`, the CVSS lines, `Reference Information:`,
`Plugin Family:` and `Plugin Output:`, mostly with the value on the line
after the label. No per-finding port, so `port`/`protocol` are always null.

`marker_join`: when the plugin name is long the row wraps, and the severity
word lands alone two lines below (`113044 GitLab 11.9.x < ...` /
`13.10.3 Remote Code Execution` / `Critical`). The row is rejoined before the
marker runs; on a 657-page report that recovered 20 of 382 findings the
one-line marker missed. Checked by counting `Plugin Description:` lines,
exactly one per finding.

`context.host_anchor` / `host_line`: the asset header prints `IPv4 Address:`
with the IP on the next line, followed by `Asset ID:`; the anchor is
`Asset ID:` and the host is the bare-IP line just above it.

`First Seen:` / `Last Seen:` are scan metadata printed after the opening
row; the prompt tells the model to ignore them. `See Also` entries carry a
`- ` bullet that the prompt strips.

`evaluation.key_parts: ["host", "plugin"]`: the same plugin fires on several
assets, and there is no port to tell instances apart.

`max_vulns_per_chunk: 3`, copied from Nessus; not yet calibrated.

## Engine-wide rules (not configurable)

- Duplicate = fully identical record, name compared normalized. Same key with
  different content is two real findings and never merges. Examples: OpenVAS
  `Services` legitimately repeats on the same host/port, one record per
  detected service; two distinct plugins can share a display name. Legitimate
  OpenVAS repeats live on different hosts/ports and are therefore never
  merged. Tenable should have no true duplicates at all, so a dedup merge in
  a Tenable run's `merge_log` is an anomaly worth investigating.
- Oversized single blocks (input alone exceeding the model's output budget,
  e.g. a block with 25 instances) are truncated at the input tail with an
  explicit `[TRUNCATED: ...]` marker and a per-block warning. Partial data
  beats a dropped finding, and the truncation is declared, never silent.
