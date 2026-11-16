# Agent Config Check

**Review an agent configuration without running it.** A small, dependency-free, local-first workbench for selected MCP JSON and Claude-style configuration fields.

## Why use it?

Before trusting a downloaded config, inspect recognizable launch commands, possible literal credentials and broad permission allowances. Compare findings against an earlier config and export a report that omits all input values, filenames and user-defined keys. No account or API key is needed.

This is **heuristic review, not a security certificate**. It does not prove a config safe or a finding exploitable. It is not a replacement for a mature security scanner.

## Start

Download the repository ZIP, extract it, and open `index.html`. There are no dependencies, CDNs or build steps. If your browser or organization blocks local files, run the following from the extracted directory and visit `http://127.0.0.1:8080`:

```sh
python3 -m http.server 8080 --bind 127.0.0.1
```

Paste JSON or choose a file explicitly. A synthetic demo is included in the interface. Optionally paste/upload a baseline. Select **Review configuration**, filter the findings and export redacted JSON. Editing either input invalidates the previous report. Failed file imports preserve existing content. Clear all removes the inputs and report from the interface.

The bilingual interface uses real HTML text, system fonts and no generated text images. The interface supports English and Simplified Chinese. Exported report schema keys and rule IDs remain English for tooling compatibility.

### CLI

With Node.js 18 or newer:

```sh
node cli.cjs ./my-config.json > review.json
```

Only that explicitly named file is read. Exit codes: `0` no high-priority heuristic findings (not “safe”), `1` high-priority findings, `2` rejected input. No recursive directory scanning, automatic discovery, modifying files, credential validation or command execution.

## Supported input

Strict JSON objects, at most 1 MiB, 64 nested levels, 30,000 traversed values. Duplicate keys and non-finite numeric results are rejected. **JSONC comments/trailing commas, YAML and TOML are not supported.** Convert privately to strict JSON or use a scanner that supports your format. Do not expect Codex TOML support.

Recognized structures:
- `mcpServers`: common MCP client JSON map, inspecting `command`, string `args`, `url` and `disabled`.
- `servers`: VS Code-style MCP map with the same inspected transport fields.
- `permissions`: selected Claude-style `allow` entries and `defaultMode`.
- `hooks`: Claude-style event arrays containing hook arrays; command hooks receive command heuristics.
- Generic nested credential-key/value heuristics also run in other JSON objects.

This is not complete validation of any client's schema. Unknown fields are not checked against client schemas. Root structures not recognized are clearly marked as unrecognized; generic secret checking alone must not be interpreted as full coverage. Effective permissions can depend on managed settings, other files and runtime behavior; none are resolved here.

## Rules and interpretation

High: possible embedded credentials, credentials/query parameters in URLs, download-to-shell patterns, elevated execution markers, selected broad allowances, approval bypass.

Medium: non-loopback HTTP, shell interpreters, package launchers requiring version/integrity review, automatic hooks, invalid/unsupported shapes within inspected fields.

Information: a configured local executable exists and warrants review before launch.

Package launchers are flagged **even when pinned** because this small tool does not parse every package manager's pin syntax or verify provenance. Not every query parameter is a secret. Environment-variable placeholders are not resolved. Credential recognition is incomplete and can produce false positives. Disabled MCP servers skip transport checks but still receive generic credential checks.

### Baseline comparisons

Findings match by **rule ID and structural position**, not server identity, raw values or effective permissions. Entry reorderings can create misleading changes. A changed dangerous value can keep the same warning. A removed warning does not prove remediation. This is a review aid, not a semantic permission diff.

## Privacy and report sharing

The app does not send network requests, execute commands, access arbitrary paths, store data in browser storage, or contact a configured service. Content remains in page memory until cleared or closed. Your browser/extensions and operating system remain outside this tool's guarantees.

Default JSON reports contain generated structural locations such as `mcpServers/server-1/command`, rule identifiers, priorities and fixed recommendations. They contain no original filenames, server names, commands, URLs or credential values. Generic `field-N` locations refer to key insertion order so the source can be reviewed locally. Reports can still reveal your security posture; review them before sharing. Input source remains visible in the input text areas, so avoid sharing screenshots while confidential inputs are present.

## Scope exclusions

No prompt-injection or malicious-server certification, runtime interception, package advisory database, secrets validity checking, effective permissions merging, automatic fixes or complete semantic shell parsing. Never grant permission just because this tool reports no findings.

## Verification

31 internal automated checks cover parsing, duplicate keys, UTF-8 byte/depth/value limits, unsupported input, malformed fields, core heuristic cases and report-value omission. Internal test files are intentionally not distributed.

The final functional candidate was downloaded, extracted and accepted in a real browser through localhost. Checks covered English/Chinese switching, import and baseline comparison, filters, invalid input handling, redacted export, and layouts at 1180 px and 400 px. The 400 px check was a browser viewport, not a physical phone. No file://, physical mobile-device or other-browser acceptance is claimed. Only this verification note was updated after that acceptance; application code is unchanged.

See [COMPARISON.md](COMPARISON.md) for positioning and [SOURCES.md](SOURCES.md) for primary references.

## License

MIT. No affiliation with Anthropic, Microsoft, Snyk or other referenced projects.
