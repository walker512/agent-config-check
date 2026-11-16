# Positioning, not a superiority claim

Reviewed primary project descriptions on 2026-11-16. This is a documentation comparison, not a benchmark of detection quality. Projects evolve.

| Project | Documented focus | Relationship to this tool |
|---|---|---|
| [Snyk Agent Scan](https://github.com/snyk/agent-scan) | Agent/MCP/skills security scanning; README warns that MCP scanning may execute stdio commands or contact remote endpoints | Prefer it when its broader checks are needed. This workbench intentionally never starts configured commands or services. |
| [aisecscan](https://github.com/jassics/aisecscan) | Static scanning of Claude configuration, permissions, hooks and related files | Clear overlap. We do not claim static analysis or offline scanning is novel. Our narrower offering is an explicit-file browser workbench with bilingual explanations, a simple baseline finding view, and exports excluding input values and user-defined keys. |
| [Gitleaks](https://github.com/gitleaks/gitleaks) | Mature secret detection for files/history and integration workflows | Use it for serious repository/history secret scanning. Our few credential heuristics are not comparable in coverage. |

The intended benefit is a low-friction, inspectable review interface for a person handed a config. There is no evidence that it detects more vulnerabilities than these tools, is unique in its features, or will attract a particular number of GitHub stars. The baseline matcher is structural, not a semantic permission-difference engine.
