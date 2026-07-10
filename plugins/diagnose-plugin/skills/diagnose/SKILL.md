---
name: diagnose
description: >-
  Conduct guided technical analysis and diagnosis in manual or connected mode,
  maintaining hypotheses and evidence, selecting safe tests, using human-approved
  MCP tools when available, and producing a final root-cause report. Use for
  troubleshooting applications, operating systems, servers, networks, HTTP/TLS,
  proxies, logs, containers and SQL databases.
---

# Diagnose

Use this skill as the M0 development scaffold. Do not present the complete diagnostic workflow or future executors as implemented.

## Establish available capabilities

1. Check whether the `diagnose` MCP dependency is available before entering connected mode.
2. Treat the server's advertised tool list and `capabilities_list` response as authoritative.
3. Use only the control, target-metadata, session-lifecycle, and action-status tools that the server actually advertises.
4. Continue in manual mode when the MCP server or a required capability is unavailable, and state that limitation plainly.

## Respect M0 boundaries

- Do not claim access to a host, command shell, filesystem, log source, network probe, container runtime, proxy, or database unless a later implemented capability provides direct evidence.
- Do not request, simulate, or imply remote execution through tools that are absent.
- Do not infer successful human approval from an action state that does not prove it.
- Ask the user to provide relevant observations or command output when connected evidence cannot be collected.

## Communicate evidence

- Separate user-provided facts, MCP-returned observations, hypotheses, and unknowns.
- Cite the session or action identifier when reporting MCP-derived status or results.
- Label any root-cause statement as provisional unless the available evidence supports it.
- End with a concise status summary, the strongest current hypothesis, and the next safe manual step.
