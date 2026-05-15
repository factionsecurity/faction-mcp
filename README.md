# Faction MCP Server

MCP server for the [Faction](https://github.com/factionsecurity/faction) penetration testing management platform. Exposes assessments, vulnerabilities, retests, and audit logs to any MCP-compatible AI client.

## Prerequisites

- Docker (or Podman) installed
- A running Faction instance
- A Faction API key — generate one under your user profile in Faction

---

## Option 1: Docker Desktop MCP Catalog

Install directly from the Docker Desktop MCP Catalog. Enter your `FACTION_API_KEY` and `FACTION_BASE_URL` when prompted.

---

## Option 2: Docker Compose (Docker or Podman)

This option works anywhere Docker Compose or Podman Compose is available.

### 1. Configure credentials

```bash
cp .env.example .env
```

Edit `.env` and fill in your values:

```env
FACTION_API_KEY=xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
FACTION_BASE_URL=https://faction.yourcompany.com
```

#### Optional: shared reports / images directory

The compose files mount a single host directory into the container at `/app/reports`. By default this is `/tmp`. It serves two purposes:

1. **Downloaded reports** — `get_assessment_report` and `generate_assessment_report` write the PDF/DOCX here, and the host path is returned as `file_path` so the client can open it.
2. **Image uploads** — `upload_assessment_image` reads files from this directory. The LLM is instructed to `cp` host-side images here first (or save pasted screenshots here), then pass the host path. The server auto-translates `/tmp/foo.png` → `/app/reports/foo.png` internally so the LLM doesn't have to think about the container.

Going through disk avoids round-tripping a large base64 string through tool arguments, where token-stream drift can corrupt the bytes.

To use a different host folder, set `FACTION_REPORTS_HOST_DIR` in `.env` to an absolute path:

```env
FACTION_REPORTS_HOST_DIR=/Users/me/faction-reports
```

### 2. Build the image

```bash
docker compose build
```

Podman:
```bash
podman-compose build
```

### 3. Configure your MCP client

Add the following to your MCP client config (e.g. `~/.claude/settings.json` for Claude Code, or `claude_desktop_config.json` for Claude Desktop):

**Docker:**
```json
{
  "mcpServers": {
    "faction": {
      "command": "docker",
      "args": [
        "compose",
        "-f", "/absolute/path/to/faction-mcp/docker-compose.yml",
        "run", "--rm", "-T", "faction-mcp"
      ]
    }
  }
}
```

**Podman:**
```json
{
  "mcpServers": {
    "faction": {
      "command": "podman-compose",
      "args": [
        "-f", "/absolute/path/to/faction-mcp/docker-compose.yml",
        "run", "--rm", "-T", "faction-mcp"
      ]
    }
  }
}
```

> The `-T` flag disables pseudo-TTY allocation so stdio passes through cleanly to the MCP client.

To update credentials, edit `.env` — no rebuild required.

---

## Available Tools

### Assessments

| Tool | Description |
|------|-------------|
| `get_assessment_queue` | Get the user's active queue (in-progress / upcoming / past-due). Use this for "my recent assessments" — not the completed endpoints |
| `get_completed_assessments` | Get completed assessments within a date range with full detail |
| `get_completed_assessments_condensed` | Same as above but with large text blocks stripped — preferred for stats and historical summaries |
| `get_assessment` | Get full details for a specific assessment by ID |
| `update_assessment` | Update assessment fields: notes, executive summary, distribution list, custom fields |
| `get_assessment_vulnerabilities` | Get full vulnerability data for an assessment (large response — includes HTML and screenshots) |
| `get_vulnerability_summary_data` | Get stripped vulnerability data optimized for generating executive summaries |
| `get_assessment_report` | Download the existing report (PDF/DOCX) for an assessment to the configured reports directory |
| `generate_assessment_report` | Kick off a fresh report build and poll until it finishes (or until `max_wait_seconds` elapses) |
| `check_report_status` | Standalone status check used to resume polling when generation outlasts the initial wait |

### Vulnerabilities

| Tool | Description |
|------|-------------|
| `get_vulnerabilities` | Get all vulnerabilities opened within a date range with full detail |
| `get_vulnerabilities_condensed` | Same as above with large text blocks stripped — preferred for stats and summaries |
| `create_vulnerability` | Add a vulnerability to an assessment. Interactively prompts for missing title/severity, offers matching default templates, and confirms whether to mirror severity to impact/likelihood |
| `update_vulnerability` | Update fields on an existing vulnerability |
| `add_templated_vulnerability` | Add a vulnerability from a default template (search with `search_vulnerability_templates` first) |
| `get_vulnerability` | Get a vulnerability by ID |
| `get_vulnerability_by_tracking` | Get a vulnerability by tracking ID (e.g. Jira ticket) |
| `set_vulnerability_tracking` | Assign a tracking ID to a vulnerability |
| `set_vulnerability_status` | Set remediation status (dev/prod closed dates) |
| `get_risk_levels` | Get the configured (mapped) risk level definitions; unmapped slots are filtered out |
| `get_categories` | Get all vulnerability categories |
| `get_category` | Get a specific category by ID |
| `create_category` | Create a new vulnerability category (manager role required) |

### Vulnerability Templates

| Tool | Description |
|------|-------------|
| `get_vulnerability_templates` | Get all default vulnerability templates |
| `search_vulnerability_templates` | Search templates by name (partial match) |
| `get_vulnerability_template` | Get a specific template by ID |
| `create_vulnerability_templates` | Create or update default vulnerability templates |

### Retests / Verifications

| Tool | Description |
|------|-------------|
| `get_verification_queue` | Get the retest queue assigned to the authenticated user |
| `get_all_verifications` | Get all verifications, optionally filtered by date range |
| `get_user_verifications` | Get verifications for a specific user |
| `complete_verification` | Mark a retest as passed or failed |
| `schedule_retest` | Schedule a retest for a vulnerability |

### Audit Logs

| Tool | Description |
|------|-------------|
| `get_audit_log` | Get the system audit log for a date range (admin role required) |
| `get_assessment_audit_log` | Get audit log entries for all assessments in a date range |
| `get_assessment_audit_log_by_id` | Get audit log entries for a specific assessment |
| `get_user_audit_log` | Get audit log entries for a specific user |

---

## Generating Executive Summaries

Use `get_vulnerability_summary_data` (not `get_assessment_vulnerabilities`) when generating executive summaries. It returns clean, stripped text optimized for LLM processing. After the AI generates the summary HTML, it will call `update_assessment` to save it automatically.

## Creating Vulnerabilities

`create_vulnerability` (and `update_vulnerability` / `add_templated_vulnerability`) accept severity, impact, and likelihood as **risk-level NAMES** — e.g. `"Critical"`, `"High"`, `"P1"`. The server resolves the name to the correct numeric ID for your Faction instance using `get_risk_levels`, so the LLM does not have to guess and IDs that differ between instances do not need to be hard-coded.

When required information is missing, `create_vulnerability` walks the user through an interactive workflow via MCP elicitation (supported by Claude Code, Claude Desktop, and other elicitation-capable clients):

1. **Title and severity** — if either is missing, the user is prompted for it. Risk levels are presented as a dropdown of the names actually configured on the instance.
2. **Template offer** — if no `description` / `recommendation` / `vuln_template_id` is supplied, the server searches default templates by the vulnerability title and offers any matches. Picking one auto-populates description and recommendation.
3. **Mirror severity** — if severity is set but impact/likelihood are not, the server asks whether to use the severity level for both. Pick "no" and a follow-up form asks for the explicit impact and likelihood values.

If the calling client does not support elicitation, the tool returns a clear error listing the missing fields so the LLM can ask the user via plain text instead.

## Generating and Downloading Reports

There are three tools for working with assessment reports:

- **`generate_assessment_report`** — kicks off a fresh report build (use `retest=true` for finalized assessments) and polls for completion up to `max_wait_seconds` (default 60). When the report is ready, the response says so; if it's still building, the response includes the `gentime` so polling can be resumed.
- **`check_report_status`** — standalone poll for the case where the initial wait window expired. Pass `last_known_gentime` from the generate response.
- **`get_assessment_report`** — downloads the existing report (PDF or DOCX). The file is written to the configured reports directory and the absolute host path is returned as `file_path`.

Typical flow:

1. Ask the AI to "generate a new report for assessment 420."
2. The MCP server fires generation, waits ~60s, and reports completion (or tells the LLM to keep polling for longer-running reports).
3. Once `status` is `complete`, the AI calls `get_assessment_report` and shares the host file path so the user can open the document.

Reports are saved to whichever path you configured via `FACTION_REPORTS_HOST_DIR` (see [reports directory](#optional-reports-directory)). Default: `./faction-reports` next to the compose file.
