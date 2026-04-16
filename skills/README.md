# Faction MCP — Shared Skills & Commands

This folder contains reusable AI assistant skills for working with the Faction MCP server. Each subfolder contains the same skills adapted for a specific AI coding tool.

| Folder | Tool | Invoke with |
|--------|------|-------------|
| `claude/` | Claude Code (CLI / IDE) | `/add-vulnerability` |
| `opencode/` | OpenCode | `/add-vulnerability` |
| `copilot/` | GitHub Copilot (VS Code) | `#add-vulnerability` in Chat |

---

## Available Skills

| Skill | Description |
|-------|-------------|
| `add-vulnerability` | Guided workflow to add a new vulnerability to a Faction assessment — searches templates, optionally generates write-ups, previews before submit |

---

## Installation

### Claude Code

Copy the contents of `claude/commands/` into `.claude/commands/` at the root of your project:

```bash
cp -r skills/claude/commands/. .claude/commands/
```

If `.claude/commands/` doesn't exist yet, create it first:

```bash
mkdir -p .claude/commands
cp -r skills/claude/commands/. .claude/commands/
```

**Usage:** Type `/add-vulnerability` in any Claude Code session inside this project.

> Global install (available in all projects): copy to `~/.claude/commands/` instead.

---

### OpenCode

Copy the contents of `opencode/commands/` into `.opencode/commands/` at the root of your project:

```bash
mkdir -p .opencode/commands
cp -r skills/opencode/commands/. .opencode/commands/
```

**Usage:** Type `/add-vulnerability` in the OpenCode TUI.

> Global install: copy to `~/.config/opencode/commands/` instead.

---

### GitHub Copilot (VS Code)

Copy the contents of `copilot/prompts/` into `.github/prompts/` at the root of your project:

```bash
mkdir -p .github/prompts
cp -r skills/copilot/prompts/. .github/prompts/
```

**Requirements:**
- VS Code with the GitHub Copilot Chat extension
- Copilot Chat in **Agent mode** (so it can call MCP tools)
- The Faction MCP server configured in VS Code settings (see below)

**Configure MCP in VS Code** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "faction": {
      "command": "docker",
      "args": ["run", "-i", "--rm",
        "-e", "FACTION_API_KEY",
        "-e", "FACTION_BASE_URL",
        "factionsecurityllc/faction-mcp:latest"
      ],
      "env": {
        "FACTION_API_KEY": "${env:FACTION_API_KEY}",
        "FACTION_BASE_URL": "${env:FACTION_BASE_URL}"
      }
    }
  }
}
```

**Usage:** Open Copilot Chat, switch to Agent mode, then type:
```
#add-vulnerability
```
or select it from the prompt file picker (paperclip icon → Prompt…).

---

## Adding New Skills

1. Create the skill in all three formats and place them in the appropriate subfolders
2. Update the skills table in this README
3. Follow the naming convention: `skill-name.md` (Claude/OpenCode) and `skill-name.prompt.md` (Copilot)
