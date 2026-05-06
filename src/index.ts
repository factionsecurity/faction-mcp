import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";
import { readFileSync, writeFileSync, mkdirSync } from "fs";
import { extname, join } from "path";
import { tmpdir } from "os";

const API_KEY = process.env.FACTION_API_KEY;
const BASE_URL = process.env.FACTION_BASE_URL?.replace(/\/$/, "");
const REPORTS_DIR = process.env.FACTION_REPORTS_DIR || tmpdir();
// Optional: when running in Docker, the in-container REPORTS_DIR maps to a different
// path on the host. Set this to the host-side path so returned file_paths are openable
// on the user's machine.
const REPORTS_HOST_DIR = process.env.FACTION_REPORTS_HOST_DIR;

if (!API_KEY || !BASE_URL) {
  process.stderr.write("FACTION_API_KEY and FACTION_BASE_URL are required\n");
  process.exit(1);
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

async function factionGet(path: string): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/api${path}`, {
    headers: { "FACTION-API-KEY": API_KEY! },
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Faction API ${res.status}: ${text}`);
  return JSON.parse(text);
}

function sanitizeRichText(text: string): string {
  // Markdown headers → bold
  let out = text.replace(/^#{1,6}\s+(.+)$/gm, "**$1**");
  // HTML headers → <strong>
  out = out.replace(/<h[1-6][^>]*>(.*?)<\/h[1-6]>/gi, "<strong>$1</strong>");
  return out;
}

async function factionPost(path: string, body: Record<string, string | number | boolean | undefined>): Promise<unknown> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) {
    if (v !== undefined) params.set(k, String(v));
  }
  const res = await fetch(`${BASE_URL}/api${path}`, {
    method: "POST",
    headers: {
      "FACTION-API-KEY": API_KEY!,
    },
    body: params,
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Faction API ${res.status}: ${text}`);
  return text ? JSON.parse(text) : {};
}

async function factionPostJSON(path: string, body: unknown): Promise<unknown> {
  const res = await fetch(`${BASE_URL}/api${path}`, {
    method: "POST",
    headers: {
      "FACTION-API-KEY": API_KEY!,
      "Content-Type": "application/json",
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Faction API ${res.status}: ${text}`);
  return text ? JSON.parse(text) : {};
}

async function factionGetWithStatus(path: string): Promise<{ code: number; body: unknown }> {
  const res = await fetch(`${BASE_URL}/api${path}`, {
    headers: { "FACTION-API-KEY": API_KEY! },
  });
  const text = await res.text();
  if (res.status >= 400) throw new Error(`Faction API ${res.status}: ${text}`);
  return { code: res.status, body: text ? JSON.parse(text) : null };
}

async function factionGetBinary(path: string): Promise<{ buffer: Buffer; filename: string; contentType: string }> {
  const res = await fetch(`${BASE_URL}/api${path}`, {
    headers: { "FACTION-API-KEY": API_KEY! },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Faction API ${res.status}: ${text}`);
  }
  const arrayBuf = await res.arrayBuffer();
  const buffer = Buffer.from(arrayBuf);
  const contentType = res.headers.get("content-type") ?? "application/octet-stream";
  const disposition = res.headers.get("content-disposition") ?? "";
  const match = disposition.match(/filename\*=UTF-8''([^;]+)|filename="?([^";]+)"?/i);
  const filename = decodeURIComponent(match?.[1] ?? match?.[2] ?? "download.bin").trim();
  return { buffer, filename, contentType };
}

function ok(data: unknown) {
  return {
    content: [{ type: "text" as const, text: JSON.stringify(data, null, 2) }],
  };
}

function err(e: unknown) {
  const msg = e instanceof Error ? e.message : String(e);
  return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
}

// ---------------------------------------------------------------------------
// Risk level resolution (name → ID)
// ---------------------------------------------------------------------------

type RiskLevel = { id: number; name: string };
let riskLevelsCache: { ts: number; levels: RiskLevel[] } | null = null;
const RISK_LEVELS_TTL_MS = 5 * 60 * 1000;

async function getMappedRiskLevels(): Promise<RiskLevel[]> {
  if (riskLevelsCache && Date.now() - riskLevelsCache.ts < RISK_LEVELS_TTL_MS) {
    return riskLevelsCache.levels;
  }
  const raw = await factionGet("/vulnerabilities/getrisklevels") as Array<Record<string, unknown>>;
  const levels: RiskLevel[] = raw
    .filter((l) => typeof l?.name === "string" && (l.name as string).trim() !== "")
    .map((l) => ({ id: Number(l.id), name: String(l.name) }));
  riskLevelsCache = { ts: Date.now(), levels };
  return levels;
}

async function resolveRiskLevel(value: string | number | undefined): Promise<number | undefined> {
  if (value === undefined || value === null) return undefined;
  if (typeof value === "number") return value;
  const trimmed = value.trim();
  if (trimmed === "") return undefined;
  if (/^\d+$/.test(trimmed)) return Number(trimmed);
  const levels = await getMappedRiskLevels();
  const target = trimmed.toLowerCase();
  const exact = levels.find((l) => l.name.toLowerCase() === target);
  if (exact) return exact.id;
  const startsWith = levels.find((l) => l.name.toLowerCase().startsWith(target));
  if (startsWith) return startsWith.id;
  const names = levels.map((l) => `${l.name} (${l.id})`).join(", ");
  throw new Error(`Unknown risk level "${value}". Valid risk levels for this instance: ${names}`);
}

function clientSupportsElicitation(): boolean {
  try {
    return Boolean(server.server.getClientCapabilities()?.elicitation);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "faction",
  version: "1.0.0",
}, {
  instructions: [
    "SEVERITY / RISK / IMPACT / LIKELIHOOD: Vulnerability and assessment responses include human-readable string fields — `overallStr` (overall risk level), `impactStr`, and `likelyHoodStr` — alongside their numeric ID counterparts. Always use the string fields when reasoning, filtering, counting, grouping, or displaying these values to the user.",
    "When the user asks about a severity (e.g. 'show me all critical findings', 'how many high vulns', 'list the P1 issues'), match on `overallStr` from the response. The exact set of values (Critical/High/Medium/Low, P1/P2/P3, etc.) is whatever the instance has configured and will be visible in the data — match on what's there, case-insensitive.",
    "Never include the numeric IDs for overall risk, impact, or likelihood in output to the user unless they specifically ask for the numeric IDs.",
    "WRITES (create_vulnerability / update_vulnerability / add_templated_vulnerability): pass severity/impact/likelihood as the risk level NAME (e.g. 'Critical', 'High', 'P1'). The server resolves names to instance-specific IDs automatically — do NOT try to translate names to numeric IDs yourself, and do NOT guess numeric IDs. On create, if you only have severity, omit impact/likelihood and the server will default them to the severity level.",
    "ASSESSMENT QUERIES — disambiguation: 'my assessments', 'my recent assessments', 'my current/active/open assessments', 'what's on my plate', or 'what am I working on' all refer to the user's active queue — use get_assessment_queue. Only use get_completed_assessments / get_completed_assessments_condensed when the user explicitly asks about COMPLETED, CLOSED, FINISHED, PAST, or HISTORICAL work, or when they specify a past date range.",
  ].join(" "),
});

// ===========================================================================
// ASSESSMENTS
// ===========================================================================

server.tool(
  "get_assessment_queue",
  "Get the authenticated user's active assessment queue — assessments currently assigned to them that are in progress, upcoming, or past due (i.e. not yet completed). USE THIS for prompts like 'show me my assessments', 'my recent assessments', 'what's on my plate', 'my current/active/open assessments', 'what am I working on'. Requires assessor or manager role. Do NOT use this for historical or completed work — use get_completed_assessments_condensed for that.",
  {},
  async () => {
    try {
      return ok(await factionGet("/assessments/queue"));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment",
  "Get full details for a specific assessment by ID.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
  },
  async ({ assessment_id }) => {
    try {
      return ok(await factionGet(`/assessments/${assessment_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "update_assessment",
  "Update fields on an assessment. Only provided fields are updated. Custom fields should be a JSON object of key-value pairs.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    notes: z.string().optional().describe("Assessment notes"),
    summary: z.string().optional().describe("Executive summary"),
    distribution_list: z.string().optional().describe("Distribution list (comma-separated emails)"),
    custom_fields: z.record(z.string(), z.string()).optional().describe("Custom field key-value pairs"),
  },
  async ({ assessment_id, notes, summary, distribution_list, custom_fields }) => {
    try {
      const body: Record<string, string | undefined> = {
        notes,
        summary,
        distributionList: distribution_list,
        customFields: custom_fields ? JSON.stringify(custom_fields) : undefined,
      };
      return ok(await factionPost(`/assessments/${assessment_id}`, body));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment_vulnerabilities",
  "Get all vulnerabilities for a specific assessment. Returns full details including screenshots and HTML — response can be very large. Do NOT use this tool to generate executive summaries. For executive summaries, use get_vulnerability_summary_data instead.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
  },
  async ({ assessment_id }) => {
    try {
      return ok(await factionGet(`/assessments/vulns/${assessment_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerability_summary_data",
  "Use this tool first when asked to write or generate an executive summary for an assessment. Returns clean structured vulnerability data with HTML and images stripped, optimized for LLM processing. After receiving this data, write a professional executive summary in HTML and call update_assessment to save it.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
  },
  async ({ assessment_id }) => {
    try {
      const vulns = await factionGet(`/assessments/vulns/${assessment_id}`) as Array<Record<string, unknown>>;

      function stripHtml(html: unknown): string {
        if (!html) return "";
        return String(html)
          .replace(/<[^>]+>/g, " ")
          .replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">")
          .replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&nbsp;/g, " ")
          .replace(/&#61;/g, "=").replace(/&#43;/g, "+").replace(/&#34;/g, '"')
          .replace(/\s+/g, " ").trim();
      }

      const cleaned = vulns.map((v) => ({
        name: v.Name,
        risk_level: v.RiskLevel,
        severity: v.Severity,
        cvss: v.CVSS,
        status: v.Status,
        description: stripHtml(v.Description),
        recommendation: stripHtml(v.Recommendation),
      }));

      return ok({
        assessment_id,
        vulnerability_count: cleaned.length,
        vulnerabilities: cleaned,
        next_step: "Use the vulnerability data above to write a professional executive summary in HTML format, then call update_assessment with the generated summary HTML to save it to this assessment.",
      });
    } catch (e) { return err(e); }
  }
);

server.tool(
  "upload_assessment_image",
  "Upload an image to a Faction assessment. Returns the image GUID and a markdown embed link that can be pasted directly into vulnerability descriptions, recommendations, or details fields. Provide either a local file path OR a pre-encoded base64 data URI — not both.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    image_path: z.string().optional().describe("Absolute path to the image file on disk (png, jpg, gif, webp)"),
    encoded_image: z.string().optional().describe("Base64 data URI of the image (e.g. data:image/png;base64,AAAA...)"),
  },
  async ({ assessment_id, image_path, encoded_image }) => {
    try {
      if (!image_path && !encoded_image) {
        return err(new Error("Provide either image_path or encoded_image"));
      }

      let dataUri: string;

      if (image_path) {
        const data = readFileSync(image_path);
        const ext = extname(image_path).toLowerCase().replace(".", "");
        const mimeMap: Record<string, string> = {
          png: "image/png",
          jpg: "image/jpeg",
          jpeg: "image/jpeg",
          gif: "image/gif",
          webp: "image/webp",
          svg: "image/svg+xml",
        };
        const mime = mimeMap[ext] ?? "image/png";
        dataUri = `data:${mime};base64,${data.toString("base64")}`;
      } else {
        dataUri = encoded_image!;
      }

      return ok(await factionPostJSON(`/assessments/image/${assessment_id}`, {
        encodedImage: dataUri,
      }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "create_assessment",
  "Create a new assessment and schedule it to one or more assessors. Auto-creates users and teams if they don't exist — unknown emails receive a registration invite. Dates in YYYY-MM-DD format. Assessors and distribution list are semicolon-delimited. (engage role required)",
  {
    app_name: z.string().describe("Application/target name"),
    type: z.string().describe("Assessment type (e.g. 'Web Application', 'Network', 'Mobile')"),
    campaign: z.string().describe("Campaign name to associate this assessment with"),
    start: z.string().describe("Assessment start date (YYYY-MM-DD)"),
    end: z.string().describe("Assessment end date (YYYY-MM-DD)"),
    assessors: z.string().describe("Semicolon-delimited list of assessor usernames (e.g. 'jdoe;jsmith')"),
    engagement_username: z.string().describe("Username of the engagement/scheduling contact"),
    remediation_username: z.string().describe("Username of the remediation contact"),
    app_id: z.string().optional().describe("Existing application ID to link this assessment to"),
    distro: z.string().optional().describe("Semicolon-delimited distribution list of emails"),
    scope: z.string().optional().describe("Scope, credentials, and context for the assessors"),
    auto_create_campaigns: z.boolean().optional().default(true).describe("Auto-create the campaign if it does not already exist"),
  },
  async ({ app_name, type, campaign, start, end, assessors, engagement_username, remediation_username, app_id, distro, scope, auto_create_campaigns }) => {
    try {
      const body: Record<string, string | boolean | undefined> = {
        appName: app_name,
        type,
        campaign,
        start,
        end,
        assessors,
        engagement_username,
        remediation_username,
        appid: app_id,
        distro,
        scope,
        auto_create_campaigns,
      };
      return ok(await factionPost("/assessments/create", body));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_completed_assessments",
  "Get all COMPLETED assessments within a date range with full detail. Dates in MM/DD/YYYY format. Response can be very large — for stats or summarizing completed work, use get_completed_assessments_condensed instead. Do NOT use this for 'my recent/current/active assessments' — that's the live queue (get_assessment_queue).",
  {
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().optional().describe("End date (MM/DD/YYYY). Defaults to now if omitted."),
  },
  async ({ start, end }) => {
    try {
      return ok(await factionPost("/assessments/completed", { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_completed_assessments_condensed",
  "Get all COMPLETED assessments within a date range with a condensed (shorter) payload — vulnerabilities are included but with large text blocks (description, recommendation, details) and assessment summary/riskAnalysis stripped out. Prefer this tool for stats, summarizing vulnerability counts across past work, or filtering historical findings (e.g. 'how many critical findings did we close last quarter'). Dates in MM/DD/YYYY format. Do NOT use this for 'my recent/current/active assessments' — that's the live queue (get_assessment_queue).",
  {
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().optional().describe("End date (MM/DD/YYYY). Defaults to now if omitted."),
  },
  async ({ start, end }) => {
    try {
      const params = new URLSearchParams({ start });
      if (end) params.set("end", end);
      return ok(await factionGet(`/assessments/completed/condensed?${params.toString()}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment_report",
  "Download the existing report file (PDF or DOCX) for an assessment. Use this when the user asks to download/export/save the report. If the assessment hasn't generated a report yet, or the user wants a fresh one, call generate_assessment_report first. The report is saved to the local filesystem and the absolute path is returned — share that path with the user so they can open the file.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
  },
  async ({ assessment_id }) => {
    try {
      const { buffer, filename, contentType } = await factionGetBinary(`/assessments/report/${assessment_id}`);
      const safeName = filename.replace(/[/\\]/g, "_");
      mkdirSync(REPORTS_DIR, { recursive: true });
      const fileBase = `faction-report-${assessment_id}-${Date.now()}-${safeName}`;
      const writePath = join(REPORTS_DIR, fileBase);
      writeFileSync(writePath, buffer);
      const hostPath = REPORTS_HOST_DIR ? join(REPORTS_HOST_DIR, fileBase) : writePath;
      return ok({
        file_path: hostPath,
        filename: safeName,
        content_type: contentType,
        size_bytes: buffer.length,
      });
    } catch (e) { return err(e); }
  }
);

server.tool(
  "generate_assessment_report",
  "Generate (or regenerate) the report for an assessment. The server kicks off background generation, then polls for completion up to `max_wait_seconds`. When status returns 'complete', call get_assessment_report to download the file. If still 'generating' after the wait window, the response includes the gentime so check_report_status can resume polling. Use retest=true to generate a retest report (required for assessments that are already finalized).",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    retest: z.boolean().optional().describe("Generate a retest report. Required for finalized assessments — the regular generate fails on those."),
    max_wait_seconds: z.number().int().min(0).max(600).optional().describe("Max seconds to wait for completion before returning. Default 60. Set to 0 to fire-and-forget (returns immediately after kicking off generation)."),
  },
  async ({ assessment_id, retest, max_wait_seconds }) => {
    try {
      const isRetest = retest === true;
      const genRes = await factionPost(`/assessments/generateReport/${assessment_id}`, {
        retest: isRetest ? "true" : undefined,
      }) as { gentime: string; status: string; assessmentId: number; retest: boolean };

      const lastKnownGentime = genRes.gentime;
      const maxWait = max_wait_seconds ?? 60;

      if (maxWait <= 0 || genRes.status === "complete") {
        return ok({
          ...genRes,
          message: genRes.status === "complete"
            ? "Report ready. Use get_assessment_report to download."
            : `Report generation started in background. Call check_report_status with last_known_gentime="${lastKnownGentime}" to check progress.`,
        });
      }

      const startedAt = Date.now();
      const deadline = startedAt + maxWait * 1000;
      let interval = 2000;
      let lastBody: Record<string, unknown> = genRes as unknown as Record<string, unknown>;

      while (Date.now() < deadline) {
        const remaining = deadline - Date.now();
        await new Promise((r) => setTimeout(r, Math.min(interval, remaining)));
        interval = Math.min(interval + 1000, 8000);

        const params = new URLSearchParams({ lastKnownGentime });
        if (isRetest) params.set("retest", "true");
        const status = await factionGetWithStatus(`/assessments/reportStatus/${assessment_id}?${params.toString()}`);
        lastBody = (status.body as Record<string, unknown>) ?? {};
        if (status.code === 200 && lastBody.status === "complete") {
          return ok({
            ...lastBody,
            elapsed_seconds: Math.round((Date.now() - startedAt) / 1000),
            message: "Report generation complete. Use get_assessment_report to download the file.",
          });
        }
      }

      return ok({
        ...lastBody,
        status: "generating",
        elapsed_seconds: Math.round((Date.now() - startedAt) / 1000),
        message: `Report still generating after ${maxWait}s. Call check_report_status with assessment_id=${assessment_id} and last_known_gentime="${lastKnownGentime}" to keep checking.`,
      });
    } catch (e) { return err(e); }
  }
);

server.tool(
  "check_report_status",
  "Check whether a report generation job is complete. Returns 'complete' if the report is ready (call get_assessment_report to download) or 'generating' if it's still being built. Pair with generate_assessment_report — pass the gentime returned from that call as last_known_gentime for accurate comparison.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    last_known_gentime: z.string().optional().describe("The gentime returned from generate_assessment_report. Strongly recommended — without it the server can't tell whether a finished report is the one you just kicked off."),
    retest: z.boolean().optional().describe("Check the retest report status"),
  },
  async ({ assessment_id, last_known_gentime, retest }) => {
    try {
      const params = new URLSearchParams();
      if (last_known_gentime) params.set("lastKnownGentime", last_known_gentime);
      if (retest === true) params.set("retest", "true");
      const qs = params.toString();
      const status = await factionGetWithStatus(`/assessments/reportStatus/${assessment_id}${qs ? "?" + qs : ""}`);
      return ok(status.body);
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment_history",
  "Get the vulnerability history for an application across all its assessments. Note: Application ID is not the same as Assessment ID — one application can span multiple assessments.",
  {
    app_id: z.string().describe("The application ID (not the assessment ID)"),
  },
  async ({ app_id }) => {
    try {
      return ok(await factionGet(`/assessments/history/${encodeURIComponent(app_id)}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment_custom_field_types",
  "Get the allowed custom field types for an assessment, including both assessment-level and vulnerability-level field definitions. Use this before setting custom_fields to know which keys are valid.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
  },
  async ({ assessment_id }) => {
    try {
      return ok(await factionGet(`/assessments/customfields/${assessment_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerability_details",
  "Get full details and exploit steps for a specific vulnerability by ID (assessor role required). Returns richer data than get_vulnerability, including step-by-step exploit information.",
  {
    vulnerability_id: z.number().int().describe("The vulnerability ID"),
  },
  async ({ vulnerability_id }) => {
    try {
      return ok(await factionGet(`/assessments/vuln/${vulnerability_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "update_vulnerability_custom_fields",
  "Update only the custom fields for an existing vulnerability. Custom field keys must match allowed types for the assessment — use get_assessment_custom_field_types to check valid keys.",
  {
    vulnerability_id: z.number().int().describe("The vulnerability ID"),
    custom_fields: z.record(z.string(), z.string()).describe("Custom field key-value pairs"),
  },
  async ({ vulnerability_id, custom_fields }) => {
    try {
      return ok(await factionPost(`/assessments/vuln/${vulnerability_id}/customfields`, {
        customFields: JSON.stringify(custom_fields),
      }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "create_vulnerability",
  "Add a new vulnerability to an assessment (assessor role required). Description, recommendation, and details support HTML/Markdown. Pass severity/impact/likelihood as the risk level NAME (e.g. 'Critical', 'High', 'P1') — the server resolves the correct ID for this instance. The server walks an interactive workflow when info is missing: (1) prompts for title/severity if absent (and impact/likelihood when severity is also absent); (2) if no description/recommendation/template is provided, searches default templates by title and offers any matches; (3) if severity is set but impact/likelihood are not, asks whether to mirror severity or set them separately. Don't guess values — call the tool and let the server drive the prompts.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    name: z.string().optional().describe("Vulnerability title. If omitted, the user will be prompted."),
    vuln_template_id: z.number().int().optional().describe("Default vulnerability template ID to pre-populate fields. If omitted and no description/recommendation is given, the server will offer matching templates."),
    description: z.string().optional().describe("Vulnerability description (HTML/Markdown supported)"),
    recommendation: z.string().optional().describe("Remediation recommendation (HTML/Markdown supported)"),
    details: z.string().optional().describe("Exploit details / proof of concept (HTML/Markdown supported)"),
    category_id: z.number().int().optional().describe("Vulnerability category ID"),
    severity: z.union([z.string(), z.number().int()]).optional().describe("Overall severity. Pass the risk level NAME as a string (e.g. 'Critical', 'High', 'P1'). If omitted, the user will be prompted."),
    impact: z.union([z.string(), z.number().int()]).optional().describe("Impact risk level NAME. If omitted, the server asks whether to mirror severity."),
    likelihood: z.union([z.string(), z.number().int()]).optional().describe("Likelihood risk level NAME. If omitted, the server asks whether to mirror severity."),
    cvss_score: z.string().optional().describe("CVSS score (e.g. '7.5')"),
    cvss_string: z.string().optional().describe("CVSS vector string"),
    section: z.string().optional().describe("Section (Enterprise feature)"),
    custom_fields: z.record(z.string(), z.string()).optional().describe("Custom field key-value pairs"),
  },
  async ({ assessment_id, name, vuln_template_id, description, recommendation, details, category_id, severity, impact, likelihood, cvss_score, cvss_string, section, custom_fields }) => {
    try {
      const isBlank = (v: unknown) => v === undefined || v === null || (typeof v === "string" && v.trim() === "");
      const elicit = (params: Parameters<typeof server.server.elicitInput>[0]) => server.server.elicitInput(params);
      const supportsPrompt = clientSupportsElicitation();

      // ----- STEP 1: Title and severity (and impact/likelihood when severity is missing) -----
      const step1Missing: string[] = [];
      if (isBlank(name)) step1Missing.push("name");
      if (isBlank(severity)) {
        step1Missing.push("severity");
        if (isBlank(impact)) step1Missing.push("impact");
        if (isBlank(likelihood)) step1Missing.push("likelihood");
      }

      if (step1Missing.length > 0) {
        if (!supportsPrompt) {
          return err(new Error(`Missing required fields: ${step1Missing.join(", ")}. Ask the user for these values and call create_vulnerability again. Valid risk level names are available from get_risk_levels.`));
        }
        const levelNames = (await getMappedRiskLevels()).map((l) => l.name);
        const properties: Record<string, unknown> = {};
        const required: string[] = [];
        if (step1Missing.includes("name")) {
          properties.name = { type: "string", title: "Title", description: "Vulnerability title" };
          required.push("name");
        }
        if (step1Missing.includes("severity")) {
          properties.severity = { type: "string", title: "Overall Severity", enum: levelNames };
          required.push("severity");
        }
        if (step1Missing.includes("impact")) {
          properties.impact = { type: "string", title: "Impact (optional — defaults to severity)", enum: levelNames };
        }
        if (step1Missing.includes("likelihood")) {
          properties.likelihood = { type: "string", title: "Likelihood (optional — defaults to severity)", enum: levelNames };
        }
        const r = await elicit({
          message: `Add new vulnerability to assessment ${assessment_id}. Please provide the missing fields.`,
          requestedSchema: { type: "object", properties: properties as never, ...(required.length > 0 ? { required } : {}) },
        });
        if (r.action !== "accept" || !r.content) return err(new Error(`Vulnerability creation cancelled by user (${r.action}).`));
        const c = r.content as Record<string, unknown>;
        if (step1Missing.includes("name") && typeof c.name === "string") name = c.name;
        if (step1Missing.includes("severity") && typeof c.severity === "string") severity = c.severity;
        if (step1Missing.includes("impact") && typeof c.impact === "string" && c.impact !== "") impact = c.impact;
        if (step1Missing.includes("likelihood") && typeof c.likelihood === "string" && c.likelihood !== "") likelihood = c.likelihood;
      }

      // ----- STEP 2: Offer template if no description/recommendation/template -----
      if (supportsPrompt && vuln_template_id === undefined && isBlank(description) && isBlank(recommendation) && !isBlank(name)) {
        try {
          const templates = await factionGet(`/vulnerabilities/default/${encodeURIComponent(String(name))}`) as Array<{ Id: number; Name: string }>;
          const valid = (templates ?? []).filter((t) => t && typeof t.Id === "number" && typeof t.Name === "string" && t.Name.trim() !== "");
          if (valid.length > 0) {
            const NONE = "None — write from scratch";
            const r = await elicit({
              message: `Found ${valid.length} default template(s) matching "${name}". Use one to pre-populate description and recommendation?`,
              requestedSchema: {
                type: "object",
                properties: {
                  template: { type: "string", title: "Template", description: "Pick a template or 'None' to write from scratch", enum: [NONE, ...valid.map((t) => t.Name)] },
                } as never,
                required: ["template"],
              },
            });
            if (r.action === "accept" && r.content) {
              const choice = (r.content as Record<string, unknown>).template;
              if (typeof choice === "string" && choice !== NONE) {
                const picked = valid.find((t) => t.Name === choice);
                if (picked) vuln_template_id = picked.Id;
              }
            }
          }
        } catch { /* template search is best-effort; ignore failures */ }
      }

      // ----- STEP 3: Confirm impact/likelihood mirror severity (when severity was provided originally) -----
      if (supportsPrompt && severity !== undefined && (isBlank(impact) || isBlank(likelihood))) {
        const sevName = typeof severity === "string"
          ? severity
          : (await getMappedRiskLevels()).find((l) => l.id === severity)?.name ?? String(severity);
        const r = await elicit({
          message: `Severity is "${sevName}". Set impact and likelihood to the same level?`,
          requestedSchema: {
            type: "object",
            properties: {
              same_as_severity: { type: "boolean", title: `Use "${sevName}" for impact and likelihood`, default: true },
            } as never,
            required: ["same_as_severity"],
          },
        });
        const same = r.action === "accept" && (r.content as Record<string, unknown> | undefined)?.same_as_severity !== false;
        if (!same) {
          const levelNames = (await getMappedRiskLevels()).map((l) => l.name);
          const r2 = await elicit({
            message: "Set impact and likelihood",
            requestedSchema: {
              type: "object",
              properties: {
                impact: { type: "string", title: "Impact", enum: levelNames, default: sevName },
                likelihood: { type: "string", title: "Likelihood", enum: levelNames, default: sevName },
              } as never,
              required: ["impact", "likelihood"],
            },
          });
          if (r2.action === "accept" && r2.content) {
            const c = r2.content as Record<string, unknown>;
            if (typeof c.impact === "string") impact = c.impact;
            if (typeof c.likelihood === "string") likelihood = c.likelihood;
          }
        }
        // If "same" or no explicit values came back, leave impact/likelihood undefined and let the auto-default below set them to severity.
      }

      const sevId = await resolveRiskLevel(severity);
      const impId = impact !== undefined ? await resolveRiskLevel(impact) : sevId;
      const likeId = likelihood !== undefined ? await resolveRiskLevel(likelihood) : sevId;
      const body: Record<string, string | number | undefined> = {
        name,
        vulnTemplateId: vuln_template_id,
        description: description ? Buffer.from(sanitizeRichText(description)).toString("base64") : undefined,
        recommendation: recommendation ? Buffer.from(sanitizeRichText(recommendation)).toString("base64") : undefined,
        details: details ? Buffer.from(sanitizeRichText(details)).toString("base64") : undefined,
        categoryId: category_id,
        severity: sevId,
        impact: impId,
        likelihood: likeId,
        cvssScore: cvss_score,
        cvssString: cvss_string,
        section,
        customFields: custom_fields ? JSON.stringify(custom_fields) : undefined,
      };
      return ok(await factionPost(`/assessments/addVuln/${assessment_id}`, body));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "update_vulnerability",
  "Update an existing vulnerability by ID (assessor role required). Only provided fields are updated. Description, recommendation, and details support HTML/Markdown. Pass severity/impact/likelihood as the risk level NAME (e.g. 'Critical', 'High') — the server resolves the correct ID for this instance.",
  {
    vulnerability_id: z.number().int().describe("The vulnerability ID"),
    name: z.string().optional().describe("Vulnerability name"),
    description: z.string().optional().describe("Vulnerability description (HTML/Markdown supported)"),
    recommendation: z.string().optional().describe("Remediation recommendation (HTML/Markdown supported)"),
    details: z.string().optional().describe("Exploit details / proof of concept (HTML/Markdown supported)"),
    severity: z.union([z.string(), z.number().int()]).optional().describe("Overall severity. Pass the risk level NAME as a string (e.g. 'Critical', 'High'). Numeric IDs accepted but not recommended."),
    impact: z.union([z.string(), z.number().int()]).optional().describe("Impact risk level. Pass the NAME as a string. Only updated if explicitly provided."),
    likelihood: z.union([z.string(), z.number().int()]).optional().describe("Likelihood risk level. Pass the NAME as a string. Only updated if explicitly provided."),
    cvss_score: z.string().optional().describe("CVSS score (e.g. '7.5')"),
    cvss_string: z.string().optional().describe("CVSS vector string"),
    category_id: z.number().int().optional().describe("Vulnerability category ID"),
    section: z.string().optional().describe("Section (Enterprise feature)"),
    custom_fields: z.record(z.string(), z.string()).optional().describe("Custom field key-value pairs"),
  },
  async ({ vulnerability_id, name, description, recommendation, details, severity, impact, likelihood, cvss_score, cvss_string, category_id, section, custom_fields }) => {
    try {
      const body: Record<string, string | number | undefined> = {
        name,
        description: description ? Buffer.from(sanitizeRichText(description)).toString("base64") : undefined,
        recommendation: recommendation ? Buffer.from(sanitizeRichText(recommendation)).toString("base64") : undefined,
        details: details ? Buffer.from(sanitizeRichText(details)).toString("base64") : undefined,
        severity: await resolveRiskLevel(severity),
        impact: await resolveRiskLevel(impact),
        likelihood: await resolveRiskLevel(likelihood),
        cvssScore: cvss_score,
        cvssString: cvss_string,
        categoryId: category_id,
        section,
        customFields: custom_fields ? JSON.stringify(custom_fields) : undefined,
      };
      return ok(await factionPost(`/assessments/vuln/${vulnerability_id}`, body));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "add_templated_vulnerability",
  "Add a vulnerability to an assessment from a default template, auto-populating description and recommendation. Use search_vulnerability_templates to find a template first. Override ratings as needed (assessor role required). Pass severity/impact/likelihood as the risk level NAME (e.g. 'Critical', 'High') — the server resolves the correct ID for this instance. If only severity is provided, impact and likelihood automatically default to the same level.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    template_id: z.number().int().describe("The default vulnerability template ID"),
    name: z.string().describe("Vulnerability name"),
    details: z.string().optional().describe("Exploit details / proof of concept"),
    severity: z.union([z.string(), z.number().int()]).optional().describe("Override overall severity. Pass the risk level NAME as a string (e.g. 'Critical', 'High'). Numeric IDs accepted but not recommended."),
    impact: z.union([z.string(), z.number().int()]).optional().describe("Override impact risk level. Pass the NAME as a string. If omitted, defaults to the same level as severity."),
    likelihood: z.union([z.string(), z.number().int()]).optional().describe("Override likelihood risk level. Pass the NAME as a string. If omitted, defaults to the same level as severity."),
    cvss_score: z.string().optional().describe("CVSS score (e.g. '7.5')"),
    cvss_string: z.string().optional().describe("CVSS vector string"),
    section: z.string().optional().describe("Section (Enterprise feature)"),
    custom_fields: z.record(z.string(), z.string()).optional().describe("Custom field key-value pairs"),
  },
  async ({ assessment_id, template_id, name, details, severity, impact, likelihood, cvss_score, cvss_string, section, custom_fields }) => {
    try {
      const sevId = await resolveRiskLevel(severity);
      const impId = impact !== undefined ? await resolveRiskLevel(impact) : sevId;
      const likeId = likelihood !== undefined ? await resolveRiskLevel(likelihood) : sevId;
      const body: Record<string, string | number | undefined> = {
        name,
        details,
        severity: sevId,
        impact: impId,
        likelihood: likeId,
        cvssScore: cvss_score,
        cvssString: cvss_string,
        section,
        customFields: custom_fields ? JSON.stringify(custom_fields) : undefined,
      };
      return ok(await factionPost(`/assessments/addDefaultVuln/${assessment_id}/${template_id}`, body));
    } catch (e) { return err(e); }
  }
);

// ===========================================================================
// VULNERABILITIES
// ===========================================================================

server.tool(
  "get_vulnerabilities",
  "Get all vulnerabilities opened within a date range with full detail. Dates in MM/DD/YYYY format. Response can be very large — for general queries like 'show me all vulnerabilities for last month' or any stats/summary work, use get_vulnerabilities_condensed instead.",
  {
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().optional().describe("End date (MM/DD/YYYY). Defaults to now if omitted."),
  },
  async ({ start, end }) => {
    try {
      return ok(await factionPost("/vulnerabilities/all", { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerabilities_condensed",
  "Get all vulnerabilities opened within a date range with a condensed (shorter) payload — large text blocks (description, recommendation, details) are stripped out. Prefer this tool whenever the user just wants to see vulnerabilities for a date range, get counts/stats, or summarize findings. Dates in MM/DD/YYYY format.",
  {
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().optional().describe("End date (MM/DD/YYYY). Defaults to now if omitted."),
  },
  async ({ start, end }) => {
    try {
      return ok(await factionPost("/vulnerabilities/all/condensed", { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerability",
  "Get a vulnerability by its ID (requires remediation or manager role).",
  {
    vulnerability_id: z.number().int().describe("The vulnerability ID"),
  },
  async ({ vulnerability_id }) => {
    try {
      return ok(await factionGet(`/vulnerabilities/getvuln/${vulnerability_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerability_by_tracking",
  "Get a vulnerability by its tracking ID (e.g. a Jira ticket number).",
  {
    tracking_id: z.string().describe("The vulnerability tracking ID"),
  },
  async ({ tracking_id }) => {
    try {
      return ok(await factionGet(`/vulnerabilities/gettracking/${tracking_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "set_vulnerability_tracking",
  "Assign a tracking ID (e.g. Jira ticket) to a vulnerability.",
  {
    vulnerability_id: z.number().int().describe("The vulnerability ID"),
    tracking_id: z.string().describe("The tracking ID to assign (e.g. JIRA-1234)"),
  },
  async ({ vulnerability_id, tracking_id }) => {
    try {
      return ok(await factionPost("/vulnerabilities/settracking", {
        vulnId: vulnerability_id,
        trackingId: tracking_id,
      }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "set_vulnerability_status",
  "Set the remediation status of a vulnerability. Provide either vulnerability_id or tracking_id. Dates in MM/DD/YYYY format.",
  {
    vulnerability_id: z.number().int().optional().describe("The vulnerability ID"),
    tracking_id: z.string().optional().describe("The vulnerability tracking ID (alternative to vulnerability_id)"),
    is_closed_dev: z.boolean().optional().describe("Mark as fixed in development environment"),
    is_closed_prod: z.boolean().optional().describe("Mark as fixed in production environment"),
    dev_closed_date: z.string().optional().describe("Date fixed in dev (MM/DD/YYYY)"),
    prod_closed_date: z.string().optional().describe("Date fixed in prod (MM/DD/YYYY)"),
  },
  async ({ vulnerability_id, tracking_id, is_closed_dev, is_closed_prod, dev_closed_date, prod_closed_date }) => {
    try {
      return ok(await factionPost("/vulnerabilities/setstatus", {
        vulnId: vulnerability_id,
        trackingId: tracking_id,
        isClosedDev: is_closed_dev,
        isClosedProd: is_closed_prod,
        devClosedDate: dev_closed_date,
        prodClosedDate: prod_closed_date,
      }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_risk_levels",
  "Get the configured risk level definitions for this Faction instance. Unmapped slots (entries with no name) are filtered out — only meaningful, mapped risk levels are returned.",
  {},
  async () => {
    try {
      return ok(await getMappedRiskLevels());
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_categories",
  "Get all vulnerability categories.",
  {},
  async () => {
    try {
      return ok(await factionGet("/vulnerabilities/categories"));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_category",
  "Get a specific vulnerability category by ID.",
  {
    category_id: z.number().int().describe("The category ID"),
  },
  async ({ category_id }) => {
    try {
      return ok(await factionGet(`/vulnerabilities/category/${category_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "create_category",
  "Create a new vulnerability category (manager role required).",
  {
    name: z.string().describe("Category name"),
  },
  async ({ name }) => {
    try {
      return ok(await factionPost("/vulnerabilities/category", { name }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerability_templates",
  "Get all default vulnerability templates stored in the system.",
  {},
  async () => {
    try {
      return ok(await factionGet("/vulnerabilities/default"));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "search_vulnerability_templates",
  "Search default vulnerability templates by name (partial match).",
  {
    name: z.string().describe("Name or partial name to search for"),
  },
  async ({ name }) => {
    try {
      return ok(await factionGet(`/vulnerabilities/default/${encodeURIComponent(name)}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_vulnerability_template",
  "Get a specific default vulnerability template by ID.",
  {
    template_id: z.number().int().describe("The default vulnerability template ID"),
  },
  async ({ template_id }) => {
    try {
      return ok(await factionGet(`/vulnerabilities/default/getvuln/${template_id}`));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "create_vulnerability_templates",
  "Create or update default vulnerability templates. If id is provided, the existing template is updated. Category can be specified by id or name.",
  {
    templates: z.array(z.object({
      id: z.number().int().optional().describe("Existing template ID to update (omit to create new)"),
      name: z.string().describe("Vulnerability name"),
      category_id: z.number().int().optional().describe("Category ID"),
      category_name: z.string().optional().describe("Category name (used if category_id not provided)"),
      description: z.string().describe("Vulnerability description"),
      recommendation: z.string().describe("Remediation recommendation"),
      severity_id: z.number().int().optional().describe("Severity rating ID"),
      impact_id: z.number().int().optional().describe("Impact rating ID"),
      likelihood_id: z.number().int().optional().describe("Likelihood rating ID"),
      active: z.boolean().optional().describe("Whether the template is active"),
      cvss31_score: z.string().optional().describe("CVSS 3.1 score"),
      cvss31_string: z.string().optional().describe("CVSS 3.1 vector string"),
      cvss40_score: z.string().optional().describe("CVSS 4.0 score"),
      cvss40_string: z.string().optional().describe("CVSS 4.0 vector string"),
      custom_fields: z.array(z.object({
        key: z.string(),
        value: z.string(),
      })).optional().describe("Custom field values"),
    })).describe("List of templates to create or update"),
  },
  async ({ templates }) => {
    try {
      const payload = templates.map((t) => ({
        id: t.id,
        name: t.name,
        categoryId: t.category_id,
        categoryName: t.category_name,
        description: t.description,
        recommendation: t.recommendation,
        severityId: t.severity_id,
        impactId: t.impact_id,
        likelihoodId: t.likelihood_id,
        active: t.active,
        cvss31Score: t.cvss31_score,
        cvss31String: t.cvss31_string,
        cvss40Score: t.cvss40_score,
        cvss40String: t.cvss40_string,
        customFields: t.custom_fields,
      }));
      return ok(await factionPostJSON("/vulnerabilities/default", payload));
    } catch (e) { return err(e); }
  }
);

// ===========================================================================
// VERIFICATIONS / RETESTS
// ===========================================================================

server.tool(
  "get_verification_queue",
  "Get the retest/verification queue assigned to the authenticated user (assessor role required).",
  {},
  async () => {
    try {
      return ok(await factionGet("/verifications/queue"));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_all_verifications",
  "Get all verifications/retests in the system. Optionally filter completed verifications by date range. Dates in MM/DD/YYYY format. Requires remediation role.",
  {
    start: z.string().optional().describe("Start date for completed verifications filter (MM/DD/YYYY)"),
    end: z.string().optional().describe("End date for completed verifications filter (MM/DD/YYYY)"),
  },
  async ({ start, end }) => {
    try {
      return ok(await factionPost("/verifications/all", { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_user_verifications",
  "Get all verifications for a specific user by username. Optionally filter by date range. Requires remediation role.",
  {
    username: z.string().describe("The username to query verifications for"),
    start: z.string().optional().describe("Start date filter (MM/DD/YYYY)"),
    end: z.string().optional().describe("End date filter (MM/DD/YYYY)"),
  },
  async ({ username, start, end }) => {
    try {
      return ok(await factionPost("/verifications/userQueue", { username, start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "complete_verification",
  "Mark a retest/verification as passed or failed. Optionally close the vulnerability in dev or prod.",
  {
    verification_id: z.number().int().describe("The verification ID"),
    passed: z.boolean().describe("Whether the retest passed"),
    notes: z.string().optional().describe("Notes about the retest outcome"),
    close_in_prod: z.boolean().optional().describe("If passed, also close the finding in production"),
    completed_date: z.string().optional().describe("Date of completion (MM/DD/YYYY). Defaults to today."),
  },
  async ({ verification_id, passed, notes, close_in_prod, completed_date }) => {
    try {
      return ok(await factionPost("/verifications/passfail", {
        verificationID: verification_id,
        passed,
        notes,
        inProd: close_in_prod,
        completedDate: completed_date,
      }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "schedule_retest",
  "Schedule a retest/verification for a vulnerability. Identify the vulnerability by id or tracking_id. Dates in MM/DD/YYYY format. Requires remediation role.",
  {
    assessor_username: z.string().describe("Username of the assessor who will perform the retest"),
    remediation_username: z.string().describe("Username of the remediation contact"),
    vulnerability_id: z.number().int().optional().describe("The vulnerability ID to retest"),
    tracking_id: z.string().optional().describe("The vulnerability tracking ID (alternative to vulnerability_id)"),
    start: z.string().describe("Start date for the retest window (MM/DD/YYYY)"),
    end: z.string().describe("End date for the retest window (MM/DD/YYYY)"),
    notes: z.string().describe("Scope, credentials, and additional context for the assessor"),
  },
  async ({ assessor_username, remediation_username, vulnerability_id, tracking_id, start, end, notes }) => {
    try {
      return ok(await factionPost("/verifications/retest", {
        assessorId: assessor_username,
        remediationId: remediation_username,
        vulnId: vulnerability_id,
        trackingId: tracking_id,
        start,
        end,
        notes,
      }));
    } catch (e) { return err(e); }
  }
);

// ===========================================================================
// AUDIT LOG
// ===========================================================================

server.tool(
  "get_audit_log",
  "Get the system audit log for a date range (admin role required). Dates in MM/DD/YYYY format.",
  {
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().describe("End date (MM/DD/YYYY)"),
  },
  async ({ start, end }) => {
    try {
      return ok(await factionPost("/auditlog/log", { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment_audit_log",
  "Get audit log entries for all assessments within a date range (admin role required). Dates in MM/DD/YYYY format.",
  {
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().describe("End date (MM/DD/YYYY)"),
  },
  async ({ start, end }) => {
    try {
      return ok(await factionPost("/auditlog/assessmentlog", { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_assessment_audit_log_by_id",
  "Get audit log entries for a specific assessment within a date range (admin role required). Dates in MM/DD/YYYY format.",
  {
    assessment_id: z.number().int().describe("The assessment ID"),
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().describe("End date (MM/DD/YYYY)"),
  },
  async ({ assessment_id, start, end }) => {
    try {
      return ok(await factionPost(`/auditlog/assessmentlog/${assessment_id}`, { start, end }));
    } catch (e) { return err(e); }
  }
);

server.tool(
  "get_user_audit_log",
  "Get audit log entries for a specific user within a date range (admin role required). Dates in MM/DD/YYYY format.",
  {
    username: z.string().describe("The username to retrieve audit logs for"),
    start: z.string().describe("Start date (MM/DD/YYYY)"),
    end: z.string().describe("End date (MM/DD/YYYY)"),
  },
  async ({ username, start, end }) => {
    try {
      return ok(await factionPost("/auditlog/userlog", { username, start, end }));
    } catch (e) { return err(e); }
  }
);

// ===========================================================================
// Start
// ===========================================================================

const transport = new StdioServerTransport();
await server.connect(transport);
