import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import fetch from "node-fetch";

const API_KEY = process.env.FACTION_API_KEY;
const BASE_URL = process.env.FACTION_BASE_URL?.replace(/\/$/, "");

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

async function factionPost(path: string, body: Record<string, string | number | boolean | undefined>): Promise<unknown> {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries(body)) {
    if (v !== undefined) params.set(k, String(v));
  }
  const res = await fetch(`${BASE_URL}/api${path}`, {
    method: "POST",
    headers: {
      "FACTION-API-KEY": API_KEY!,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: params.toString(),
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
// Server
// ---------------------------------------------------------------------------

const server = new McpServer({
  name: "faction",
  version: "1.0.0",
});

// ===========================================================================
// ASSESSMENTS
// ===========================================================================

server.tool(
  "get_assessment_queue",
  "Get the assessment queue for the authenticated user (assessor or manager role required).",
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

// ===========================================================================
// VULNERABILITIES
// ===========================================================================

server.tool(
  "get_vulnerabilities",
  "Get all vulnerabilities opened within a date range. Dates in MM/DD/YYYY format.",
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
  "Get the configured risk level definitions for this Faction instance.",
  {},
  async () => {
    try {
      return ok(await factionGet("/vulnerabilities/getrisklevels"));
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
      return ok(await factionPostJSON("/vulnerabilities/category", { name }));
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
