#!/usr/bin/env tsx

import { Buffer } from "node:buffer";
import { mkdir, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { fileURLToPath } from "node:url";

type CheckStatus = "pass" | "fail" | "warning";

type CheckResult = {
  id: string;
  title: string;
  status: CheckStatus;
  message: string;
};

type SarifResult = {
  ruleId: string;
  level: "error" | "warning" | "note";
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
      region: { startLine: number };
    };
  }>;
};

type GitHubGetResult =
  | { ok: true; body: Record<string, unknown> }
  | { ok: false; message: string; status: number; degraded: boolean };

type GitHubGetOptionalResult =
  | { ok: true; body: Record<string, unknown> | null }
  | { ok: false; message: string; status: number; degraded: boolean };
type GitHubGetFailure = Extract<
  GitHubGetResult | GitHubGetOptionalResult,
  { ok: false }
>;
type GitHubGetOptions = {
  authToken?: string;
  degradeStatuses?: number[];
  tokenLabel?: string;
};

const owner = process.env.GITHUB_REPOSITORY_OWNER;
const repository = process.env.GITHUB_REPOSITORY;
const token = process.env.GH_TOKEN ?? process.env.GITHUB_TOKEN;
const baselineAdminToken = process.env.GHA_BASELINE_ADMIN_TOKEN;
const apiUrl = process.env.GITHUB_API_URL ?? "https://api.github.com";
const outputSarif =
  process.env.GHA_BASELINE_SARIF ?? "gha-baseline-check.sarif";
const outputJson = process.env.GHA_BASELINE_JSON ?? "gha-baseline-check.json";
const adminEnforcement = process.env.GHA_BASELINE_ADMIN_ENFORCEMENT === "true";
const productionReviewerException =
  process.env.GHA_BASELINE_R14_EXCEPTION?.trim();
const githubEventName = process.env.GITHUB_EVENT_NAME;
const githubSha = process.env.GITHUB_SHA;

if (!owner || !repository) {
  throw new Error("GITHUB_REPOSITORY_OWNER and GITHUB_REPOSITORY are required");
}

const repoName = repository.split("/")[1];
if (!repoName) {
  throw new Error(`GITHUB_REPOSITORY must be owner/name, got ${repository}`);
}

const mockPayload = process.env.GHA_BASELINE_MOCK_JSON
  ? (JSON.parse(process.env.GHA_BASELINE_MOCK_JSON) as Record<string, unknown>)
  : null;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function getRecord(value: unknown, label: string): Record<string, unknown> {
  if (!isRecord(value)) throw new Error(`${label} response was not an object`);
  return value;
}

function apiFailure(
  path: string,
  status: number,
  statusText: string,
  degraded: boolean,
): GitHubGetFailure {
  return {
    ok: false,
    message: `GET ${path} failed: ${status} ${statusText}`,
    status,
    degraded,
  };
}

function missingTokenFor(path: string, tokenLabel: string): GitHubGetResult {
  return {
    ok: false,
    message: `GET ${path} failed: ${tokenLabel} is required`,
    status: 0,
    degraded: false,
  };
}

async function githubGet(
  path: string,
  options: GitHubGetOptions = {},
): Promise<GitHubGetResult> {
  const requestToken = options.authToken ?? token;
  const tokenLabel = options.tokenLabel ?? "GH_TOKEN or GITHUB_TOKEN";
  const degradeStatuses = options.degradeStatuses ?? [];

  if (mockPayload) {
    const value = mockPayload[path];
    if (!value) throw new Error(`mock payload missing ${path}`);
    return { ok: true, body: getRecord(value, path) };
  }

  if (!requestToken) return missingTokenFor(path, tokenLabel);

  const response = await fetch(`${apiUrl}${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${requestToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (!response.ok) {
    return apiFailure(
      path,
      response.status,
      response.statusText,
      degradeStatuses.includes(response.status),
    );
  }

  return { ok: true, body: getRecord(await response.json(), path) };
}

async function githubGetOrNull(
  path: string,
  options: GitHubGetOptions = {},
): Promise<GitHubGetOptionalResult> {
  const requestToken = options.authToken ?? token;
  const tokenLabel = options.tokenLabel ?? "GH_TOKEN or GITHUB_TOKEN";
  const degradeStatuses = options.degradeStatuses ?? [404];

  if (mockPayload) {
    if (!Object.hasOwn(mockPayload, path))
      throw new Error(`mock payload missing ${path}`);
    const value = mockPayload[path];
    return { ok: true, body: value === null ? null : getRecord(value, path) };
  }

  if (!requestToken) return missingTokenFor(path, tokenLabel);

  const response = await fetch(`${apiUrl}${path}`, {
    headers: {
      Accept: "application/vnd.github+json",
      Authorization: `Bearer ${requestToken}`,
      "X-GitHub-Api-Version": "2022-11-28",
    },
  });

  if (response.status === 404)
    return { ok: true, body: null };
  if (!response.ok) {
    return apiFailure(
      path,
      response.status,
      response.statusText,
      degradeStatuses.includes(response.status),
    );
  }

  return { ok: true, body: getRecord(await response.json(), path) };
}

function result(
  id: string,
  title: string,
  status: CheckStatus,
  message: string,
): CheckResult {
  return { id, title, status, message };
}

function adminPermissionStatus(apiResult: GitHubGetFailure): CheckStatus {
  return apiResult.status === 403 && apiResult.degraded && !adminEnforcement
    ? "warning"
    : "fail";
}

function adminPermissionMessage(
  apiResult: GitHubGetFailure,
  ruleIds: string,
): string {
  return apiResult.status === 403 && apiResult.degraded && !adminEnforcement
    ? `could not verify ${ruleIds}: token lacks administration:read on this event`
    : apiResult.message;
}

function stringValue(
  record: Record<string, unknown>,
  key: string,
): string | null {
  const value = record[key];
  return typeof value === "string" ? value : null;
}

function booleanValue(
  record: Record<string, unknown>,
  key: string,
): boolean | null {
  const value = record[key];
  return typeof value === "boolean" ? value : null;
}

function decodeContent(record: Record<string, unknown>): string | null {
  const content = stringValue(record, "content");
  const encoding = stringValue(record, "encoding");
  if (!content || encoding !== "base64") return null;
  return Buffer.from(content.replaceAll("\n", ""), "base64").toString("utf8");
}

function codeownersCoversWorkflows(codeowners: string): boolean {
  return codeowners
    .split("\n")
    .map((line) => line.replace(/#.*/, "").trim())
    .filter(Boolean)
    .some((line) => {
      const [pattern, ...owners] = line.split(/\s+/);
      if (!pattern || owners.length === 0) return false;
      const normalized = pattern.startsWith("/") ? pattern.slice(1) : pattern;
      return (
        normalized === ".github/" ||
        normalized === ".github/*" ||
        normalized === ".github/**" ||
        normalized === ".github/workflows/" ||
        normalized === ".github/workflows/*" ||
        normalized === ".github/workflows/**"
      );
    });
}

function contentsRefQuery(): string {
  return githubEventName === "pull_request" && githubSha
    ? `?ref=${encodeURIComponent(githubSha)}`
    : "";
}

function requiredReviewerRuleExists(
  environment: Record<string, unknown>,
): boolean {
  const rules = environment.protection_rules;
  if (!Array.isArray(rules)) return false;

  return rules.some((rule) => {
    if (!isRecord(rule)) return false;
    const type = stringValue(rule, "type");
    const reviewers = rule.reviewers;
    return (
      type === "required_reviewers" &&
      Array.isArray(reviewers) &&
      reviewers.length > 0
    );
  });
}

async function run(): Promise<CheckResult[]> {
  const workflowPermissionsPath = `/repos/${owner}/${repoName}/actions/permissions/workflow`;
  const actionsPermissionsPath = `/repos/${owner}/${repoName}/actions/permissions`;
  const productionEnvironmentPath = `/repos/${owner}/${repoName}/environments/Production`;
  const codeownersPath = `/repos/${owner}/${repoName}/contents/.github/CODEOWNERS${contentsRefQuery()}`;
  const adminApiToken = adminEnforcement ? baselineAdminToken : token;
  const adminGetOptions = {
    authToken: adminApiToken,
    tokenLabel: adminEnforcement
      ? "GHA_BASELINE_ADMIN_TOKEN"
      : "GH_TOKEN or GITHUB_TOKEN",
  };

  const [
    workflowPermissions,
    actionsPermissions,
    productionEnvironment,
    codeownersResponse,
  ] = await Promise.all([
    githubGet(workflowPermissionsPath, {
      ...adminGetOptions,
      degradeStatuses: [404, 403],
    }),
    githubGet(actionsPermissionsPath, {
      ...adminGetOptions,
      degradeStatuses: [404, 403],
    }),
    githubGetOrNull(productionEnvironmentPath, {
      ...adminGetOptions,
      degradeStatuses: [403],
    }),
    githubGetOrNull(codeownersPath),
  ]);

  const checks: CheckResult[] = [];

  if (workflowPermissions.ok) {
    checks.push(
      result(
        "R1",
        "Default workflow token is read-only",
        stringValue(
          workflowPermissions.body,
          "default_workflow_permissions",
        ) === "read"
          ? "pass"
          : "fail",
        `default_workflow_permissions=${String(
          workflowPermissions.body.default_workflow_permissions,
        )}`,
      ),
    );

    checks.push(
      result(
        "R3",
        "GitHub Actions cannot approve pull request reviews",
        booleanValue(
          workflowPermissions.body,
          "can_approve_pull_request_reviews",
        ) === false
          ? "pass"
          : "fail",
        `can_approve_pull_request_reviews=${String(
          workflowPermissions.body.can_approve_pull_request_reviews,
        )}`,
      ),
    );
  } else {
    checks.push(
      result(
        "R1",
        "Default workflow token is read-only",
        adminPermissionStatus(workflowPermissions),
        adminPermissionMessage(workflowPermissions, "R1/R3"),
      ),
      result(
        "R3",
        "GitHub Actions cannot approve pull request reviews",
        adminPermissionStatus(workflowPermissions),
        adminPermissionMessage(workflowPermissions, "R1/R3"),
      ),
    );
  }

  if (actionsPermissions.ok) {
    checks.push(
      result(
        "R5",
        "Allowed actions is restricted",
        stringValue(actionsPermissions.body, "allowed_actions") !== "all"
          ? "pass"
          : "fail",
        `allowed_actions=${String(actionsPermissions.body.allowed_actions)}`,
      ),
    );

    checks.push(
      result(
        "R6",
        "SHA pinning is required by repository settings",
        booleanValue(actionsPermissions.body, "sha_pinning_required") === true
          ? "pass"
          : "fail",
        `sha_pinning_required=${String(actionsPermissions.body.sha_pinning_required)}`,
      ),
    );
  } else {
    checks.push(
      result(
        "R5",
        "Allowed actions is restricted",
        adminPermissionStatus(actionsPermissions),
        adminPermissionMessage(actionsPermissions, "R5/R6"),
      ),
      result(
        "R6",
        "SHA pinning is required by repository settings",
        adminPermissionStatus(actionsPermissions),
        adminPermissionMessage(actionsPermissions, "R5/R6"),
      ),
    );
  }

  if (productionEnvironment.ok) {
    const environment = productionEnvironment.body;
    const hasRequiredReviewer =
      environment !== null && requiredReviewerRuleExists(environment);
    checks.push(
      result(
        "R13",
        "Production environment exists",
        environment && stringValue(environment, "name") === "Production"
          ? "pass"
          : "fail",
        environment
          ? `environment=${String(environment.name)}`
          : "Production environment not found",
      ),
    );

    checks.push(
      result(
        "R14",
        "Production environment has required reviewers",
        hasRequiredReviewer
          ? "pass"
          : productionReviewerException
            ? "warning"
            : "fail",
        hasRequiredReviewer
          ? "required_reviewers protection rule contains at least one reviewer"
          : productionReviewerException
            ? `documented exception: ${productionReviewerException}`
            : environment
              ? "required_reviewers protection rule must contain at least one reviewer"
              : "Production environment not found",
      ),
    );
  } else {
    checks.push(
      result(
        "R13",
        "Production environment exists",
        adminPermissionStatus(productionEnvironment),
        adminPermissionMessage(productionEnvironment, "R13/R14"),
      ),
      result(
        "R14",
        "Production environment has required reviewers",
        adminPermissionStatus(productionEnvironment),
        adminPermissionMessage(productionEnvironment, "R13/R14"),
      ),
    );
  }

  const codeowners = codeownersResponse.ok
    ? codeownersResponse.body
      ? decodeContent(codeownersResponse.body)
      : null
    : null;
  checks.push(
    result(
      "R15",
      "CODEOWNERS covers GitHub Actions workflows",
      codeowners && codeownersCoversWorkflows(codeowners) ? "pass" : "fail",
      codeownersResponse.ok
        ? ".github/CODEOWNERS must include an owner rule for .github/workflows/"
        : codeownersResponse.message,
    ),
  );

  const expectedBaselineSha = process.env.EXPECTED_GBRAIN_BASELINE_SHA;
  const currentBaselineSha = process.env.CURRENT_GBRAIN_BASELINE_SHA;
  if (expectedBaselineSha && currentBaselineSha) {
    checks.push(
      result(
        "R28",
        "GBrain baseline page SHA matches the expected SHA",
        expectedBaselineSha === currentBaselineSha ? "pass" : "fail",
        `expected=${expectedBaselineSha} current=${currentBaselineSha}`,
      ),
    );
  } else {
    checks.push(
      result(
        "R28",
        "GBrain baseline page SHA comparison is configured",
        "warning",
        "AIVA-1670 sub-issues still open: EXPECTED_GBRAIN_BASELINE_SHA and CURRENT_GBRAIN_BASELINE_SHA are not both set",
      ),
    );
  }

  return checks;
}

function toSarif(checks: CheckResult[]): Record<string, unknown> {
  const rules = checks.map((check) => ({
    id: check.id,
    name: check.title,
    shortDescription: { text: check.title },
    help: { text: check.message },
  }));

  const results: SarifResult[] = checks
    .filter((check) => check.status !== "pass")
    .map((check) => ({
      ruleId: check.id,
      level: check.status === "fail" ? "error" : "warning",
      message: { text: `${check.title}: ${check.message}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: {
              uri: ".github/workflows/gha-baseline-audit.yml",
            },
            region: { startLine: 1 },
          },
        },
      ],
    }));

  return {
    version: "2.1.0",
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    runs: [
      {
        tool: {
          driver: {
            name: "gha-baseline-check",
            informationUri: `https://github.com/${repository}`,
            rules,
          },
        },
        results,
      },
    ],
  };
}

async function writeJson(path: string, value: unknown): Promise<void> {
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, `${JSON.stringify(value, null, 2)}\n`);
}

async function main(): Promise<void> {
  const checks = await run();
  const failed = checks.filter((check) => check.status === "fail");

  await writeJson(outputJson, {
    ok: failed.length === 0,
    checks,
  });
  await writeJson(outputSarif, toSarif(checks));

  for (const check of checks) {
    const prefix =
      check.status === "pass"
        ? "PASS"
        : check.status === "warning"
          ? "WARN"
          : "FAIL";
    console.log(`${prefix} ${check.id}: ${check.title} — ${check.message}`);
  }

  if (failed.length > 0) {
    process.exitCode = 1;
  }
}

if (process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1]) {
  void main();
}

export { run, toSarif };
