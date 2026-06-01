const LOCAL_AGENT_RUN_API_TOKEN_PREFIX = "pcr_";
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

export function createLocalAgentRunApiToken(runId: string): string {
  const trimmed = runId.trim();
  if (!trimmed) {
    throw new Error("runId is required to create a local agent run API token");
  }
  return `${LOCAL_AGENT_RUN_API_TOKEN_PREFIX}${trimmed}`;
}

export function parseLocalAgentRunApiToken(token: string): string | null {
  const trimmed = token.trim();
  if (!trimmed.startsWith(LOCAL_AGENT_RUN_API_TOKEN_PREFIX)) return null;
  const runId = trimmed.slice(LOCAL_AGENT_RUN_API_TOKEN_PREFIX.length);
  return UUID_RE.test(runId) ? runId : null;
}
