import { describe, expect, it } from "vitest";

import { createLocalAgentRunApiToken, parseLocalAgentRunApiToken } from "./local-agent-run-token.js";

const JWT_SHAPED_VALUE_RE = /[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

describe("local agent run API tokens", () => {
  it("creates a non-JWT run-scoped API handle", () => {
    const runId = "123e4567-e89b-42d3-a456-426614174000";
    const token = createLocalAgentRunApiToken(runId);

    expect(token).toBe(`pcr_${runId}`);
    expect(token).not.toMatch(JWT_SHAPED_VALUE_RE);
    expect(parseLocalAgentRunApiToken(token)).toBe(runId);
  });

  it("rejects JWT-shaped values and non-UUID handles", () => {
    expect(parseLocalAgentRunApiToken("aaa.bbb.ccc")).toBeNull();
    expect(parseLocalAgentRunApiToken("pcr_run-123")).toBeNull();
    expect(parseLocalAgentRunApiToken("pcr_123e4567-e89b-62d3-a456-426614174000")).toBeNull();
  });
});
