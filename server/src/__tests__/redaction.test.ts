import { describe, expect, it } from "vitest";
import { REDACTED_EVENT_VALUE, redactEventPayload, redactSensitiveText, sanitizeRecord } from "../redaction.js";

describe("redaction", () => {
  function syntheticSecret(prefixParts: string[], suffix = "abcdefghijklmnopqrstuvwx") {
    return `${prefixParts.join("")}${suffix}`;
  }

  it("redacts sensitive keys and nested secret values", () => {
    const input = {
      apiKey: "abc123",
      nested: {
        AUTH_TOKEN: "token-value",
        safe: "ok",
      },
      env: {
        OPENAI_API_KEY: syntheticSecret(["s", "k-"], "openai"),
        OPENAI_API_KEY_REF: {
          type: "secret_ref",
          secretId: "11111111-1111-1111-1111-111111111111",
        },
        OPENAI_API_KEY_PLAIN: {
          type: "plain",
          value: syntheticSecret(["s", "k-"], "plain"),
        },
        PAPERCLIP_API_URL: "http://localhost:3100",
      },
    };

    const result = sanitizeRecord(input);

    expect(result.apiKey).toBe(REDACTED_EVENT_VALUE);
    expect(result.nested).toEqual({
      AUTH_TOKEN: REDACTED_EVENT_VALUE,
      safe: "ok",
    });
    expect(result.env).toEqual({
      OPENAI_API_KEY: REDACTED_EVENT_VALUE,
      OPENAI_API_KEY_REF: {
        type: "secret_ref",
        secretId: "11111111-1111-1111-1111-111111111111",
      },
      OPENAI_API_KEY_PLAIN: {
        type: "plain",
        value: REDACTED_EVENT_VALUE,
      },
      PAPERCLIP_API_URL: "http://localhost:3100",
    });
  });

  it("redacts jwt-looking values even when key name is not sensitive", () => {
    const input = {
      session: "aaa.bbb.ccc",
      normal: "plain",
    };

    const result = sanitizeRecord(input);

    expect(result.session).toBe(REDACTED_EVENT_VALUE);
    expect(result.normal).toBe("plain");
  });

  it("redacts known secret-looking scalar values even when key names are safe", () => {
    const paperclipToken = syntheticSecret(["p", "cp_"]);
    const dashKey = syntheticSecret(["s", "k-"]);
    const underscoreKey = syntheticSecret(["s", "k_"]);
    const personalAccessToken = syntheticSecret(["p", "at_"]);
    const githubToken = syntheticSecret(["g", "hp_"]);
    const jwt = ["aaaabbbb", "ccccdddd", "eeeeffff"].join(".");
    const input = {
      env: {
        PAPERCLIP_API_URL: "http://localhost:3100",
        harmless: "visible",
        nestedToken: paperclipToken,
        plainBinding: { type: "plain", value: dashKey },
        values: [underscoreKey, "safe-array-value"],
      },
      metadata: {
        personalAccessToken,
        githubToken,
        jwt,
      },
    };

    const result = sanitizeRecord(input);
    const serialized = JSON.stringify(result);

    expect(result.env).toEqual({
      PAPERCLIP_API_URL: "http://localhost:3100",
      harmless: "visible",
      nestedToken: REDACTED_EVENT_VALUE,
      plainBinding: { type: "plain", value: REDACTED_EVENT_VALUE },
      values: [REDACTED_EVENT_VALUE, "safe-array-value"],
    });
    expect(result.metadata).toEqual({
      personalAccessToken: REDACTED_EVENT_VALUE,
      githubToken: REDACTED_EVENT_VALUE,
      jwt: REDACTED_EVENT_VALUE,
    });
    for (const secret of [paperclipToken, dashKey, underscoreKey, personalAccessToken, githubToken, jwt]) {
      expect(serialized).not.toContain(secret);
    }
  });

  it("redacts payload objects while preserving null", () => {
    expect(redactEventPayload(null)).toBeNull();
    expect(redactEventPayload({ password: "hunter2", safe: "value" })).toEqual({
      password: REDACTED_EVENT_VALUE,
      safe: "value",
    });
  });

  it("redacts common secret shapes from unstructured text", () => {
    const jwt = ["aaaabbbb", "ccccdddd", "eeeeffff"].join(".");
    const githubToken = syntheticSecret(["g", "hp_"], "1234567890abcdefghijklmnopqrstuvwxyz");
    const input = [
      "Authorization: Bearer live-bearer-token-value",
      `payload {"apiKey":"json-secret-value"}`,
      `paperclip {"PAPERCLIP_API_KEY":"paperclip-json-secret"}`,
      `escaped {\\"apiKey\\":\\"escaped-json-secret\\"}`,
      `export PAPERCLIP_API_KEY='paperclip-shell-secret'`,
      `GITHUB_TOKEN=${githubToken}`,
      `session=${jwt}`,
    ].join("\n");

    const result = redactSensitiveText(input);

    expect(result).toContain(REDACTED_EVENT_VALUE);
    expect(result).not.toContain("live-bearer-token-value");
    expect(result).not.toContain("json-secret-value");
    expect(result).not.toContain("paperclip-json-secret");
    expect(result).not.toContain("escaped-json-secret");
    expect(result).not.toContain("paperclip-shell-secret");
    expect(result).not.toContain(githubToken);
    expect(result).not.toContain(jwt);
  });

  it("redacts inline secrets from command metadata without hiding safe command text", () => {
    const commandToken = syntheticSecret(["g", "hp_"], "example_secret_value");
    const commandKey = syntheticSecret(["s", "k-"], "live-example-value");
    const argToken = syntheticSecret(["g", "hp_"], "arg_secret_value_value");
    const inlineKey = syntheticSecret(["s", "k-"], "inline-example-value");
    const input = {
      command: `custom-acp --token ${commandToken} env OPENAI_API_KEY=${commandKey} custom-acp`,
      commandArgs: ["--safe", "ok", "--token", argToken, `--api-key=${inlineKey}`],
      env: {
        PAPERCLIP_RESOLVED_COMMAND: `env OPENAI_API_KEY=${commandKey} custom-acp --token ${commandToken}`,
        SAFE_VALUE: "visible",
      },
    };

    const result = redactEventPayload(input);

    expect(result?.command).toBe(
      `custom-acp --token ${REDACTED_EVENT_VALUE} env OPENAI_API_KEY=${REDACTED_EVENT_VALUE} custom-acp`,
    );
    expect(result?.commandArgs).toEqual([
      "--safe",
      "ok",
      "--token",
      REDACTED_EVENT_VALUE,
      `--api-key=${REDACTED_EVENT_VALUE}`,
    ]);
    expect(result?.env).toEqual({
      PAPERCLIP_RESOLVED_COMMAND:
        `env OPENAI_API_KEY=${REDACTED_EVENT_VALUE} custom-acp --token ${REDACTED_EVENT_VALUE}`,
      SAFE_VALUE: "visible",
    });
  });

  it("redacts non-string command args after secret flags", () => {
    const result = redactEventPayload({
      commandArgs: ["--api-key", { nested: "secret-value" }, "safe-next"],
    });

    expect(result?.commandArgs).toEqual(["--api-key", REDACTED_EVENT_VALUE, "safe-next"]);
  });

  it("does not treat bare args payloads as command args", () => {
    const result = redactEventPayload({
      args: ["--api-key", "not-a-command-secret"],
      argv: ["--api-key", "command-secret"],
    });

    expect(result?.args).toEqual(["--api-key", "not-a-command-secret"]);
    expect(result?.argv).toEqual(["--api-key", REDACTED_EVENT_VALUE]);
  });
});
