import { test } from "node:test";
import assert from "node:assert/strict";
import { checkBashExfil, SENSITIVE_PATH_RE, matchesSensitivePath } from "./security.js";

// A Go template field is not a credential path. `docker inspect --format
// "{{.Config.Env}}"` names a field on an object, not a `.env` file, and the
// command was blocked as "network discovery/transfer with sensitive material"
// because `\b` matched the `}` that closes the template.
test("Go template .Config.Env is not a sensitive path", () => {
  const cmd =
    `ssh host 'docker inspect app --format "{{range .Config.Env}}{{println .}}{{end}}" | grep -i x'`;
  assert.equal(
    checkBashExfil(cmd),
    undefined,
    "a Go template field must not read as a .env path"
  );
});

test("a real .env path beside an egress call is still blocked", () => {
  const cmd = "ssh host 'cat ~/.env | head -3'";
  assert.match(String(checkBashExfil(cmd)), /sensitive material/);
});

test("a real .env expansion beside an egress call is still blocked", () => {
  const cmd = "ssh host 'source .env; env'";
  assert.match(String(checkBashExfil(cmd)), /sensitive material|environment/);
});

test("SENSITIVE_PATH_RE still matches a plain .env reference", () => {
  assert.ok(SENSITIVE_PATH_RE.test("cat .env"));
  assert.ok(SENSITIVE_PATH_RE.test("cat ~/.env"));
  assert.ok(SENSITIVE_PATH_RE.test("grep x .env"));
  assert.ok(SENSITIVE_PATH_RE.test("cd /srv/app && cat .env"));
});

test("SENSITIVE_PATH_RE ignores Go template fields once templates are stripped", () => {
  // The regex alone cannot know about Go templates, so the guarded entry point
  // is matchesSensitivePath — that is the contract callers must use.
  assert.equal(matchesSensitivePath("{{.Config.Env}}"), false);
  assert.equal(matchesSensitivePath("--format {{.Config.Env}}"), false);
  assert.equal(matchesSensitivePath('{{range .Config.Env}}{{println .}}{{end}}'), false);
  // Stripping must not hide a real .env reference in the same command.
  assert.equal(matchesSensitivePath('docker inspect x --format "{{.Config.Env}}" && cat .env'), true);
});
