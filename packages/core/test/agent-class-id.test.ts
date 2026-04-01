import { strict as assert } from "node:assert";
import { test } from "node:test";
import { computeAgentClassId } from "../src/agent-class-id";

const BASE = {
  systemPrompt: "You are a payment assistant.",
  toolNames: ["stripe.createCharge", "stripe.createRefund"],
  modelId: "claude-sonnet-4-6",
};

test("deterministic — same inputs produce same output", () => {
  assert.equal(computeAgentClassId(BASE), computeAgentClassId(BASE));
});

test("output format — cls_ prefix and 32 lowercase hex chars", () => {
  assert.match(computeAgentClassId(BASE), /^cls_[0-9a-f]{32}$/);
});

test("tool array order does not affect output", () => {
  const reversed = { ...BASE, toolNames: [...BASE.toolNames].reverse() };
  assert.equal(computeAgentClassId(BASE), computeAgentClassId(reversed));
});

test("duplicate tool names are normalized", () => {
  const dupes = {
    ...BASE,
    toolNames: ["stripe.createCharge", "stripe.createCharge", "stripe.createRefund"],
  };
  assert.equal(computeAgentClassId(BASE), computeAgentClassId(dupes));
});

test("tool name whitespace is trimmed", () => {
  const padded = {
    ...BASE,
    toolNames: [" stripe.createCharge ", " stripe.createRefund "],
  };
  assert.equal(computeAgentClassId(BASE), computeAgentClassId(padded));
});

test("systemPrompt whitespace is trimmed", () => {
  const padded = { ...BASE, systemPrompt: "  You are a payment assistant.  " };
  assert.equal(computeAgentClassId(BASE), computeAgentClassId(padded));
});

test("modelId whitespace is trimmed", () => {
  const padded = { ...BASE, modelId: " claude-sonnet-4-6 " };
  assert.equal(computeAgentClassId(BASE), computeAgentClassId(padded));
});

test("different modelId produces different output", () => {
  assert.notEqual(
    computeAgentClassId(BASE),
    computeAgentClassId({ ...BASE, modelId: "claude-opus-4-6" })
  );
});

test("different systemPrompt produces different output", () => {
  assert.notEqual(
    computeAgentClassId(BASE),
    computeAgentClassId({ ...BASE, systemPrompt: "Different prompt." })
  );
});

test("different toolNames produces different output", () => {
  assert.notEqual(
    computeAgentClassId(BASE),
    computeAgentClassId({ ...BASE, toolNames: ["stripe.createCharge"] })
  );
});
