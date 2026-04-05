import receiptSchema from "../public/var/v1/schema.json";
import testVectorsData from "../public/var/v1/test-vectors.json";
import policySchema from "../../docs/reference/policy-schema.json";
import publicContractData from "../../docs/reference/contract.md";
import varCoreSpec from "../../docs/spec/var-core-v1.0.md";
import varMoneySpec from "../../docs/spec/var-money-v1.0.md";

/**
 * schemas.nonsudo.com — Cloudflare Worker
 *
 * Endpoints:
 *   GET /                                — homepage with service info
 *   GET /.well-known/keys/<key_id>.json  — public key JWK for a key_id
 *   GET /var/v1/test-vectors.json        — VAR v1 conformance test vectors
 *   GET /var/v1/conformance              — Alias for test vectors
 *   GET /var/v1/schema.json              — VAR v1 receipt schema
 *   GET /var/v1/receipt                  — Alias for receipt schema
 *   GET /var/v1/public-contract          — Public contract markdown
 *   GET /var/v1/spec                     — Alias for VAR Core v1.0 spec
 *   GET /var/v1.0/spec.md               — VAR Core v1.0 spec markdown
 *   GET /var/v1.0/policy-schema.json     — Policy config JSON Schema
 *   GET /var-money/v1.0/spec.md          — VAR-Money v1.0 spec markdown
 *   GET /var-money/v1.0/taxonomy.json    — (coming soon)
 *   GET /health                          — health check
 *
 * Public keys are stored as Cloudflare secrets (environment bindings), never
 * committed. The secret name convention is: KEY_<KEY_ID_UPPER_SNAKE>
 * e.g. key_id "ns-prod-01" → secret name "KEY_NS_PROD_01"
 *
 * Zero npm runtime dependencies.
 */

export interface Env {
  // Key JWKs stored as Cloudflare secrets.
  // Format: KEY_<KEY_ID with - replaced by _> e.g. KEY_NS_PROD_01
  [key: string]: string | undefined;
}

function keySecretName(keyId: string): string {
  // "ns-prod-01" → "KEY_NS_PROD_01"
  return "KEY_" + keyId.toUpperCase().replace(/-/g, "_");
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "public, max-age=31536000, immutable", // keys are immutable
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function cachedJsonResponse(body: unknown, maxAgeSeconds: number, status = 200): Response {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": `public, max-age=${maxAgeSeconds}`,
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function jsonErrorResponse(message: string, status: number): Response {
  return new Response(JSON.stringify({ error: message }), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function markdownResponse(body: string, maxAgeSeconds: number, status = 200): Response {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/markdown",
      "Cache-Control": `public, max-age=${maxAgeSeconds}`,
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function withHeaders(response: Response, headers: Record<string, string>): Response {
  const nextHeaders = new Headers(response.headers);
  for (const [key, value] of Object.entries(headers)) {
    nextHeaders.set(key, value);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: nextHeaders,
  });
}

function redirectResponse(location: string): Response {
  return new Response(null, {
    status: 301,
    headers: {
      Location: location,
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function notFound(message: string): Response {
  return jsonErrorResponse(message, 404);
}

function testVectorsResponse(maxAgeSeconds: number): Response {
  return cachedJsonResponse(testVectorsData, maxAgeSeconds);
}

function receiptSchemaResponse(maxAgeSeconds: number): Response {
  return cachedJsonResponse(receiptSchema, maxAgeSeconds);
}

function homepageResponse(): Response {
  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>schemas.nonsudo.com — VAR Core Public Schema Server</title>
  <style>
    body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; color: #1a1a1a; }
    h1 { font-size: 1.4rem; }
    h2 { font-size: 1.1rem; margin-top: 2rem; }
    a { color: #0057b7; }
    pre { background: #f5f5f5; padding: 1rem; overflow-x: auto; border-radius: 4px; font-size: 0.85rem; }
    code { font-family: "SF Mono", Menlo, monospace; }
    ul { padding-left: 1.2rem; }
    li { margin: 0.3rem 0; }
  </style>
</head>
<body>
  <h1>schemas.nonsudo.com</h1>
  <p>Public schema server for <strong>VAR Core v1.0</strong> — the Verified Agent Receipts protocol by NonSudo.</p>

  <h2>Endpoints</h2>
  <ul>
    <li><a href="/var/v1/schema.json">/var/v1/schema.json</a> — Receipt JSON Schema</li>
    <li><a href="/var/v1.0/spec.md">/var/v1.0/spec.md</a> — VAR Core v1.0 Specification</li>
    <li><a href="/var/v1.0/policy-schema.json">/var/v1.0/policy-schema.json</a> — Policy Config JSON Schema</li>
    <li><a href="/var/v1/conformance">/var/v1/conformance</a> — Conformance Test Vectors</li>
    <li><a href="/var/v1/public-contract">/var/v1/public-contract</a> — Public Contract</li>
    <li><a href="/var-money/v1.0/spec.md">/var-money/v1.0/spec.md</a> — VAR-Money v1.0 Specification</li>
    <li><a href="/health">/health</a> — Health Check</li>
  </ul>

  <h2>Sample Receipt</h2>
  <pre><code>{
  "receipt_id": "01HXYZ...",
  "record_type": "action_receipt",
  "spec_version": "var/1.0",
  "workflow_id": "01HABC...",
  "agent_id": "agent-demo-01",
  "tool_name": "stripe_create_refund",
  "params_canonical_hash": "sha256:e3b0c44...",
  "decision": "ALLOW",
  "decision_reason": "ALLOW — below spend ceiling",
  "decision_order": 1,
  "blast_radius": "HIGH",
  "reversible": false,
  "sequence_number": 1847,
  "prev_receipt_hash": "sha256:abc123...",
  "policy_bundle_hash": "sha256:abc123...",
  "response_hash": null,
  "rfc3161_token": null,
  "issued_at": "2026-03-15T14:32:01.000Z",
  "signature": {
    "alg": "Ed25519",
    "key_id": "ns-prod-01",
    "sig": "3Yv7..."
  }
}</code></pre>

  <p>Verify offline: <code>nonsudo verify chain.ndjson --key ns-prod-01</code></p>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "public, max-age=3600",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

    // Homepage
    if (pathname === "/" || pathname === "") {
      return homepageResponse();
    }

    if (pathname === "/v1/receipt") {
      return redirectResponse("/var/v1/receipt");
    }
    if (pathname === "/v1/conformance") {
      return redirectResponse("/var/v1/conformance");
    }
    if (pathname === "/v1/public-contract") {
      return redirectResponse("/var/v1/public-contract");
    }

    // Health check
    if (pathname === "/health") {
      return jsonResponse({ status: "ok", service: "schemas.nonsudo.com" });
    }

    // GET /.well-known/keys/<key_id>.json
    const keyMatch = pathname.match(/^\/.well-known\/keys\/(.+)\.json$/);
    if (keyMatch) {
      const keyId = decodeURIComponent(keyMatch[1]);
      const secretName = keySecretName(keyId);
      const jwkStr = env[secretName];
      if (!jwkStr) {
        return notFound(`Key not found: ${keyId}`);
      }
      // Parse and re-serialize to ensure valid JSON
      try {
        const jwk = JSON.parse(jwkStr) as unknown;
        return jsonResponse(jwk);
      } catch {
        return notFound(`Key data malformed for: ${keyId}`);
      }
    }

    // GET /var/v1/test-vectors.json
    if (pathname === "/var/v1/test-vectors.json") {
      return testVectorsResponse(86400);
    }

    // GET /var/v1/conformance
    if (pathname === "/var/v1/conformance") {
      return withHeaders(testVectorsResponse(86400), {
        Link: "<https://schemas.nonsudo.com/var/v1/test-vectors.json>; rel=\"canonical\"",
      });
    }

    // GET /var/v1/schema.json
    if (pathname === "/var/v1/schema.json") {
      return receiptSchemaResponse(3600);
    }

    // GET /var/v1/receipt
    if (pathname === "/var/v1/receipt") {
      return withHeaders(receiptSchemaResponse(3600), {
        Link: "<https://schemas.nonsudo.com/var/v1/schema.json>; rel=\"canonical\"",
      });
    }

    // GET /var/v1/public-contract
    if (pathname === "/var/v1/public-contract") {
      return markdownResponse(publicContractData, 3600);
    }

    // GET /var/v1.0/spec.md — VAR Core v1.0 spec
    if (pathname === "/var/v1.0/spec.md") {
      return markdownResponse(varCoreSpec, 3600);
    }

    // GET /var/v1/spec — clean alias for the spec
    if (pathname === "/var/v1/spec") {
      return withHeaders(markdownResponse(varCoreSpec, 3600), {
        Link: "<https://schemas.nonsudo.com/var/v1.0/spec.md>; rel=\"canonical\"",
      });
    }

    // GET /var/v1.0/policy-schema.json
    if (pathname === "/var/v1.0/policy-schema.json") {
      return cachedJsonResponse(policySchema, 3600);
    }

    // GET /var-money/v1.0/spec.md — VAR-Money v1.0 spec
    if (pathname === "/var-money/v1.0/spec.md") {
      return markdownResponse(varMoneySpec, 3600);
    }

    // GET /var-money/v1.0/taxonomy.json — placeholder
    if (pathname === "/var-money/v1.0/taxonomy.json") {
      return jsonErrorResponse("VAR-Money taxonomy endpoint coming soon", 404);
    }

    return jsonErrorResponse("Not found", 404);
  },
} satisfies ExportedHandler<Env>;
