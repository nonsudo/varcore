import receiptSchema from "../public/var/v1/schema.json";

/**
 * schemas.nonsudo.com — Cloudflare Worker
 *
 * Endpoints:
 *   GET /.well-known/keys/<key_id>.json  — public key JWK for a key_id
 *   GET /var/v1/test-vectors.json        — VAR v1 conformance test vectors
 *   GET /var/v1/schema.json              — VAR v1 receipt schema (reserved)
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

function notFound(message: string): Response {
  return new Response(JSON.stringify({ error: message }), {
    status: 404,
    headers: {
      "Content-Type": "application/json",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

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
      const vectors = env["TEST_VECTORS_V1"];
      if (!vectors) {
        return new Response(JSON.stringify({ error: "Test vectors not available" }), {
          status: 503,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          },
        });
      }
      try {
        const parsed = JSON.parse(vectors) as unknown;
        return cachedJsonResponse(parsed, 3600);
      } catch {
        return notFound("Test vectors data malformed");
      }
    }

    // GET /var/v1/schema.json
    if (pathname === "/var/v1/schema.json") {
      return cachedJsonResponse(receiptSchema, 3600);
    }

    return new Response(JSON.stringify({ error: "Not found" }), {
      status: 404,
      headers: { "Content-Type": "application/json" },
    });
  },
} satisfies ExportedHandler<Env>;
