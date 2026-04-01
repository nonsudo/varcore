import receiptSchema from "../public/var/v1/schema.json";

/**
 * schemas.nonsudo.com — Cloudflare Worker
 *
 * Endpoints:
 *   GET /.well-known/keys/<key_id>.json  — public key JWK for a key_id
 *   GET /var/v1/test-vectors.json        — VAR v1 conformance test vectors
 *   GET /var/v1/conformance              — Alias for test vectors
 *   GET /var/v1/schema.json              — VAR v1 receipt schema
 *   GET /var/v1/receipt                  — Alias for receipt schema
 *   GET /var/v1/public-contract          — Public contract markdown
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

function testVectorsResponse(env: Env, maxAgeSeconds: number): Response {
  const vectors = env["TEST_VECTORS_V1"];
  if (!vectors) {
    return jsonErrorResponse("Test vectors not available", 503);
  }
  try {
    const parsed = JSON.parse(vectors) as unknown;
    return cachedJsonResponse(parsed, maxAgeSeconds);
  } catch {
    return notFound("Test vectors data malformed");
  }
}

function receiptSchemaResponse(maxAgeSeconds: number): Response {
  return cachedJsonResponse(receiptSchema, maxAgeSeconds);
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const pathname = url.pathname;

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
      return testVectorsResponse(env, 86400);
    }

    // GET /var/v1/conformance
    if (pathname === "/var/v1/conformance") {
      return withHeaders(testVectorsResponse(env, 86400), {
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
      // Populate with: wrangler secret put PUBLIC_CONTRACT_V1 < docs/public-contract.md
      const publicContract = env["PUBLIC_CONTRACT_V1"];
      if (!publicContract) {
        return jsonErrorResponse("public contract not yet deployed", 503);
      }
      return markdownResponse(publicContract, 3600);
    }

    return jsonErrorResponse("Not found", 404);
  },
} satisfies ExportedHandler<Env>;
