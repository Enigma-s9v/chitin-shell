/**
 * Shared HTTP Utilities for Chitin Shell Docker Services
 *
 * Zero dependencies — uses only Node.js built-in modules.
 * All three containers (agent, policy, proxy) share this code.
 */

import http from 'node:http';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface JsonRoute {
  method: 'GET' | 'POST';
  path: string;
  handler: (body: unknown, req: http.IncomingMessage) => Promise<RouteResponse>;
}

export interface RouteResponse {
  status: number;
  body: unknown;
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------

/**
 * Creates a simple JSON HTTP server.
 * No framework, no middleware — just route matching and JSON I/O.
 */
export function createJsonServer(
  port: number,
  routes: JsonRoute[],
  serviceName: string,
): http.Server {
  const server = http.createServer(async (req, res) => {
    // CORS preflight
    if (req.method === 'OPTIONS') {
      res.writeHead(204, corsHeaders());
      res.end();
      return;
    }

    const route = routes.find(
      (r) => r.method === req.method && r.path === req.url,
    );

    if (!route) {
      sendJson(res, 404, { error: 'Not Found', path: req.url });
      return;
    }

    try {
      const body = req.method === 'POST' ? await parseBody(req) : undefined;
      const result = await route.handler(body, req);
      sendJson(res, result.status, result.body);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`[${serviceName}] Error handling ${req.method} ${req.url}: ${message}`);
      sendJson(res, 500, { error: 'Internal Server Error', message });
    }
  });

  server.listen(port, '0.0.0.0', () => {
    console.log(`[${serviceName}] listening on 0.0.0.0:${port}`);
  });

  return server;
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/**
 * Simple HTTP JSON client using Node.js built-in http module.
 * Supports timeout and automatic JSON parsing.
 */
export function fetchJson<T = unknown>(
  url: string,
  body: unknown,
  timeoutMs = 30_000,
): Promise<{ status: number; data: T }> {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const payload = JSON.stringify(body);

    const options: http.RequestOptions = {
      hostname: parsed.hostname,
      port: parsed.port || 80,
      path: parsed.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
      },
      timeout: timeoutMs,
    };

    const req = http.request(options, (res) => {
      const chunks: Buffer[] = [];
      res.on('data', (chunk: Buffer) => chunks.push(chunk));
      res.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf-8');
        try {
          const data = JSON.parse(raw) as T;
          resolve({ status: res.statusCode ?? 500, data });
        } catch {
          reject(new Error(`Invalid JSON response from ${url}: ${raw.slice(0, 200)}`));
        }
      });
    });

    req.on('error', (err) => reject(err));
    req.on('timeout', () => {
      req.destroy();
      reject(new Error(`Request to ${url} timed out after ${timeoutMs}ms`));
    });

    req.write(payload);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Parse JSON request body from an IncomingMessage */
export function parseBody(req: http.IncomingMessage): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    const MAX_BODY = 1_048_576; // 1 MB

    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        req.destroy();
        reject(new Error('Request body too large (max 1 MB)'));
        return;
      }
      chunks.push(chunk);
    });

    req.on('end', () => {
      const raw = Buffer.concat(chunks).toString('utf-8');
      if (!raw) {
        resolve(undefined);
        return;
      }
      try {
        resolve(JSON.parse(raw));
      } catch {
        reject(new Error('Invalid JSON in request body'));
      }
    });

    req.on('error', reject);
  });
}

/** Standard health check handler */
export function healthHandler(
  serviceName: string,
  startedAt: string,
): JsonRoute {
  return {
    method: 'GET',
    path: '/health',
    handler: async () => ({
      status: 200,
      body: {
        service: serviceName,
        status: 'healthy',
        uptime_ms: Date.now() - new Date(startedAt).getTime(),
        started_at: startedAt,
      },
    }),
  };
}

function corsHeaders(): Record<string, string> {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  };
}

function sendJson(
  res: http.ServerResponse,
  status: number,
  body: unknown,
): void {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(payload),
    ...corsHeaders(),
  });
  res.end(payload);
}
