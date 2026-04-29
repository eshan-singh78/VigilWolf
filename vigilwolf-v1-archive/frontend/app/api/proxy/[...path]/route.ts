import { NextRequest, NextResponse } from 'next/server';

const BACKEND_URL = process.env.BACKEND_URL || 'http://localhost:8000';
const API_KEY = process.env.API_KEY || '';
const PROXY_TIMEOUT_MS = 30_000;
const MAX_BODY_SIZE_BYTES = 10 * 1024 * 1024; // 10MB

// Allowlist of backend paths that can be proxied
const ALLOWED_PATHS = [
  /^health$/,
  /^config$/,
  /^whois$/,
  /^nrd-latest$/,
  /^brand-search$/,
  /^dump-nrd$/,
  /^monitoring\/groups$/,
  /^monitoring\/groups\/[^/]+$/,
  /^monitoring\/groups\/[^/]+\/domains$/,
  /^monitoring\/domains\/[^/]+\/force-dump$/,
  /^monitoring\/domains\/[^/]+\/snapshots$/,
  /^monitoring\/snapshots\/[^/]+$/,
  /^monitoring\/reset$/,
  /^metrics$/,
];

function isPathAllowed(path: string): boolean {
  return ALLOWED_PATHS.some((pattern) => pattern.test(path));
}

async function proxyRequest(
  request: NextRequest,
  context: { params: Promise<{ path: string[] }> }
): Promise<NextResponse> {
  try {
    const { path } = await context.params;
    const backendPath = path.join('/');

    // Enforce path allowlist
    if (!isPathAllowed(backendPath)) {
      return NextResponse.json(
        { error: 'Not found' },
        { status: 404 }
      );
    }

    // Build the backend URL preserving query parameters
    const url = new URL(`${BACKEND_URL}/${backendPath}`);
    request.nextUrl.searchParams.forEach((value, key) => {
      url.searchParams.set(key, value);
    });

    // Prepare headers
    const headers = new Headers();
    request.headers.forEach((value, key) => {
      const lowerKey = key.toLowerCase();
      // Skip host, connection, and client authorization headers
      if (lowerKey !== 'host' && lowerKey !== 'connection' && lowerKey !== 'authorization') {
        headers.set(key, value);
      }
    });

    // Add authorization server-side (never exposed to client)
    if (API_KEY) {
      headers.set('Authorization', `Bearer ${API_KEY}`);
    }

    // Preserve original client IP for backend rate limiting
    const clientIp = request.headers.get('x-forwarded-for') || request.headers.get('x-real-ip') || 'unknown';
    headers.set('X-Forwarded-For', clientIp);

    // Forward body for mutating methods with size limit
    let body: BodyInit | undefined;
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      const contentLength = request.headers.get('content-length');
      if (contentLength && parseInt(contentLength) > MAX_BODY_SIZE_BYTES) {
        return NextResponse.json(
          { error: 'Request body too large' },
          { status: 413 }
        );
      }

      const contentType = request.headers.get('content-type') || '';
      if (contentType.includes('application/json')) {
        body = await request.text();
      } else if (contentType.includes('multipart/form-data')) {
        body = await request.formData();
      } else {
        body = await request.blob();
      }
    }

    // AbortController for timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), PROXY_TIMEOUT_MS);

    try {
      const response = await fetch(url.toString(), {
        method: request.method,
        headers,
        body,
        redirect: 'manual',
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Build NextResponse preserving status and headers
      const responseHeaders = new Headers();
      response.headers.forEach((value, key) => {
        responseHeaders.set(key, value);
      });

      const responseBody = await response.blob();
      return new NextResponse(responseBody, {
        status: response.status,
        statusText: response.statusText,
        headers: responseHeaders,
      });
    } catch (fetchError) {
      clearTimeout(timeoutId);
      if ((fetchError as Error).name === 'AbortError') {
        return NextResponse.json(
          { error: 'Gateway timeout' },
          { status: 504 }
        );
      }
      throw fetchError;
    }
  } catch (error) {
    console.error('Proxy error:', error);
    return NextResponse.json(
      { error: 'Internal proxy error' },
      { status: 502 }
    );
  }
}

export const GET = proxyRequest;
export const POST = proxyRequest;
export const PUT = proxyRequest;
export const DELETE = proxyRequest;
export const PATCH = proxyRequest;
export const OPTIONS = proxyRequest;
