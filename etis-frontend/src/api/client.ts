import type {
  AnalyzeRequest,
  AnalyzeResponse,
  ThreatsQueryParams,
  ThreatsResponse,
  StatsResponse,
} from './types';
import { ensureSession } from './session';

// An empty VITE_API_BASE_URL means "same origin" (the backend serves the
// built dashboard itself, ETIS_FRONTEND_DIST), so only a missing value falls
// back to the local dev server.
export const BASE_URL = import.meta.env.VITE_API_BASE_URL ?? 'http://localhost:8000';

/**
 * Authentication (2026-10-26): the dashboard no longer carries an API key.
 * VITE_ETIS_API_KEY put a shared secret inside the public JavaScript, where
 * anyone could read it. The browser now holds a signed HttpOnly session
 * cookie from POST /session (after a Turnstile bot check when enabled), sent
 * with `credentials: 'include'`. Per-client API keys are for programs such as
 * the Gmail extension, never for a public page. See api/session.ts and
 * backend/app/core/security.py.
 */

export class ApiError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown, message: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.body = body;
  }
}

function buildHeaders(hasJsonBody: boolean): HeadersInit {
  const headers: Record<string, string> = {};
  if (hasJsonBody) headers['Content-Type'] = 'application/json';
  return headers;
}

function isSessionRequired(status: number, body: unknown): boolean {
  return (
    status === 401 &&
    typeof body === 'object' &&
    body !== null &&
    (body as { error?: unknown }).error === 'SessionRequiredError'
  );
}

/**
 * Shared request handler. Error body shape confirmed from main.py's global
 * exception handler: { error: "<ExceptionClassName>", detail: "<message>" }
 * for any ETISException subclass (InvalidScanInputError -> 400,
 * BlacklistLookupError -> 502, EngineFailureError -> 500, anything else
 * unmapped -> 500). Uncaught non-ETISException errors would fall through
 * to FastAPI's default handler instead, which has a different shape
 * ({"detail": ...} with no "error" key) -- ApiError.body is left as
 * `unknown` rather than typed as EtisErrorResponse for that reason, but
 * EtisErrorResponse is exported from types.ts so callers can safely check
 * for it (e.g. `if (err.body && 'error' in err.body)`).
 */
async function request<TResponse>(
  path: string,
  options: RequestInit & { hasJsonBody?: boolean } = {},
  isRetry = false,
): Promise<TResponse> {
  const { hasJsonBody = false, ...init } = options;
  const url = `${BASE_URL}${path}`;

  let response: Response;
  try {
    response = await fetch(url, {
      ...init,
      credentials: 'include',
      headers: { ...buildHeaders(hasJsonBody), ...init.headers },
    });
  } catch (networkError) {
    throw new ApiError(
      0,
      networkError,
      `Network error reaching ${url} — is the backend running and is VITE_API_BASE_URL correct?`,
    );
  }

  const rawText = await response.text();
  const body = rawText ? safeJsonParse(rawText) : null;

  // Missing or expired session: start one (bot check included) and retry
  // once. A second 401 is shown to the user as "access refused".
  if (!isRetry && isSessionRequired(response.status, body)) {
    await ensureSession(BASE_URL, true);
    return request<TResponse>(path, options, true);
  }

  if (!response.ok) {
    throw new ApiError(
      response.status,
      body,
      `ETIS API ${response.status} on ${path}`,
    );
  }

  return body as TResponse;
}

function safeJsonParse(text: string): unknown {
  try {
    return JSON.parse(text);
  } catch {
    return text; // non-JSON error body (e.g. a plain-text 500) — don't crash on it
  }
}

function buildQueryString(params: object): string {
  const searchParams = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null) {
      searchParams.set(key, String(value));
    }
  }
  const query = searchParams.toString();
  return query ? `?${query}` : '';
}

// ---- Public API ----

export function analyzeScan(payload: AnalyzeRequest): Promise<AnalyzeResponse> {
  return request<AnalyzeResponse>('/analyze', {
    method: 'POST',
    body: JSON.stringify(payload),
    hasJsonBody: true,
  });
}

export function getThreats(params: ThreatsQueryParams = {}): Promise<ThreatsResponse> {
  return request<ThreatsResponse>(`/threats${buildQueryString(params)}`);
}

export function getStats(): Promise<StatsResponse> {
  return request<StatsResponse>('/stats');
}
