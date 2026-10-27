import { BotCheckError } from './turnstile';

/**
 * Dashboard session (backend/app/core/security.py). The browser holds a
 * signed HttpOnly cookie set by POST /session; this page never sees or stores
 * the token, and no API key is built into the JavaScript any more.
 *
 * ensureSession() is called once on load and again whenever an API call
 * comes back 401 SessionRequiredError (expired or missing cookie). Calls made
 * while a session is being started share the same promise, so the bot check
 * runs at most once at a time.
 *
 * The bot check itself is shown inside the page by components/BotCheck.tsx,
 * which registers itself here as the challenge handler: given the site key,
 * it draws the Turnstile box and resolves with the token once Cloudflare is
 * satisfied (often without a click).
 */

type ChallengeHandler = (siteKey: string) => Promise<string>;
let challengeHandler: ChallengeHandler | null = null;

export function registerChallengeHandler(handler: ChallengeHandler | null): void {
  challengeHandler = handler;
}

export interface SessionStatus {
  auth_required: boolean;
  turnstile_site_key: string | null;
  active: boolean;
  expires_at: number | null;
}

export class SessionStartError extends Error {
  readonly status: number;
  readonly body: unknown;

  constructor(status: number, body: unknown) {
    super(`Could not start a session (${status})`);
    this.name = 'SessionStartError';
    this.status = status;
    this.body = body;
  }
}

let pending: Promise<void> | null = null;

async function readJson(response: Response): Promise<unknown> {
  const text = await response.text();
  try {
    return text ? JSON.parse(text) : null;
  } catch {
    return text;
  }
}

async function startSession(baseUrl: string, force: boolean): Promise<void> {
  const statusResponse = await fetch(`${baseUrl}/session`, { credentials: 'include' });
  if (!statusResponse.ok) throw new SessionStartError(statusResponse.status, await readJson(statusResponse));
  const status = (await statusResponse.json()) as SessionStatus;
  if (!status.auth_required || (status.active && !force)) return;

  let turnstileToken: string | undefined;
  if (status.turnstile_site_key) {
    if (!challengeHandler) throw new BotCheckError('No bot check component is mounted');
    turnstileToken = await challengeHandler(status.turnstile_site_key);
  }

  const response = await fetch(`${baseUrl}/session`, {
    method: 'POST',
    credentials: 'include',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ turnstile_token: turnstileToken }),
  });
  if (!response.ok) throw new SessionStartError(response.status, await readJson(response));
}

/** `force` starts a new session even if GET /session says one is active
 * (used after a 401, when the cookie the browser holds was just refused). */
export function ensureSession(baseUrl: string, force = false): Promise<void> {
  if (!pending) {
    pending = startSession(baseUrl, force).finally(() => {
      pending = null;
    });
  }
  return pending;
}
