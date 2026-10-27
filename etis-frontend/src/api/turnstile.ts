/**
 * Cloudflare Turnstile script loader and types. The widget itself is drawn
 * inside the page by components/BotCheck.tsx, like the "Verify you are
 * human" box on ordinary sign-in forms. The site key is public by design;
 * the secret half stays on the server, which verifies the token
 * (backend/app/core/turnstile.py).
 */

export interface TurnstileRenderOptions {
  sitekey: string;
  action: string;
  language: string;
  theme: 'light' | 'dark' | 'auto';
  size: 'normal' | 'flexible' | 'compact';
  appearance: 'always' | 'execute' | 'interaction-only';
  callback: (token: string) => void;
  'error-callback': () => void;
  'timeout-callback': () => void;
  'expired-callback': () => void;
}

export interface TurnstileApi {
  render: (container: HTMLElement, options: TurnstileRenderOptions) => string;
  reset: (widgetId: string) => void;
  remove: (widgetId: string) => void;
}

declare global {
  interface Window {
    turnstile?: TurnstileApi;
  }
}

const SCRIPT_URL = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
// Must match EXPECTED_ACTION in backend/app/core/turnstile.py.
export const TURNSTILE_ACTION = 'etis_session';

export class BotCheckError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BotCheckError';
  }
}

let scriptPromise: Promise<TurnstileApi> | null = null;

export function loadTurnstile(): Promise<TurnstileApi> {
  if (window.turnstile) return Promise.resolve(window.turnstile);
  if (!scriptPromise) {
    scriptPromise = new Promise((resolve, reject) => {
      const script = document.createElement('script');
      script.src = SCRIPT_URL;
      script.async = true;
      script.onload = () =>
        window.turnstile ? resolve(window.turnstile) : reject(new BotCheckError('Turnstile did not initialise'));
      script.onerror = () => {
        scriptPromise = null; // allow a retry later (e.g. the network came back)
        reject(new BotCheckError('Turnstile script could not be loaded'));
      };
      document.head.appendChild(script);
    });
  }
  return scriptPromise;
}
