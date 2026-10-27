import { useCallback, useEffect, useRef, useState } from 'react';
import { Box, Paper, Stack, Typography } from '@mui/material';
import VerifiedUserOutlined from '@mui/icons-material/VerifiedUserOutlined';
import { useTranslation } from 'react-i18next';

import { registerChallengeHandler } from '../api/session';
import { BotCheckError, loadTurnstile, TURNSTILE_ACTION } from '../api/turnstile';

interface PendingChallenge {
  siteKey: string;
  resolve: (token: string) => void;
  reject: (error: Error) => void;
}

// How long the box stays on screen showing Cloudflare's "Success!" tick.
const SUCCESS_DISPLAY_MS = 1500;

/**
 * The "Security check" box, drawn inside the page above the current tab's
 * content, the way sign-in forms show Cloudflare's "Verify you are human"
 * box. It appears only while a session is being started (first visit, or
 * after the session expired) and disappears once the check has passed.
 * With a real site key Cloudflare usually passes the visitor on its own
 * after a second or two; a click is asked for only when it is unsure.
 */
export function BotCheck() {
  const { t, i18n } = useTranslation();
  const [challenge, setChallenge] = useState<PendingChallenge | null>(null);
  const [passed, setPassed] = useState(false);
  const widgetHostRef = useRef<HTMLDivElement>(null);

  const handler = useCallback(
    (siteKey: string) =>
      new Promise<string>((resolve, reject) => {
        setPassed(false);
        setChallenge({ siteKey, resolve, reject });
      }),
    [],
  );

  useEffect(() => {
    registerChallengeHandler(handler);
    return () => registerChallengeHandler(null);
  }, [handler]);

  // Draw the widget while a challenge is pending; redraw on a language
  // change so Cloudflare's own text follows the page language.
  useEffect(() => {
    if (!challenge || passed) return;
    let widgetId: string | null = null;
    let cancelled = false;

    loadTurnstile()
      .then((turnstile) => {
        if (cancelled || !widgetHostRef.current) return;
        widgetId = turnstile.render(widgetHostRef.current, {
          sitekey: challenge.siteKey,
          action: TURNSTILE_ACTION,
          language: i18n.language,
          theme: 'light',
          size: 'flexible',
          appearance: 'always',
          callback: (token) => {
            setPassed(true);
            challenge.resolve(token);
            window.setTimeout(() => setChallenge(null), SUCCESS_DISPLAY_MS);
          },
          'error-callback': () => {
            challenge.reject(new BotCheckError('Turnstile reported an error'));
            setChallenge(null);
          },
          // An unanswered checkbox times out; offer a fresh one rather than failing.
          'timeout-callback': () => {
            if (widgetId !== null) turnstile.reset(widgetId);
          },
          'expired-callback': () => {},
        });
      })
      .catch((error: Error) => {
        if (cancelled) return;
        challenge.reject(error);
        setChallenge(null);
      });

    const host = widgetHostRef.current;
    return () => {
      cancelled = true;
      if (widgetId !== null) window.turnstile?.remove(widgetId);
      host?.replaceChildren();
    };
    // `passed` is left out on purpose: the widget must stay on screen to
    // show its success tick until the box closes.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [challenge, i18n.language]);

  if (!challenge) return null;

  return (
    <Paper
      variant="outlined"
      component="section"
      aria-labelledby="bot-check-heading"
      sx={{ mt: 3, p: 2.5, borderRadius: 3, maxWidth: 520 }}
    >
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 0.5 }}>
        <VerifiedUserOutlined fontSize="small" color="primary" aria-hidden />
        <Typography id="bot-check-heading" variant="subtitle1" component="h2" sx={{ fontWeight: 600 }}>
          {t('session.botCheckHeading')}
        </Typography>
      </Stack>
      <Typography variant="body2" color="text.secondary" role="status" sx={{ mb: 1.5 }}>
        {passed ? t('session.botCheckPassed') : t('session.botCheckIntro')}
      </Typography>
      <Box ref={widgetHostRef} sx={{ minHeight: 65 }} />
    </Paper>
  );
}
