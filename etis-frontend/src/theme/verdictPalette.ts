import type { Verdict } from '../api/types';

/**
 * Single source of truth for verdict colors, shared by VerdictCard and
 * anywhere else a verdict needs consistent color treatment (StatsPage's
 * by_verdict breakdown, e.g.) -- avoids the LOW/MEDIUM/HIGH palette
 * silently drifting apart between components.
 */
// Accents are used for text (the seal, the score), so each one is checked
// against its own background for WCAG AA (4.5:1): LOW 4.7, MEDIUM 4.7,
// HIGH 4.8. The theme's warning orange #C4881A was only 2.8 on the MEDIUM
// background, so the MEDIUM accent is a darker shade of the same amber.
export const VERDICT_STYLE: Record<Verdict, { bg: string; accent: string; chipColor: 'success' | 'warning' | 'error' }> = {
  LOW: { bg: '#eafbf1', accent: '#2e7d4f', chipColor: 'success' },
  MEDIUM: { bg: '#fdf3e3', accent: '#946410', chipColor: 'warning' },
  HIGH: { bg: '#fdecea', accent: '#c0392b', chipColor: 'error' },
};
