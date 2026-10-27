import { Box, Paper, Stack, Typography } from '@mui/material';
import TipsAndUpdatesOutlined from '@mui/icons-material/TipsAndUpdatesOutlined';
import { useTranslation } from 'react-i18next';

import type { AnalyzeResponse } from '../api/types';
import { VERDICT_STYLE } from '../theme/verdictPalette';

/**
 * Picks the advice keys for a result. Kept as a plain function next to the
 * card so the rules are easy to read in one place:
 * - the verdict decides the base steps (HIGH: do not engage, MEDIUM: verify
 *   first, LOW: no indicators but stay careful);
 * - a look-alike of a known brand adds "contact <brand> through its official
 *   channel" (never on the brand's own verified domain);
 * - a verified (allowlisted) domain gets its own short advice instead.
 * The "never share codes" line is in every case on purpose: it is the one
 * habit that stops most Egyptian bank and wallet scams, and a LOW verdict
 * must not read as "safe to share".
 */
function adviceFor(result: AnalyzeResponse): { key: string; values?: Record<string, string> }[] {
  // A verified main link only gets the short advice when nothing else (the
  // text, or another link in it) raised the verdict.
  if (result.allowlisted && result.verdict === 'LOW') {
    return [{ key: 'advice.allowlistedCheckSource' }, { key: 'advice.neverShareCodes' }];
  }

  const typosquat = result.engine_details.rule_based.engine_results.domain_typosquatting;
  const impersonatedBrand =
    !result.allowlisted && typosquat?.matched_brand && typosquat.technique !== 'exact_match' && typosquat.technique !== 'brand_subdomain'
      ? typosquat.matched_brand
      : null;

  const items: { key: string; values?: Record<string, string> }[] = [];
  if (result.verdict === 'HIGH') {
    items.push({ key: 'advice.highDoNotOpen' }, { key: 'advice.neverShareCodes' });
    if (impersonatedBrand) items.push({ key: 'advice.contactBrand', values: { brand: impersonatedBrand } });
    items.push({ key: 'advice.highIfAlreadyEntered' }, { key: 'advice.highReport' });
  } else if (result.verdict === 'MEDIUM') {
    items.push({ key: 'advice.mediumVerifyFirst' }, { key: 'advice.neverShareCodes' });
    if (impersonatedBrand) items.push({ key: 'advice.contactBrand', values: { brand: impersonatedBrand } });
    items.push({ key: 'advice.mediumNoPressure' });
  } else {
    items.push({ key: 'advice.lowNoIndicators' }, { key: 'advice.neverShareCodes' });
  }
  return items;
}

/** "What should I do?" panel shown next to the verdict. */
export function AdviceCard({ result }: { result: AnalyzeResponse }) {
  const { t } = useTranslation();
  const style = VERDICT_STYLE[result.verdict];
  const headingId = 'advice-heading';

  return (
    <Paper
      variant="outlined"
      component="section"
      aria-labelledby={headingId}
      sx={{ p: 2, borderRadius: 3, height: '100%', borderInlineStart: `4px solid ${style.accent}` }}
    >
      <Stack direction="row" spacing={1} sx={{ alignItems: 'center', mb: 1 }}>
        <TipsAndUpdatesOutlined fontSize="small" sx={{ color: style.accent }} aria-hidden />
        <Typography id={headingId} variant="subtitle2" component="h3" sx={{ fontWeight: 600 }}>
          {t('advice.heading')}
        </Typography>
      </Stack>
      <Box component="ul" sx={{ m: 0, ps: 2.5, '& li + li': { mt: 0.75 } }}>
        {adviceFor(result).map(({ key, values }) => (
          <Typography key={key} component="li" variant="body2">
            {t(key, values)}
          </Typography>
        ))}
      </Box>
    </Paper>
  );
}
