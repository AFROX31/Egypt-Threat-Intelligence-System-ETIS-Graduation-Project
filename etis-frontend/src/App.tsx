import { useEffect, useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CacheProvider } from '@emotion/react';
import {
  ThemeProvider,
  CssBaseline,
  AppBar,
  Toolbar,
  Tabs,
  Tab,
  Container,
  Button,
  Box,
} from '@mui/material';

import { BASE_URL } from './api/client';
import { ensureSession } from './api/session';
import { BotCheck } from './components/BotCheck';
import { createEtisTheme } from './theme/theme';
import { createRtlCache, createLtrCache } from './theme/rtlCache';
import { ScanPage } from './pages/ScanPage';
import { ThreatFeedPage } from './pages/ThreatFeedPage';
import { StatsPage } from './pages/StatsPage';

const PAGES = ['scan', 'threats', 'stats'] as const;
type PageKey = (typeof PAGES)[number];

export default function App() {
  const { t, i18n } = useTranslation();
  const [activePage, setActivePage] = useState<PageKey>('scan');

  const isRtl = i18n.language === 'ar';
  const direction = isRtl ? 'rtl' : 'ltr';

  // Theme and emotion cache both depend on direction, so both are
  // recreated together when the language toggle flips it.
  const theme = useMemo(() => createEtisTheme(direction), [direction]);
  const cache = useMemo(() => (isRtl ? createRtlCache() : createLtrCache()), [isRtl]);

  // Start the session (and its bot check) while the user reads the page, so
  // the first scan does not wait for it. A failure here is not shown: the
  // first API call retries and reports it through the page's error box.
  useEffect(() => {
    ensureSession(BASE_URL).catch(() => {});
  }, []);

  useEffect(() => {
    document.documentElement.dir = direction;
    document.documentElement.lang = i18n.language;
  }, [direction, i18n.language]);

  function toggleLanguage() {
    i18n.changeLanguage(isRtl ? 'en' : 'ar');
  }

  return (
    <CacheProvider value={cache}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        {/* Keyboard users can jump past the header and tabs. Hidden until focused. */}
        <Box
          component="a"
          href="#main-content"
          sx={{
            position: 'absolute',
            insetInlineStart: 8,
            top: -48,
            zIndex: 2000,
            px: 2,
            py: 1,
            bgcolor: 'background.paper',
            color: 'primary.main',
            borderRadius: 1,
            '&:focus': { top: 8 },
          }}
        >
          {t('a11y.skipToContent')}
        </Box>
        <AppBar position="static" color="primary">
          <Toolbar sx={{ gap: 2 }}>
            <Box sx={{ flexGrow: 1, display: 'flex', alignItems: 'center' }}>
              <Box
                component="img"
                src="/etis-logo.png"
                alt="ETIS"
                sx={{ height: 34, width: 'auto', display: 'block' }}
              />
            </Box>
            {/* lang on the button so a screen reader pronounces the other
                language's name in that language. */}
            <Button
              color="inherit"
              onClick={toggleLanguage}
              lang={isRtl ? 'en' : 'ar'}
              aria-label={isRtl ? 'Switch to English' : 'التبديل إلى العربية'}
            >
              {isRtl ? 'English' : 'العربية'}
            </Button>
          </Toolbar>
        </AppBar>

        <Container maxWidth="xl">
          <Tabs
            aria-label={t('a11y.mainNavigation')}
            value={activePage}
            onChange={(_, value: PageKey) => setActivePage(value)}
            sx={{ borderBottom: 1, borderColor: 'divider', mt: 1 }}
          >
            <Tab value="scan" label={t('nav.scan')} id="tab-scan" aria-controls="main-content" />
            <Tab value="threats" label={t('nav.threats')} id="tab-threats" aria-controls="main-content" />
            <Tab value="stats" label={t('nav.stats')} id="tab-stats" aria-controls="main-content" />
          </Tabs>

          <BotCheck />

          <Box
            component="main"
            id="main-content"
            tabIndex={-1}
            role="tabpanel"
            aria-labelledby={`tab-${activePage}`}
            sx={{ outline: 'none' }}
          >
            {activePage === 'scan' && <ScanPage />}
            {activePage === 'threats' && <ThreatFeedPage />}
            {activePage === 'stats' && <StatsPage />}
          </Box>
        </Container>
      </ThemeProvider>
    </CacheProvider>
  );
}
