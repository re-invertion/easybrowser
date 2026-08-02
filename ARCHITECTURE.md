# Easybrowser

Easybrowser is a very simple and security-focused browser based on Electron.

## Non Negotiable Principles
- No ads, no tracking, no telemetry.
- No unnecessary features and no bloat.
- Every user-facing string must be in Polish.
- The UI must use `Atkinson Hyperlegible` consistently.
- The product is designed for elderly and non-technical people, so security messages must be calm, clear, and non-technical.

## Technology
- Electron for the desktop shell, privileged main process, Chromium sessions, and `WebContentsView`.
- React and TypeScript for the renderer UI.
- Tailwind CSS for styling.
- Vite and Electron Vite for bundling.
- `sql.js` for the application-managed SQLite database.
- Electron `safeStorage` for encrypting the SQLite payload before it is written to disk.
- `tldts` for URL, hostname, public suffix, and registrable-domain normalization.

## Process And Layer Split
- `src/main/index.ts` owns privileged browser behavior:
  - main window and `WebContentsView` lifecycle,
  - navigation validation,
  - Chromium session configuration,
  - permission handling,
  - encrypted SQLite storage,
  - phishing and reputation checks,
  - trusted-domain synchronization,
  - admin PIN verification.
- `src/preload/index.ts` exposes a narrow, typed bridge from the renderer to the main process.
- `src/renderer/src/App.tsx` owns the visible UI:
  - user selection,
  - home screen,
  - browser chrome,
  - admin panel,
  - warning and error screens.
- Browsed web pages are not rendered inside the React DOM. They are rendered through Electron `WebContentsView` below the custom browser chrome.

## Application Startup
- On app startup, the encrypted SQLite database is initialized before the main window is created.
- The app always starts with no active user selected.
- Existing users remain stored in the database, but `activeUserId` is cleared on launch.
- Trusted-domain sources are checked in the background after startup.
- If the default trusted-domain source has no local entries yet, the app attempts an initial synchronization.
- The app remains usable if the trusted-domain synchronization fails.

## User Profiles
- Users are stored in the shared application database in the `users` table.
- Each user has:
  - `id`,
  - `name`,
  - `initials`,
  - `description`,
  - `created_at`,
  - `is_active`.
- The app supports:
  - creating a user,
  - selecting a user,
  - removing a user,
  - clearing the active user when returning to the selection flow.
- User removal also clears Easybrowser-managed user favorites and in-memory media grants for that user.
- Chromium browsing data is isolated separately per user through persistent Chromium partitions.

## Chromium Session Isolation
- Each user gets a Chromium partition named `persist:easybrowser-user-{userId}`.
- Chromium stores cookies, cache, local storage, IndexedDB, and other page-controlled browser data inside that partition.
- This Chromium-managed partition storage is isolated per user.
- Easybrowser does not additionally encrypt Chromium's own session storage.
- Application-managed profile data is separate from Chromium session storage and is stored in `browser-data.sqlite.enc`.

## Home Screen And Favorites
- After selecting a user, the user sees a simplified home screen with a large search field.
- The home search field is always clean when returning from browsing mode.
- Browser URLs are not written back into the home search field.
- Plain search terms use Google Search by default.
- The app avoids unrelated background Google requests such as favicon fallback services or remote Google Fonts.
- Favorites are stored per user in the `favorites` table.
- Each favorite contains:
  - `url`,
  - `title`,
  - optional `favicon_url`,
  - `created_at`,
  - `updated_at`.
- The home screen renders favorites as large tiles.
- Favorite tiles can be opened directly from the home screen.
- Favorite tiles can be removed directly from the home screen.

## Browser Chrome
- The browser chrome is rendered in React above the `WebContentsView`.
- The renderer reports the browser chrome height to the main process.
- The main process resizes the `WebContentsView` so web content starts below the custom browser chrome.
- The browser chrome includes:
  - back,
  - forward,
  - reload,
  - home,
  - favorite star,
  - current-page favicon,
  - URL input,
  - copy URL,
  - microphone/camera usage indicator,
  - custom window controls.
- The URL input preserves user edits while the user is typing.
- Deleting the URL does not cause the old loaded URL to be reinserted into the field.

## Favicons
- Favicons are resolved from several sources:
  - Electron page favicon events,
  - page `<link rel="icon">` candidates,
  - `/favicon.ico`,
  - `/apple-touch-icon.png`.
- Successful favicon responses are cached per origin as data URLs.
- The cache prevents favicons from disappearing during later navigation/loading events.
- The renderer does not call Google favicon fallback services.
- The renderer has a fallback display path when no favicon is available.
- The favicon is shown both:
  - in the browser address bar,
  - on favorite tiles.

## Navigation Pipeline
- Navigation is allowed only for `http:` and `https:` URLs.
- New windows are blocked by default.
- Safe external links are opened externally through the OS when appropriate.
- Every attempted navigation goes through normalization and validation before the page is shown.
- The navigation pipeline checks:
  - protocol,
  - normalized hostname,
  - trusted-domain bypass,
  - reputation filters,
  - warning/block thresholds,
  - DNS and Chromium navigation failures.
- When navigation is blocked or paused by a warning, the `WebContentsView` is hidden and the renderer shows a dedicated safety screen.

## URL Normalization
- URLs are parsed through the platform URL parser.
- Hostnames are normalized before security checks.
- Domain data is resolved with `tldts`.
- The normalized candidate includes:
  - original URL,
  - normalized URL,
  - protocol,
  - hostname,
  - ASCII hostname,
  - Unicode hostname,
  - registrable domain,
  - public suffix,
  - subdomain,
  - IP-address marker,
  - port,
  - path,
  - query.
- This normalized candidate is the shared input for reputation rules.

## Reputation Engine
- The reputation engine scores each navigation attempt.
- The engine can be enabled or disabled from the admin panel.
- Each rule can be enabled or disabled independently.
- Each rule has a configurable score value.
- The warning threshold and block threshold are configurable.
- Current default behavior:
  - score `50+` shows a warning screen,
  - score `70+` blocks the page.
- The public reputation score is capped at `100`; if multiple rules add more than `100` points, the engine still exposes `100` as the final score.
- Blocking rules can force a high score by adding enough points to cross the block threshold.
- Content analysis runs after domain/URL rules for every navigation whose preliminary score is still below the block threshold.
- If a page is already blocked by domain/URL rules, the engine does not fetch its HTML for content analysis.
- Filter settings are edited as draft state in the renderer.
- Filter settings are persisted only after the admin clicks `Zapisz`.
- The browser chrome receives a lightweight reputation-status snapshot for the current page and renders it as a compact animated security-level indicator next to the favorites action.
- The status indicator shows the score, decision, block threshold, and matched-rule count without exposing full page HTML or re-running content analysis in the renderer.
- The security-level tooltip is rendered by the main process as a small frameless child `BrowserWindow`, not as a normal DOM tooltip, so it can appear above the `WebContentsView` layer.

## Reputation Rules
- `insecure-http`
  - Detects navigation to plain `http:`.
  - This is configured under warning filters.
  - The user can choose whether to continue from the warning screen.
- `domain-blocklist`
  - Checks the hostname against remote phishing/blocklist sources.
  - Enabled lists are fetched live during navigation.
  - If a source cannot be fetched during validation, navigation fails closed for that list path.
- `non-latin-script`
  - Detects hostnames containing letters outside the Latin alphabet.
  - This helps catch lookalike domains using mixed scripts.
- `lookalike-trusted-domain`
  - Detects domains that are not trusted themselves but look very similar to a trusted domain.
  - The rule compares the registrable domain against enabled trusted domains.
  - It uses a lightweight skeleton for common substitutions such as `0` to `o`, `1` to `l`, and similar characters.
  - The skeleton also maps common Cyrillic and Greek confusable characters to Latin equivalents.
  - It also uses a small edit-distance threshold to catch close typos.
  - Trusted domains store precomputed `label`, `skeleton`, and `label_length` metadata in SQLite so navigation checks do not need to recompute every trusted domain.
  - SQLite indexes on `skeleton` and `label_length` support a fast shortlist before edit-distance comparison.
  - The rule adds warning score and can be configured from the admin panel.
  - This rule is intentionally heuristic and local; it does not use an external model or remote reputation API.
  - Exact trusted-domain matches are allowed before this rule runs, so the rule only affects similar but different domains.
- `trusted-domain-in-subdomain`
  - Detects addresses where a trusted domain appears inside the subdomain while the real registrable domain is different.
  - This catches bait patterns such as `paypal.com.example.net`, where the visible beginning may look trustworthy but the actual site is `example.net`.
  - It also detects trusted brand labels in unofficial subdomains, such as `paypal.fake.xyz`, when the trusted label has at least five characters.
  - The rule adds warning score and can be configured from the admin panel.
- `is-ip`
  - Detects direct navigation to an IP address instead of a named domain.
- `google-safe-browsing`
  - Checks the URL with Google Safe Browsing when an API key is configured.
  - The API key is never exposed to page content or normal renderer state.
  - If no API key is configured, the rule is inactive.
  - If the remote request fails, this rule fails softly and does not add score by itself.
- `young-domain-age`
  - Checks domain age through RDAP.
  - Very young domains can add warning score.
  - Missing RDAP data does not block navigation by itself.
- `url-risk-pattern`
  - Detects generic suspicious URL path/query patterns such as `phishing`, `malware`, `bad_login`, `low_rep_login`, `trick_to_bill`, `cookie_theft`, `pua`, `suspicious`, and risky executable/archive file extensions.
  - This rule is generic and is not tied to a specific test domain.
  - It is configured as a blocking-score rule by default.
- `content-sensitive-form`
  - Fetches the HTML document and detects forms or inputs that ask for sensitive data such as passwords, email, card data, OTP/SMS codes, BLIK, or similar fields.
  - This is intentionally a warning-score signal because legitimate login pages also contain password fields.
- `content-cross-origin-form`
  - Detects sensitive forms that submit to a different hostname than the page being visited.
  - This is a stronger content signal because phishing pages often collect credentials on a different endpoint.
- `content-brand-impersonation`
  - Compares visible page text and raw HTML against trusted-domain labels.
  - If a trusted brand appears on an unofficial domain, the rule adds warning score.
- Trusted domains themselves are still allowed before content analysis runs.
- Trusted-domain matching keeps the full hostname during evaluation.
- Exact trusted-domain matches are allowed.
- Normal first-party subdomains can inherit trust from the trusted parent domain.
- Private/shared hosting tenant domains, for example domains under private suffixes like `appspot.com` or `github.io`, do not inherit trust from the hosting platform entry. This prevents a popular hosting provider from disabling filters for every tenant page hosted below it.
- Manually added trusted domains preserve the exact hostname entered by the administrator after normalization. For example, adding `testsafebrowsing.appspot.com` stores `testsafebrowsing.appspot.com`, not `appspot.com`.
- Imported trusted-domain sources such as Tranco are normalized to registrable domains because they represent broad popularity lists rather than explicit administrator allowlist entries.
- `content-urgent-language`
  - Detects pressure language such as urgent verification, blocked account, account confirmation, or similar Polish/English phrases.
  - This rule is low-score by default to reduce false positives.
- `content-suspicious-iframe`
  - Detects hidden iframes or iframes loaded from another hostname.
- `content-download-risk`
  - Detects links to risky executable/archive/script file extensions.
- `content-threat-link-catalog`
  - Detects pages that look like catalogs of links to multiple threat types, for example phishing, malware, unwanted software, billing traps, cookie theft, low-reputation pages, dangerous downloads, or restricted-content warnings.
  - The rule requires several distinct threat categories and repeated warning/trigger language, so ordinary educational articles mentioning one threat should not be blocked by this rule alone.
  - This is a generic content rule and is not tied to a specific testing hostname.

## Page Content Analysis
- Page content analysis is part of the same reputation engine and uses the same thresholds.
- The main process fetches only HTML-like responses for analysis.
- Content fetches use:
  - no-store cache mode,
  - a 6 second timeout,
  - an HTML size cap before local analysis.
- Content analysis is skipped for pages already blocked by earlier reputation rules.
- The HTML is analyzed in memory and is not persisted.
- Security events store only the matched rule metadata, score, event code, URL, hostname, and timestamp.
- Full page content is never written to SQLite logs or browser settings.
- Content analysis is skipped for trusted domains because trusted-domain navigation is allowed before reputation rules run.
- The content-analysis rule group also performs its own trusted-domain guard before fetching HTML, so trusted domains are never fetched by this layer even if the group is called independently.
- Content rules are configurable from the admin Security panel under `Analiza treści strony`.

## Remote Blocklists
- The default remote blocklist sources are:
  - `https://hole.cert.pl/domains/v2/domains.txt`,
  - `https://urlhaus.abuse.ch/downloads/text_online/`.
- Admins can add more HTTPS blocklist sources.
- Admins can enable or disable each source.
- Admins can remove non-default sources.
- Source metadata is stored in `domain_blocklist_sources`.
- Downloaded blocklist contents are not stored as an offline Easybrowser mirror.
- Blocklist validation is performed live against currently enabled source URLs.

## Trusted Domains
- Trusted domains are intended as a whitelist-style bypass for reputation filters.
- Trusted domains can come from:
  - the default Tranco source,
  - manually added administrator domains.
- Trusted source metadata is stored in `trusted_sources`.
- Trusted domain entries are stored in `trusted_domains`.
- The default Tranco source is:
  - `https://tranco-list.eu/top-1m.csv.zip`.
- The default local limit is `50_000` domains.
- Tranco data is downloaded as a ZIP archive and parsed locally.
- Manually added domains use the internal `manual` trusted source and are managed directly in the admin panel.
- Manual trusted domains are normalized before saving and IP addresses are rejected.
- Manual trusted domains are displayed as a list with one row per domain, including the creation timestamp and a remove action.
- If a domain is trusted, reputation rules are bypassed and the navigation assessment is allowed.
- Trusted source synchronization errors are stored on the source row and do not prevent the app from starting.

## Warning And Error Screens
- Warning and block screens are rendered by the renderer in the browser content area.
- The dangerous page is not shown behind the warning screen.
- Warning copy is written for non-technical users.
- Rule IDs are not shown to the user.
- The user-facing event codes are:
  - `filters-warning`,
  - `filters-block`,
  - `no-dns-found`.
- `filters-warning` allows the user to continue explicitly.
- `filters-block` does not allow continuing to the page.
- `no-dns-found` is shown when Chromium reports that the domain cannot be resolved.
- The DNS failure screen includes a return action to the home screen.

## Security Events
- Security events are stored in the `security_events` table.
- A security event is currently written when reputation filters produce a warning or block intervention.
- The admin panel Security tab exposes recent warning/block events in a right-side slide-out panel.
- The log viewer shows events from the last 30 days, newest first.
- At most 500 recent events are returned to the UI in one read.
- Each stored event contains:
  - generated event id,
  - current user id when available,
  - normalized URL,
  - hostname,
  - decision,
  - event code,
  - JSON details with score and matched rule metadata,
  - creation timestamp.
- Events older than 30 days are purged automatically:
  - during application database initialization,
  - before writing a new security event,
  - before listing events for the admin panel.
- These events are local application state and are encrypted as part of the shared SQLite payload.

## Permissions
- Media permissions use a custom in-app modal instead of Electron's native dialog.
- The modal is displayed above the browser as a separate lightweight overlay window controlled by the main process.
- The modal distinguishes between:
  - microphone access,
  - camera access,
  - microphone and camera access together.
- The modal offers:
  - `Zezwalaj`,
  - `Nie zezwalaj`,
  - `Opuść stronę`.
- Choosing `Opuść stronę` exits the current page and returns the user to the home screen.
- Media permissions are:
  - per user,
  - per origin,
  - per app session.
- Media permission grants are intentionally memory-only and are cleared after app restart.
- The browser chrome shows a visible indicator when the current page has access to:
  - microphone,
  - camera,
  - microphone and camera.
- Other browser permissions are denied unless explicitly allowed in code.

## Admin Panel
- The admin panel is opened from the browser label context menu.
- The panel is protected by an administrator PIN.
- If the PIN is unset, the admin must set it before entering the panel.
- After the PIN is set, entering the panel requires verification.
- The PIN itself is never stored.
- Stored PIN metadata includes:
  - salt,
  - hash,
  - failed attempt count,
  - lock timestamp.
- The admin unlocked state is session-only and memory-only.
- The admin panel includes:
  - accessibility settings,
  - reputation scoring settings,
  - per-rule enable/disable toggles,
  - per-rule score values,
  - warning and block thresholds,
  - remote blocklist source management,
  - trusted-domain source management,
  - Google Safe Browsing API key management,
  - recent security event logs from the last 30 days in a slide-out side panel.
- The panel content scrolls inside the panel area and does not scroll the custom window chrome.

## Accessibility
- The current accessibility setting is `visibleFocus`.
- `visibleFocus` controls the yellow focus outline.
- The setting is stored in `app_settings`.
- The UI is designed around high contrast, large controls, simple layouts, and readable typography.

## Shared SQLite Database
- Easybrowser uses one application-managed database file:
  - `browser-data.sqlite.enc`.
- The file lives in Electron's `app.getPath('userData')` directory.
- The app does not currently migrate data from older JSON-based storage files.
- Losing old local state is accepted at this stage.
- The database is loaded on startup, decrypted in memory, and saved back as an encrypted payload.
- If the encrypted database cannot be read, the app creates a fresh database.

## Database Tables
- `app_settings`
  - key-value JSON settings such as accessibility options.
- `users`
  - Easybrowser user profiles and active-user marker.
- `favorites`
  - user favorite pages keyed by `user_id`.
- `admin_security`
  - admin PIN salt/hash metadata, failed attempts, and lock state.
- `reputation_settings`
  - global reputation engine state, thresholds, young-domain configuration, and Google Safe Browsing API key.
- `reputation_rule_settings`
  - per-rule enable state, score delta, and severity.
- `domain_blocklist_sources`
  - configured remote phishing/blocklist source URLs and score values.
- `trusted_sources`
  - configured trusted-domain source metadata, including Tranco and the internal manual source.
- `trusted_domains`
  - trusted domain rows imported from enabled trusted sources or added manually by the administrator.
  - stores lookalike metadata: `label`, `skeleton`, and `label_length`.
- `security_events`
  - local records of warning/block security decisions.
  - retained for 30 days and exposed in the admin Security tab side panel.

## Encryption Model
- The SQLite database bytes are exported from `sql.js`.
- The exported SQLite bytes are base64-encoded.
- The base64 payload is encrypted with Electron `safeStorage.encryptString`.
- The encrypted output is saved as base64 text in `browser-data.sqlite.enc`.
- On load, the file is decoded, decrypted with `safeStorage.decryptString`, and reconstructed as a `sql.js` database.
- There are no per-user Easybrowser data keys.
- User-specific application rows are separated by `user_id`, not by separate encrypted files.
- This protects Easybrowser-managed application data at rest through the OS-backed storage mechanism used by Electron `safeStorage`.
- Chromium profile data remains managed by Chromium and is not additionally encrypted by Easybrowser.

## Memory-Only State
- The following state is intentionally not persisted:
  - media permission grants,
  - pending media permission requests,
  - administrator unlocked session,
  - favicon cache,
  - RDAP bootstrap cache,
  - domain-age result cache,
  - Google Safe Browsing response cache,
  - renderer draft state for unsaved admin settings.

## Current UI State
- The interface uses `Atkinson Hyperlegible`.
- The browser top bar is compact to preserve vertical space.
- The browsing header includes a right-side status badge for active microphone and camera access.
- The browser address bar includes:
  - left-side favicon,
  - favorite star action,
  - copy URL action.
- The user home screen includes favorite page tiles with favicon rendering and delete actions.
- The browser warning state is rendered as a dedicated in-browser safety screen.
- Warning and block screens use non-technical Polish copy intended for elderly or non-technical users.

## Visual Design Rules
- Background: `#F8FAFC`
- Text: `#111827`
- Tiles: `#FFFFFF`
- Tile border: `#CBD5E1`
- Primary button: `#1E3A8A`
- Primary button text: `#FFFFFF`
- Focus ring: `#FBBF24`

## UI Principles
- Keep the interface calm, high-contrast, and easy to scan.
- Use white tiles on the light background for key actions and grouped content.
- Reserve the primary blue for the main action on each screen.
- Ensure keyboard focus can be visible with the amber focus ring.
- Do not introduce alternate decorative UI fonts.
- Avoid unnecessary text and labels.
- Prefer clear, concise Polish wording over technical details.
