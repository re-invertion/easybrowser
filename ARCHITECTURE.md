# Easybrowser is a very simple web browser based on Electron.
## Non negotiable principles:
- No ads, no tracking, no telemetry.
- No unnecessary features, no bloat.
- Every string is in Polish!
- Always use the `Atkinson Hyperlegible` font across the whole interface.

## Project goal
The goal is to create a simple and very secure browser for eldery and non technical people.
- Future plans:
    - Add a simple password manager with multiple users.
    
## Technology:
- Electron
- React TS
- Tailwind CSS
- Vite

## Current Implementation Status
- The app is already split into the standard Electron layers:
  - `src/main/index.ts` for window management, browser session security, user data, and permission handling.
  - `src/preload/index.ts` for the safe bridge exposed to the renderer.
  - `src/renderer/src/App.tsx` for the full user interface.
- The main browser surface is rendered through `WebContentsView`, not inside the React DOM.
- The renderer currently works as a single main React screen with distinct states for:
  - user selection,
  - user home screen,
  - active browser mode.

## Current User Flow
- On launch, the app always starts with no active user selected.
- The user can:
  - choose an existing profile,
  - create a new profile,
  - remove a profile.
- After choosing a profile, the user sees a simplified home screen with a large search field.
- Entering a query or address opens the browsing mode.
- Returning to the home screen clears the main search field so it never shows leftover URLs from the browser view.
- The home screen also renders the active user's favorite pages as large tiles.
- Favorite tiles can be clicked to open the saved page or removed directly from the home screen.

## Current Browser Architecture
- Each user gets a separate persistent Chromium partition: `persist:easybrowser-user-{userId}`.
- This means browsing storage is isolated per user profile.
- The browser mode includes:
  - back,
  - forward,
  - reload,
  - go home,
  - add or remove the current page from favorites,
  - copy current URL,
  - custom window controls.
- The browser chrome height is reported from the renderer to the main process so the `WebContentsView` can be resized correctly below the custom header.
- The address field shows the current page favicon on the left and keeps user edits stable while the user is typing.
- The address field never restores a browser URL into the home search field.
- Favicons are resolved from Electron favicon events, page `<link rel="icon">` candidates, `/favicon.ico`, and `/apple-touch-icon.png`.
- Successful favicon responses are cached per origin as data URLs so the icon does not flicker or disappear during later loading events.
- The renderer has an additional visual fallback chain for favicon display.
- Every attempted navigation is checked live against the currently enabled phishing blocklists configured in the admin panel.
- Every attempted navigation is also passed through a configurable reputation engine before the page is shown.
- Domain blocklist sources are fetched on demand from their remote HTTPS endpoints at navigation time, with no offline mirror maintained by Easybrowser.
- The default blocklist sources are:
  - `https://hole.cert.pl/domains/v2/domains.txt`
  - `https://urlhaus.abuse.ch/downloads/text_online/`
- The admin panel can add additional blocklist source URLs, enable or disable each source, and remove non-default sources.
- The current reputation engine can score the page using these filters:
  - plain `http` navigation,
  - non-Latin characters in the hostname,
  - direct navigation to an IP address,
  - Google Safe Browsing matches,
  - very young domain age resolved through RDAP,
  - remote phishing blocklist matches.
- Each filter can be enabled or disabled independently from the admin panel, even while its section is collapsed.
- Filter settings are edited as a draft in the renderer and are written only after the user clicks the shared `Zapisz` action in the admin panel.
- Domain-age checks use RDAP over HTTPS with the IANA DNS bootstrap as the registry discovery source.
- Google Safe Browsing checks are executed from the Electron main process only and never expose the API key to page content or normal renderer state.
- If a hostname matches a listed domain, the `WebContentsView` is hidden and the renderer shows a full warning screen in its place.
- If the reputation score reaches the warning threshold, the user sees an in-browser caution screen and can explicitly continue.
- If the reputation score reaches the block threshold, the user sees an in-browser block screen and cannot continue.
- The current warning screens are phrased for non-technical users and show only a generic event code:
  - `filters-warning`
  - `filters-block`
- DNS resolution failures render a separate in-browser screen with the event code `no-dns-found`.

## Current Security Model
- `contextIsolation` is enabled.
- `nodeIntegration` is disabled.
- `sandbox` is enabled both for the main renderer window and the browser view.
- Only `http:` and `https:` navigation are allowed for opened pages.
- New windows are blocked and safe links are opened externally through the OS.
- Browser sessions use explicit Electron permission handlers.
- User data keys are stored with `safeStorage` when secure system storage is available.
- The browser administrator PIN is not stored in plain text:
  - the PIN itself is never persisted,
  - only `pinSalt`, `pinHash`, `failedAttempts`, and `lockedUntil` are stored.
- Global browser settings are stored in a single encrypted `browser-settings.json` payload.
- User favorites are stored in per-user encrypted payload files.
- Remote phishing blocklists are accepted only from HTTPS source URLs.
- Google Safe Browsing API checks are sent only from the main process.
- Navigation is fail-closed for phishing checks:
  - if a domain is found on an enabled list, the page is blocked,
  - if an enabled list cannot be fetched successfully during validation, the navigation is also blocked.
- Domain-age lookups use RDAP and fall back safely:
  - if RDAP data is unavailable, the age filter simply does not add score,
  - missing RDAP data alone does not block navigation.
- Google Safe Browsing lookups also fail softly:
  - if no API key is configured, the filter stays inactive,
  - if the remote request fails, the filter does not add score by itself.
- Only the configured blocklist source metadata is persisted locally.
- The downloaded blocklist contents are not written to disk by Easybrowser.

## Current Permissions Model
- Media permissions are handled with a custom in-app modal instead of the native Electron message box.
- The modal is shown above the browser as a separate lightweight overlay window controlled by the main process.
- The modal distinguishes between:
  - microphone access,
  - camera access,
  - microphone and camera access together.
- The modal currently offers three actions:
  - `Zezwalaj`
  - `Nie zezwalaj`
  - `Opuść stronę`
- Choosing `Opuść stronę` exits the current page and returns the user to the app home screen.
- Media permissions are currently:
  - per user,
  - per origin,
  - per app session only.
- Permissions are intentionally kept only in memory, so they are cleared after the app is restarted.
- The browser UI shows a visible indicator when the current page has access to:
  - the microphone,
  - the camera,
  - both microphone and camera.
- All other browser permissions are effectively denied unless explicitly added to the allowlist in code.

## Current Data Storage
- `users.json`
  - stores the user list and current active user id.
  - the whole file payload is encrypted directly with Electron `safeStorage`.
- `user-keys.json`
  - stores per-user data keys.
  - when secure system storage is available, each stored key is protected with Electron `safeStorage`.
  - in local development fallback mode, keys may be stored as `dev-plain:*`.
- `favorites/{userId}.json.enc`
  - stores the active user's favorite pages encrypted with the user's data key.
  - each favorite contains the URL, title, optional favicon data, and timestamps.
  - payload encryption uses `AES-256-GCM`.
  - the encryption key is derived from the per-user data key stored in `user-keys.json`.
- `browser-settings.json`
  - stores global browser settings such as:
    - `accessibility.visibleFocus`
    - administrator PIN metadata: `pinSalt`, `pinHash`, `failedAttempts`, `lockedUntil`
    - Google Safe Browsing API key
    - reputation engine settings:
      - `enabled`
      - `warningThreshold`
      - `blockedThreshold`
      - `disabledRuleIds`
      - `ruleWeights`
      - `youngDomainMaxAgeDays`
    - phishing blocklist source definitions:
      - `id`
      - `url`
      - `enabled`
      - `scoreDelta`
      - `isDefault`
      - `createdAt`
      - `updatedAt`
  - the whole file payload is encrypted directly with Electron `safeStorage`.
- Chromium session storage for each user partition
  - each user gets a separate persistent partition: `persist:easybrowser-user-{userId}`.
  - Chromium stores cookies, cache, local storage, and other browser session data there.
  - this storage is isolated per user, but it is not additionally encrypted by Easybrowser itself.
- Media permission grants are not persisted to disk.
- The following state is intentionally memory-only:
  - media permission grants,
  - administrator unlocked session state,
  - favicon cache,
  - RDAP bootstrap cache,
  - domain-age result cache,
  - Google Safe Browsing response cache,
  - filter draft state in the admin panel.

## Current UI State
- All user-facing strings remain in Polish.
- The interface uses `Atkinson Hyperlegible`.
- The browser top bar has already been slightly compacted to reduce vertical space.
- The browsing header now includes a right-side status badge for active microphone and camera access.
- The browser address bar includes:
  - a left-side favicon,
  - a favorite star action,
  - a copy URL action.
- The user home screen includes favorite page tiles with favicon rendering and a delete action.
- The admin panel is protected by an administrator PIN gate before access is granted.
- The admin panel includes an accessibility setting for toggling the visible yellow focus outline.
- The admin panel includes phishing protection settings for managing remote domain blocklist sources.
- The admin panel includes a broader security section for reputation scoring, per-filter enable/disable toggles, filter weights, RDAP-based young-domain settings, Google Safe Browsing configuration, and remote domain blocklist management.
- The Google Safe Browsing section exposes only whether the API key is configured plus actions to set or remove it; the stored key is not shown back to the user.
- The browser warning state is rendered as a dedicated in-browser safety screen instead of showing the dangerous page directly.
- Both the warning and block screens now use non-technical Polish copy intended for elderly or non-technical users.

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
- Ensure keyboard focus is always visible with the amber focus ring.
- Do not introduce alternate decorative UI fonts. Use `Atkinson Hyperlegible` consistently for headings, labels, inputs, and buttons.
- Avoid any unnecessary texts or labels. Use clear and concise language. 
