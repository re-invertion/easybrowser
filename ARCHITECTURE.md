# Easybrowser is a very simple web browser based on Electron.
## Non negotiable principles:
- No ads, no tracking, no telemetry.
- No unnecessary features, no bloat.
- Every string is in Polish!
- Always use the `Atkinson Hyperlegible` font across the whole interface.

## Project goal
The goal is to create a simple and very secure browser for eldery and non technical people.
- Future plans:
    - Add validation against malicious websites.
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
  - the whole file payload is encrypted directly with Electron `safeStorage`.
- Chromium session storage for each user partition
  - each user gets a separate persistent partition: `persist:easybrowser-user-{userId}`.
  - Chromium stores cookies, cache, local storage, and other browser session data there.
  - this storage is isolated per user, but it is not additionally encrypted by Easybrowser itself.
- Media permission grants are not persisted to disk.
- The following state is intentionally memory-only:
  - media permission grants,
  - administrator unlocked session state,
  - favicon cache.

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
