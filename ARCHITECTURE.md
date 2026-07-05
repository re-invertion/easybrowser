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

## Current Browser Architecture
- Each user gets a separate persistent Chromium partition: `persist:easybrowser-user-{userId}`.
- This means browsing storage is isolated per user profile.
- The browser mode includes:
  - back,
  - forward,
  - reload,
  - go home,
  - copy current URL,
  - custom window controls.
- The browser chrome height is reported from the renderer to the main process so the `WebContentsView` can be resized correctly below the custom header.

## Current Security Model
- `contextIsolation` is enabled.
- `nodeIntegration` is disabled.
- `sandbox` is enabled both for the main renderer window and the browser view.
- Only `http:` and `https:` navigation are allowed for opened pages.
- New windows are blocked and safe links are opened externally through the OS.
- Browser sessions use explicit Electron permission handlers.
- User data keys are stored with `safeStorage` when secure system storage is available.

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
- `user-keys.json`
  - stores encrypted per-user data keys.
- Media permission grants are not persisted to disk.

## Current UI State
- All user-facing strings remain in Polish.
- The interface uses `Atkinson Hyperlegible`.
- The browser top bar has already been slightly compacted to reduce vertical space.
- The browsing header now includes a right-side status badge for active microphone and camera access.

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
