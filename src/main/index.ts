import {
  app,
  BrowserWindow,
  clipboard,
  ipcMain,
  safeStorage,
  session,
  shell,
  WebContentsView
} from 'electron'
import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto'
import fs from 'node:fs'
import path from 'node:path'

if (process.platform === 'linux') {
  app.commandLine.appendSwitch('enable-features', 'UseOzonePlatform')
  app.commandLine.appendSwitch('ozone-platform-hint', 'wayland')
  app.commandLine.appendSwitch('ozone-platform', 'wayland')
}

// Xvfb and other headless Linux environments often fail GPU initialization.
app.disableHardwareAcceleration()

type BrowserMode = 'home' | 'browser'

type UserProfile = {
  id: string
  initials: string
  name: string
  description: string
  createdAt: string
}

type UserStore = {
  users: UserProfile[]
  activeUserId: string | null
}

type UserKeyStore = Record<string, string>
type MediaAccessType = 'audio' | 'video'
type UserMediaPermissionStore = Record<string, Record<string, MediaAccessType[]>>
type FavoriteEntry = {
  url: string
  title: string
  faviconUrl: string | null
  createdAt: string
  updatedAt: string
}
type UserFavoritesStore = Record<string, FavoriteEntry[]>

let mainWindow: BrowserWindow | null = null
let browserView: WebContentsView | null = null
let permissionPromptWindow: BrowserWindow | null = null
let browserMode: BrowserMode = 'home'
let lastError: string | null = null
let browserChromeHeight = 122
let browserCssKey: string | null = null
let browserFaviconUrl: string | null = null
let userStore: UserStore | null = null
let userKeyStore: UserKeyStore | null = null
let userMediaPermissionStore: UserMediaPermissionStore | null = null
let userFavoritesStore: UserFavoritesStore | null = null
const pendingMediaPermissionRequests = new Map<string, Promise<PermissionPromptAction>>()
const faviconDataUrlCache = new Map<string, string | null>()
const pageFaviconCache = new Map<string, string>()

const DEFAULT_USERS: UserProfile[] = []
const DEV_PLAIN_KEY_PREFIX = 'dev-plain:'

const BROWSER_INPUT_RING_CSS = `
  input:focus,
  textarea:focus,
  select:focus,
  [contenteditable="true"]:focus,
  [role="textbox"]:focus {
    outline: none !important;
    box-shadow: inset 0 0 0 2.5px rgba(251, 191, 36, 0.9) !important;
    padding-left: 0.35rem !important;
    padding-right: 0.35rem !important;
    position: relative !important;
    z-index: 2147483647 !important;
  }
`

const GOOGLE_HOME_URL = 'https://www.google.pl/?hl=pl&gl=PL&pws=0'
const ALLOWED_BROWSER_PERMISSION_ORIGINS = new Set<string>([])
const ALLOWED_BROWSER_PROTOCOLS = new Set(['https:', 'http:'])

type PermissionPromptAction = 'allow' | 'deny' | 'leave'

function normalizeMediaTypes(mediaTypes: readonly MediaAccessType[] | undefined): MediaAccessType[] {
  const nextMediaTypes = new Set<MediaAccessType>()

  for (const mediaType of mediaTypes ?? []) {
    if (mediaType === 'audio' || mediaType === 'video') {
      nextMediaTypes.add(mediaType)
    }
  }

  if (nextMediaTypes.size === 0) {
    return ['audio', 'video']
  }

  return Array.from(nextMediaTypes).sort()
}

function getMediaPermissionPromptText(mediaTypes: readonly MediaAccessType[]): {
  title: string
  message: string
} {
  const hasAudio = mediaTypes.includes('audio')
  const hasVideo = mediaTypes.includes('video')

  if (hasAudio && hasVideo) {
    return {
      title: 'Ta strona prosi o dostęp do kamery i mikrofonu.',
      message: 'Zezwolić tej stronie na użycie kamery i mikrofonu?'
    }
  }

  if (hasVideo) {
    return {
      title: 'Ta strona prosi o dostęp do kamery.',
      message: 'Zezwolić tej stronie na użycie kamery?'
    }
  }

  return {
    title: 'Ta strona prosi o dostęp do mikrofonu.',
    message: 'Zezwolić tej stronie na użycie mikrofonu?'
  }
}

function buildMediaPermissionRequestKey(
  origin: string,
  mediaTypes: readonly MediaAccessType[]
): string {
  return `${origin}|${mediaTypes.join(',')}`
}

function getUserStorePath(): string {
  return path.join(app.getPath('userData'), 'users.json')
}

function getUserKeyStorePath(): string {
  return path.join(app.getPath('userData'), 'user-keys.json')
}

function getUserFavoritesDirectoryPath(): string {
  return path.join(app.getPath('userData'), 'favorites')
}

function getUserFavoritesPath(userId: string): string {
  return path.join(getUserFavoritesDirectoryPath(), `${userId}.json.enc`)
}

function getInitials(value: string): string {
  const parts = value
    .trim()
    .split(/\s+/)
    .filter(Boolean)

  if (parts.length === 0) {
    return 'U'
  }

  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase()
  }

  return `${parts[0][0] ?? ''}${parts[1][0] ?? ''}`.toUpperCase()
}

function buildUserPartition(userId: string): string {
  return `persist:easybrowser-user-${userId}`
}

function getActiveUserId(): string | null {
  return loadUserStore().activeUserId
}

function loadUserMediaPermissionStore(): UserMediaPermissionStore {
  if (userMediaPermissionStore) {
    return userMediaPermissionStore
  }

  userMediaPermissionStore = {}
  return userMediaPermissionStore
}

function loadUserFavoritesStore(): UserFavoritesStore {
  if (userFavoritesStore) {
    return userFavoritesStore
  }

  userFavoritesStore = {}
  return userFavoritesStore
}

function getUserDataKey(userId: string): Buffer {
  const storedValue = loadUserKeyStore()[userId]

  if (typeof storedValue !== 'string' || storedValue.length === 0) {
    throw new Error('Nie znaleziono klucza danych użytkownika.')
  }

  if (storedValue.startsWith(DEV_PLAIN_KEY_PREFIX)) {
    return Buffer.from(storedValue.slice(DEV_PLAIN_KEY_PREFIX.length), 'base64')
  }

  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  const decryptedValue = safeStorage.decryptString(Buffer.from(storedValue, 'base64'))
  return Buffer.from(decryptedValue, 'base64')
}

function encryptUserPayload(userId: string, payload: string): string {
  const key = createHash('sha256').update(getUserDataKey(userId)).digest()
  const iv = randomBytes(12)
  const cipher = createCipheriv('aes-256-gcm', key, iv)
  const encryptedValue = Buffer.concat([cipher.update(payload, 'utf8'), cipher.final()])
  const authTag = cipher.getAuthTag()

  return JSON.stringify({
    iv: iv.toString('base64'),
    tag: authTag.toString('base64'),
    content: encryptedValue.toString('base64')
  })
}

function decryptUserPayload(userId: string, payload: string): string {
  const parsedPayload = JSON.parse(payload) as {
    iv?: string
    tag?: string
    content?: string
  }

  if (!parsedPayload.iv || !parsedPayload.tag || !parsedPayload.content) {
    throw new Error('Nieprawidłowy format zaszyfrowanych danych użytkownika.')
  }

  const key = createHash('sha256').update(getUserDataKey(userId)).digest()
  const decipher = createDecipheriv(
    'aes-256-gcm',
    key,
    Buffer.from(parsedPayload.iv, 'base64')
  )
  decipher.setAuthTag(Buffer.from(parsedPayload.tag, 'base64'))

  return Buffer.concat([
    decipher.update(Buffer.from(parsedPayload.content, 'base64')),
    decipher.final()
  ]).toString('utf8')
}

function normalizeFavoriteEntries(entries: FavoriteEntry[]): FavoriteEntry[] {
  return entries
    .filter((entry) => {
      return (
        entry &&
        typeof entry.url === 'string' &&
        entry.url.length > 0 &&
        typeof entry.title === 'string' &&
        (typeof entry.faviconUrl === 'string' || entry.faviconUrl === null || entry.faviconUrl === undefined) &&
        typeof entry.createdAt === 'string' &&
        typeof entry.updatedAt === 'string'
      )
    })
    .map((entry) => ({
      ...entry,
      faviconUrl: typeof entry.faviconUrl === 'string' ? entry.faviconUrl : null
    }))
    .sort((left, right) => left.title.localeCompare(right.title, 'pl'))
}

function getUserFavorites(userId: string): FavoriteEntry[] {
  const store = loadUserFavoritesStore()

  if (store[userId]) {
    return store[userId]
  }

  const filePath = getUserFavoritesPath(userId)

  try {
    if (fs.existsSync(filePath)) {
      const encryptedPayload = fs.readFileSync(filePath, 'utf8')
      const decryptedPayload = decryptUserPayload(userId, encryptedPayload)
      const parsedFavorites = JSON.parse(decryptedPayload) as FavoriteEntry[]
      const normalizedFavorites = Array.isArray(parsedFavorites)
        ? normalizeFavoriteEntries(parsedFavorites)
        : []
      store[userId] = normalizedFavorites
      return normalizedFavorites
    }
  } catch {
    // Fall back to empty favorites when encrypted data cannot be read.
  }

  store[userId] = []
  return store[userId]
}

function saveUserFavorites(userId: string, favorites: FavoriteEntry[]): void {
  const normalizedFavorites = normalizeFavoriteEntries(favorites)
  const store = loadUserFavoritesStore()
  store[userId] = normalizedFavorites

  const directoryPath = getUserFavoritesDirectoryPath()
  fs.mkdirSync(directoryPath, { recursive: true })

  const encryptedPayload = encryptUserPayload(userId, JSON.stringify(normalizedFavorites))
  fs.writeFileSync(getUserFavoritesPath(userId), encryptedPayload, 'utf8')
}

function isFavoriteUrl(userId: string | null, rawUrl: string): boolean {
  if (!userId || !isSafeBrowserUrl(rawUrl)) {
    return false
  }

  return getUserFavorites(userId).some((favorite) => favorite.url === rawUrl)
}

function toggleFavoriteForCurrentPage(): boolean {
  const userId = getActiveUserId()
  const currentUrl = browserView?.webContents.getURL() ?? ''

  if (!userId) {
    throw new Error('Najpierw wybierz użytkownika.')
  }

  if (!isSafeBrowserUrl(currentUrl)) {
    throw new Error('Nie można dodać tej strony do ulubionych.')
  }

  const favorites = getUserFavorites(userId)
  const existingFavorite = favorites.find((favorite) => favorite.url === currentUrl)

  if (existingFavorite) {
    saveUserFavorites(
      userId,
      favorites.filter((favorite) => favorite.url !== currentUrl)
    )
    sendBrowserState()
    return false
  }

  const timestamp = new Date().toISOString()
  const pageTitle = browserView?.webContents.getTitle()?.trim() || currentUrl

  saveUserFavorites(userId, [
    ...favorites,
    {
      url: currentUrl,
      title: pageTitle,
      faviconUrl: browserFaviconUrl,
      createdAt: timestamp,
      updatedAt: timestamp
    }
  ])
  sendBrowserState()
  return true
}

function removeFavoriteForActiveUser(rawUrl: string) {
  const userId = getActiveUserId()

  if (!userId) {
    throw new Error('Najpierw wybierz użytkownika.')
  }

  if (!isSafeBrowserUrl(rawUrl)) {
    throw new Error('Nie można usunąć tej strony z ulubionych.')
  }

  const favorites = getUserFavorites(userId)
  saveUserFavorites(
    userId,
    favorites.filter((favorite) => favorite.url !== rawUrl)
  )
  sendBrowserState()

  return getUserState()
}

function getGrantedMediaTypes(userId: string | null, origin: string): MediaAccessType[] {
  if (!userId) {
    return []
  }

  const store = loadUserMediaPermissionStore()
  return store[userId]?.[origin] ?? []
}

function hasGrantedMediaPermission(
  userId: string | null,
  origin: string,
  mediaTypes?: readonly MediaAccessType[]
): boolean {
  const grantedMediaTypes = new Set(getGrantedMediaTypes(userId, origin))

  if (grantedMediaTypes.size === 0) {
    return false
  }

  if (!mediaTypes || mediaTypes.length === 0) {
    return true
  }

  return mediaTypes.every((mediaType) => grantedMediaTypes.has(mediaType))
}

function getGrantedMediaAccessState(userId: string | null, rawUrl: string): {
  hasMicrophoneAccess: boolean
  hasCameraAccess: boolean
} {
  const origin = getSecureOrigin(rawUrl)

  if (!origin) {
    return {
      hasMicrophoneAccess: false,
      hasCameraAccess: false
    }
  }

  const grantedMediaTypes = new Set(getGrantedMediaTypes(userId, origin))

  return {
    hasMicrophoneAccess: grantedMediaTypes.has('audio'),
    hasCameraAccess: grantedMediaTypes.has('video')
  }
}

function grantMediaPermission(
  userId: string | null,
  origin: string,
  mediaTypes: readonly MediaAccessType[]
): void {
  if (!userId) {
    return
  }

  const store = loadUserMediaPermissionStore()
  const nextUserPermissions = { ...(store[userId] ?? {}) }
  const nextMediaTypes = new Set(nextUserPermissions[origin] ?? [])

  for (const mediaType of mediaTypes) {
    nextMediaTypes.add(mediaType)
  }

  nextUserPermissions[origin] = Array.from(nextMediaTypes).sort()
  store[userId] = nextUserPermissions
}

function clearUserMediaPermissions(userId: string): void {
  const store = loadUserMediaPermissionStore()

  if (!(userId in store)) {
    return
  }

  delete store[userId]
}

function clearUserFavorites(userId: string): void {
  const store = loadUserFavoritesStore()

  if (userId in store) {
    delete store[userId]
  }

  const filePath = getUserFavoritesPath(userId)

  if (fs.existsSync(filePath)) {
    fs.rmSync(filePath, { force: true })
  }
}

function isAllowedPermissionOrigin(rawUrl: string): boolean {
  try {
    const parsedUrl = new URL(rawUrl)
    return parsedUrl.protocol === 'https:' && ALLOWED_BROWSER_PERMISSION_ORIGINS.has(parsedUrl.origin)
  } catch {
    return false
  }
}

function getSecureOrigin(rawUrl: string): string | null {
  try {
    const parsedUrl = new URL(rawUrl)

    if (parsedUrl.protocol !== 'https:') {
      return null
    }

    return parsedUrl.origin
  } catch {
    return null
  }
}

function isSafeBrowserUrl(rawUrl: string): boolean {
  try {
    const parsedUrl = new URL(rawUrl)
    return ALLOWED_BROWSER_PROTOCOLS.has(parsedUrl.protocol)
  } catch {
    return false
  }
}

function buildFallbackFaviconCandidates(rawUrl: string): string[] {
  try {
    const parsedUrl = new URL(rawUrl)

    if (!ALLOWED_BROWSER_PROTOCOLS.has(parsedUrl.protocol)) {
      return []
    }

    return [
      `${parsedUrl.origin}/favicon.ico`,
      `${parsedUrl.origin}/apple-touch-icon.png`
    ]
  } catch {
    return []
  }
}

function getFaviconCacheKey(rawUrl: string): string | null {
  try {
    const parsedUrl = new URL(rawUrl)

    if (!ALLOWED_BROWSER_PROTOCOLS.has(parsedUrl.protocol)) {
      return null
    }

    return parsedUrl.origin
  } catch {
    return null
  }
}

function getCachedPageFavicon(rawUrl: string): string | null {
  const cacheKey = getFaviconCacheKey(rawUrl)

  if (!cacheKey) {
    return null
  }

  return pageFaviconCache.get(cacheKey) ?? null
}

function rememberPageFavicon(rawUrl: string, dataUrl: string): void {
  const cacheKey = getFaviconCacheKey(rawUrl)

  if (!cacheKey) {
    return
  }

  pageFaviconCache.set(cacheKey, dataUrl)
}

function updateFavoriteFavicon(userId: string | null, rawUrl: string, faviconUrl: string): void {
  if (!userId || !isSafeBrowserUrl(rawUrl)) {
    return
  }

  const favorites = getUserFavorites(userId)
  const favoriteIndex = favorites.findIndex((favorite) => favorite.url === rawUrl)

  if (favoriteIndex === -1 || favorites[favoriteIndex]?.faviconUrl === faviconUrl) {
    return
  }

  const timestamp = new Date().toISOString()
  const nextFavorites = favorites.map((favorite, index) => {
    if (index !== favoriteIndex) {
      return favorite
    }

    return {
      ...favorite,
      faviconUrl,
      updatedAt: timestamp
    }
  })

  saveUserFavorites(userId, nextFavorites)
}

function applyCachedPageFavicon(rawUrl: string, shouldClearMissing = false): void {
  const cachedFavicon = getCachedPageFavicon(rawUrl)
  browserFaviconUrl = cachedFavicon ?? (shouldClearMissing ? null : browserFaviconUrl)
  sendBrowserState()
}

async function fetchFaviconAsDataUrl(
  targetSession: Electron.Session,
  faviconUrl: string
): Promise<string | null> {
  const cachedValue = faviconDataUrlCache.get(faviconUrl)

  if (cachedValue !== undefined) {
    return cachedValue
  }

  try {
    const response = await targetSession.fetch(faviconUrl)

    if (!response.ok) {
      faviconDataUrlCache.set(faviconUrl, null)
      return null
    }

    const contentType = response.headers.get('content-type') || 'image/png'

    if (!contentType.startsWith('image/')) {
      faviconDataUrlCache.set(faviconUrl, null)
      return null
    }

    const arrayBuffer = await response.arrayBuffer()
    const dataUrl = `data:${contentType};base64,${Buffer.from(arrayBuffer).toString('base64')}`
    faviconDataUrlCache.set(faviconUrl, dataUrl)
    return dataUrl
  } catch {
    faviconDataUrlCache.set(faviconUrl, null)
    return null
  }
}

async function extractPageIconCandidates(view: WebContentsView): Promise<string[]> {
  try {
    const rawValue = await view.webContents.executeJavaScript(`
      (() => {
        const nodes = Array.from(document.querySelectorAll('link[rel]'));
        return nodes
          .filter((node) => {
            const rel = String(node.getAttribute('rel') || '').toLowerCase();
            return rel.includes('icon');
          })
          .sort((left, right) => {
            const leftSizes = String(left.getAttribute('sizes') || '');
            const rightSizes = String(right.getAttribute('sizes') || '');
            return rightSizes.length - leftSizes.length;
          })
          .map((node) => node.href)
          .filter((value) => typeof value === 'string' && value.length > 0);
      })()
    `)

    return Array.isArray(rawValue)
      ? rawValue.filter((value): value is string => typeof value === 'string' && value.length > 0)
      : []
  } catch {
    return []
  }
}

async function updateBrowserFavicon(view: WebContentsView, candidateUrls: string[] = []): Promise<void> {
  const currentPageUrl = view.webContents.getURL()
  const activeUserId = getActiveUserId()
  const cachedFavicon = getCachedPageFavicon(currentPageUrl)

  if (cachedFavicon && !browserFaviconUrl) {
    browserFaviconUrl = cachedFavicon
    sendBrowserState()
  }

  const pageIconCandidates = await extractPageIconCandidates(view)

  if (currentPageUrl !== view.webContents.getURL()) {
    return
  }

  const combinedCandidates = [
    ...candidateUrls,
    ...pageIconCandidates,
    ...buildFallbackFaviconCandidates(currentPageUrl)
  ].filter((value, index, array) => {
    return typeof value === 'string' && value.length > 0 && array.indexOf(value) === index
  })

  if (combinedCandidates.length === 0) {
    if (!browserFaviconUrl) {
      sendBrowserState()
    }
    return
  }

  for (const candidateUrl of combinedCandidates) {
    if (candidateUrl.startsWith('data:image/')) {
      rememberPageFavicon(currentPageUrl, candidateUrl)
      updateFavoriteFavicon(activeUserId, currentPageUrl, candidateUrl)
      browserFaviconUrl = candidateUrl
      sendBrowserState()
      return
    }

    if (!isSafeBrowserUrl(candidateUrl)) {
      continue
    }

    const dataUrl = await fetchFaviconAsDataUrl(view.webContents.session, candidateUrl)

    if (currentPageUrl !== view.webContents.getURL()) {
      return
    }

    if (dataUrl) {
      rememberPageFavicon(currentPageUrl, dataUrl)
      updateFavoriteFavicon(activeUserId, currentPageUrl, dataUrl)
      browserFaviconUrl = dataUrl
      sendBrowserState()
      return
    }
  }

  if (!browserFaviconUrl) {
    sendBrowserState()
  }
}

function buildPermissionPromptHtml(mediaTypes: readonly MediaAccessType[]): string {
  const promptText = getMediaPermissionPromptText(mediaTypes)

  return `<!doctype html>
<html lang="pl">
  <head>
    <meta charset="UTF-8" />
    <meta
      http-equiv="Content-Security-Policy"
      content="default-src 'none'; img-src data:; style-src 'unsafe-inline'; script-src 'unsafe-inline'"
    />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Prośba o dostęp</title>
    <style>
      :root {
        color-scheme: light;
        font-family: "Atkinson Hyperlegible", system-ui, sans-serif;
      }

      * {
        box-sizing: border-box;
      }

      body {
        margin: 0;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        background: rgba(15, 23, 42, 0.34);
        color: #111827;
      }

      .backdrop {
        width: 100%;
        min-height: 100vh;
        display: flex;
        align-items: center;
        justify-content: center;
        padding: 24px;
      }

      .card {
        width: min(100%, 520px);
        border-radius: 28px;
        border: 1px solid #cbd5e1;
        background: rgba(255, 255, 255, 0.98);
        box-shadow: 0 32px 80px rgba(15, 23, 42, 0.22);
        padding: 28px;
      }

      .eyebrow {
        margin: 0 0 12px;
        font-size: 13px;
        font-weight: 700;
        letter-spacing: 0.16em;
        text-transform: uppercase;
        color: #64748b;
      }

      h1 {
        margin: 0;
        font-size: 30px;
        line-height: 1.15;
      }

      p {
        margin: 14px 0 0;
        font-size: 17px;
        line-height: 1.55;
        color: #475569;
      }

      .actions {
        margin-top: 24px;
        display: flex;
        flex-wrap: wrap;
        justify-content: flex-end;
        gap: 12px;
      }

      button {
        border: 0;
        border-radius: 999px;
        padding: 14px 20px;
        font: inherit;
        font-size: 15px;
        font-weight: 700;
        cursor: pointer;
        transition: transform 140ms ease, background-color 140ms ease, color 140ms ease;
      }

      button:focus-visible {
        outline: 3px solid #fbbf24;
        outline-offset: 2px;
      }

      button:hover {
        transform: translateY(-1px);
      }

      .secondary {
        background: #ffffff;
        color: #111827;
        border: 1px solid #cbd5e1;
      }

      .danger {
        background: #fff1f2;
        color: #b91c1c;
        border: 1px solid #fecdd3;
      }

      .primary {
        background: #1e3a8a;
        color: #ffffff;
      }

      @media (max-width: 640px) {
        .card {
          padding: 22px;
          border-radius: 24px;
        }

        h1 {
          font-size: 26px;
        }

        .actions {
          justify-content: stretch;
        }

        .actions button {
          width: 100%;
        }
      }
    </style>
  </head>
  <body>
    <div class="backdrop">
      <section class="card" role="dialog" aria-modal="true" aria-labelledby="title">
        <p class="eyebrow">Prośba o dostęp</p>
        <h1 id="title">${promptText.title}</h1>
        <p>${promptText.message}</p>

        <div class="actions">
          <button class="danger" id="leave" type="button">Opuść stronę</button>
          <button class="secondary" id="deny" type="button">Nie zezwalaj</button>
          <button class="primary" id="allow" type="button" autofocus>Zezwalaj</button>
        </div>
      </section>
    </div>

    <script>
      const leaveButton = document.getElementById('leave');
      const denyButton = document.getElementById('deny');
      const allowButton = document.getElementById('allow');

      const resolvePrompt = (decision) => {
        const url = 'easybrowser-permission://' + decision;
        window.location.href = url;
      };

      leaveButton?.addEventListener('click', () => resolvePrompt('leave'));
      denyButton?.addEventListener('click', () => resolvePrompt('deny'));
      allowButton?.addEventListener('click', () => resolvePrompt('allow'));

      window.addEventListener('keydown', (event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          resolvePrompt('deny');
        }
      });
    </script>
  </body>
</html>`
}

function updatePermissionPromptBounds(): void {
  if (!mainWindow || !permissionPromptWindow) {
    return
  }

  permissionPromptWindow.setBounds(mainWindow.getBounds())
}

function leaveCurrentPage(): void {
  if (browserView?.webContents.isLoading()) {
    browserView.webContents.stop()
  }

  browserMode = 'home'
  lastError = null
  updateBrowserBounds()
  sendBrowserState()
}

async function showMediaPermissionPrompt(
  mediaTypes: readonly MediaAccessType[]
): Promise<PermissionPromptAction> {
  if (!mainWindow || mainWindow.isDestroyed()) {
    return 'deny'
  }

  const parentWindow = mainWindow

  return await new Promise<PermissionPromptAction>((resolve) => {
    let settled = false

    const finish = (decision: PermissionPromptAction) => {
      if (settled) {
        return
      }

      settled = true

      if (permissionPromptWindow && !permissionPromptWindow.isDestroyed()) {
        permissionPromptWindow.destroy()
      }

      permissionPromptWindow = null
      resolve(decision)
    }

    const promptWindow = new BrowserWindow({
      parent: parentWindow,
      modal: true,
      frame: false,
      transparent: true,
      backgroundColor: '#00000000',
      resizable: false,
      movable: false,
      minimizable: false,
      maximizable: false,
      closable: true,
      show: false,
      skipTaskbar: true,
      hasShadow: false,
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
      }
    })

    permissionPromptWindow = promptWindow
    updatePermissionPromptBounds()

    promptWindow.webContents.setWindowOpenHandler(() => {
      return { action: 'deny' }
    })

    promptWindow.webContents.on('will-navigate', (event, navigationUrl) => {
      if (navigationUrl === 'easybrowser-permission://allow') {
        event.preventDefault()
        finish('allow')
        return
      }

      if (navigationUrl === 'easybrowser-permission://deny') {
        event.preventDefault()
        finish('deny')
        return
      }

      if (navigationUrl === 'easybrowser-permission://leave') {
        event.preventDefault()
        finish('leave')
        return
      }

      event.preventDefault()
    })

    promptWindow.on('closed', () => {
      finish('deny')
    })

    promptWindow.once('ready-to-show', () => {
      updatePermissionPromptBounds()
      promptWindow.show()
      promptWindow.focus()
    })

    const promptHtml = buildPermissionPromptHtml(mediaTypes)
    void promptWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(promptHtml)}`)
  })
}

async function requestMediaPermission(
  rawUrl: string,
  permission: string,
  mediaTypes: readonly MediaAccessType[] | undefined
): Promise<boolean> {
  const origin = getSecureOrigin(rawUrl)
  const activeUserId = getActiveUserId()

  if (!origin || permission !== 'media' || !activeUserId) {
    return false
  }

  const normalizedMediaTypes = normalizeMediaTypes(mediaTypes)

  if (
    hasGrantedMediaPermission(activeUserId, origin, normalizedMediaTypes) ||
    ALLOWED_BROWSER_PERMISSION_ORIGINS.has(origin)
  ) {
    return true
  }

  const requestKey = buildMediaPermissionRequestKey(origin, normalizedMediaTypes)
  const pendingRequest = pendingMediaPermissionRequests.get(requestKey)

  if (pendingRequest) {
    const decision = await pendingRequest

    if (decision === 'leave') {
      leaveCurrentPage()
    }

    return decision === 'allow'
  }

  const permissionRequest = showMediaPermissionPrompt(normalizedMediaTypes)
  pendingMediaPermissionRequests.set(requestKey, permissionRequest)

  try {
    const decision = await permissionRequest

    if (decision === 'allow') {
      grantMediaPermission(activeUserId, origin, normalizedMediaTypes)
      sendBrowserState()
    }

    if (decision === 'leave') {
      leaveCurrentPage()
    }

    return decision === 'allow'
  } finally {
    pendingMediaPermissionRequests.delete(requestKey)
  }
}

function configureUserSessionSecurity(partition: string) {
  const targetSession = session.fromPartition(partition)

  targetSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const requestingUrl = details.requestingUrl || webContents.getURL()

    if (permission === 'media') {
      const mediaTypes = 'mediaTypes' in details ? details.mediaTypes : undefined

      void requestMediaPermission(requestingUrl, permission, mediaTypes)
        .then((allowed) => {
          callback(allowed)
        })
        .catch(() => {
          callback(false)
        })
      return
    }

    callback(isAllowedPermissionOrigin(requestingUrl))
  })

  targetSession.setPermissionCheckHandler((_webContents, permission, requestingOrigin, details) => {
    if (permission === 'media') {
      const mediaType = details.mediaType
      const requestedMediaTypes =
        mediaType === 'audio' || mediaType === 'video' ? [mediaType] : undefined

      return hasGrantedMediaPermission(getActiveUserId(), requestingOrigin, requestedMediaTypes)
    }

    return isAllowedPermissionOrigin(requestingOrigin)
  })

  return targetSession
}

function normalizeStore(store: UserStore): UserStore {
  const users = Array.isArray(store.users) ? store.users : DEFAULT_USERS
  const activeUserId =
    store.activeUserId && users.some((user) => user.id === store.activeUserId)
      ? store.activeUserId
      : null

  return {
    users,
    activeUserId
  }
}

function saveUserStore(store: UserStore): void {
  fs.writeFileSync(getUserStorePath(), JSON.stringify(store, null, 2), 'utf8')
}

function saveUserKeyStore(store: UserKeyStore): void {
  fs.writeFileSync(getUserKeyStorePath(), JSON.stringify(store, null, 2), 'utf8')
}

function loadUserStore(): UserStore {
  if (userStore) {
    return userStore
  }

  const filePath = getUserStorePath()

  try {
    if (fs.existsSync(filePath)) {
      const rawValue = fs.readFileSync(filePath, 'utf8')
      const parsedStore = JSON.parse(rawValue) as UserStore
      userStore = normalizeStore(parsedStore)
      return userStore
    }
  } catch {
    // Fall back to default users when local data is unreadable.
  }

  userStore = {
    users: DEFAULT_USERS,
    activeUserId: null
  }
  saveUserStore(userStore)
  return userStore
}

function loadUserKeyStore(): UserKeyStore {
  if (userKeyStore) {
    return userKeyStore
  }

  const filePath = getUserKeyStorePath()

  try {
    if (fs.existsSync(filePath)) {
      const rawValue = fs.readFileSync(filePath, 'utf8')
      const parsedStore = JSON.parse(rawValue) as UserKeyStore
      userKeyStore =
        parsedStore && typeof parsedStore === 'object' && !Array.isArray(parsedStore)
          ? parsedStore
          : {}
      return userKeyStore
    }
  } catch {
    // Fall back to an empty key store when local data is unreadable.
  }

  userKeyStore = {}
  saveUserKeyStore(userKeyStore)
  return userKeyStore
}

function assertSecureUserKeyStorageAvailable(): void {
  if (!safeStorage.isEncryptionAvailable()) {
    if (!app.isPackaged) {
      return
    }

    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  if (process.platform === 'linux') {
    const backend = safeStorage.getSelectedStorageBackend()

    if (backend === 'basic_text' || backend === 'unknown') {
      if (!app.isPackaged) {
        return
      }

      throw new Error(
        'Brak bezpiecznego systemowego magazynu kluczy. Skonfiguruj keyring systemowy.'
      )
    }
  }
}

function createAndStoreUserDataKey(userId: string): void {
  const dataKey = randomBytes(32).toString('base64')
  const keyStore = loadUserKeyStore()
  let storedValue: string

  try {
    assertSecureUserKeyStorageAvailable()

    if (safeStorage.isEncryptionAvailable()) {
      const encryptedDataKey = safeStorage.encryptString(dataKey)
      storedValue = encryptedDataKey.toString('base64')
    } else if (!app.isPackaged) {
      storedValue = `${DEV_PLAIN_KEY_PREFIX}${dataKey}`
    } else {
      throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
    }
  } catch (error) {
    if (app.isPackaged) {
      throw error
    }

    storedValue = `${DEV_PLAIN_KEY_PREFIX}${dataKey}`
  }

  keyStore[userId] = storedValue
  saveUserKeyStore(keyStore)
}

function hasStoredUserDataKey(userId: string): boolean {
  const keyStore = loadUserKeyStore()
  return typeof keyStore[userId] === 'string' && keyStore[userId].length > 0
}

function removeStoredUserDataKey(userId: string): void {
  const keyStore = loadUserKeyStore()

  if (!(userId in keyStore)) {
    return
  }

  delete keyStore[userId]
  saveUserKeyStore(keyStore)
}

function destroyBrowserView(): void {
  if (!browserView) {
    return
  }

  if (mainWindow) {
    mainWindow.contentView.removeChildView(browserView)
  }

  browserView.webContents.close()
  browserView = null
  browserCssKey = null
}

async function clearUserBrowsingData(userId: string): Promise<void> {
  const partition = buildUserPartition(userId)
  const targetSession = configureUserSessionSecurity(partition)
  const storagePath = targetSession.getStoragePath()

  if (browserView) {
    const currentStoragePath = browserView.webContents.session.getStoragePath()

    if (currentStoragePath === storagePath) {
      destroyBrowserView()
    }
  }

  try {
    await targetSession.clearStorageData()
  } catch {
    // Continue cleanup even if the Chromium storage layer partially fails.
  }

  try {
    await targetSession.clearCache()
  } catch {
    // Continue cleanup even if cache clearing is unavailable on this platform.
  }

  try {
    targetSession.flushStorageData()
  } catch {
    // Best-effort flush before removing the on-disk partition directory.
  }

  if (storagePath && fs.existsSync(storagePath)) {
    fs.rmSync(storagePath, { recursive: true, force: true })
  }
}

function getUserState() {
  const store = loadUserStore()
  const favorites = store.activeUserId ? getUserFavorites(store.activeUserId) : []

  return {
    users: store.users,
    activeUserId: store.activeUserId,
    favorites
  }
}

function getActiveUserPartition(): string | null {
  const store = loadUserStore()

  if (!store.activeUserId) {
    return null
  }

  return buildUserPartition(store.activeUserId)
}

function normalizeAddress(value: string): string {
  const trimmed = value.trim()

  if (trimmed.length === 0) {
    return GOOGLE_HOME_URL
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return isSafeBrowserUrl(trimmed) ? trimmed : GOOGLE_HOME_URL
  }

  if (/^[^\s]+\.[^\s]+$/.test(trimmed)) {
    return `https://${trimmed}`
  }

  return `https://www.google.pl/search?hl=pl&gl=PL&pws=0&q=${encodeURIComponent(trimmed)}`
}

function updateBrowserBounds(): void {
  if (!mainWindow || !browserView) {
    return
  }

  const [width, height] = mainWindow.getContentSize()

  if (browserMode !== 'browser') {
    browserView.setBounds({ x: 0, y: 0, width: 0, height: 0 })
    return
  }

  browserView.setBounds({
    x: 0,
    y: browserChromeHeight,
    width: Math.max(0, width),
    height: Math.max(0, height - browserChromeHeight)
  })
}

function sendBrowserState(): void {
  if (!mainWindow) {
    return
  }

  const currentUrl = browserView?.webContents.getURL() ?? ''
  const activeUserId = getActiveUserId()
  const mediaAccessState = getGrantedMediaAccessState(activeUserId, currentUrl)
  const effectiveBrowserFaviconUrl = browserFaviconUrl || getCachedPageFavicon(currentUrl)

  mainWindow.webContents.send('browser:state', {
    mode: browserMode,
    url: currentUrl,
    title: browserView?.webContents.getTitle() || 'Easybrowser',
    isLoading: browserView?.webContents.isLoading() ?? false,
    canGoBack: browserView?.webContents.navigationHistory.canGoBack() ?? false,
    canGoForward: browserView?.webContents.navigationHistory.canGoForward() ?? false,
    isMaximized: mainWindow.isMaximized(),
    error: lastError,
    hasMicrophoneAccess: mediaAccessState.hasMicrophoneAccess,
    hasCameraAccess: mediaAccessState.hasCameraAccess,
    isFavorite: isFavoriteUrl(activeUserId, currentUrl),
    browserFaviconUrl: effectiveBrowserFaviconUrl
  })
}

function wireBrowserView(view: WebContentsView): void {
  const syncBrowserState = () => {
    sendBrowserState()
  }

  const injectBrowserCss = async () => {
    try {
      if (browserCssKey) {
        await view.webContents.removeInsertedCSS(browserCssKey)
      }
    } catch {
      browserCssKey = null
    }

    try {
      browserCssKey = await view.webContents.insertCSS(BROWSER_INPUT_RING_CSS)
    } catch {
      browserCssKey = null
    }
  }

  view.webContents.setWindowOpenHandler(({ url }: { url: string }) => {
    if (isSafeBrowserUrl(url)) {
      shell.openExternal(url)
    }

    return { action: 'deny' }
  })

  view.webContents.on('will-navigate', (event, navigationUrl) => {
    if (!isSafeBrowserUrl(navigationUrl)) {
      event.preventDefault()
      lastError = `Zablokowano niebezpieczny adres: ${navigationUrl}`
      sendBrowserState()
    }
  })

  view.webContents.on('did-start-loading', () => {
    syncBrowserState()
  })
  view.webContents.on('did-stop-loading', syncBrowserState)
  view.webContents.on('did-navigate', (_event, navigationUrl) => {
    applyCachedPageFavicon(navigationUrl, true)
    void updateBrowserFavicon(view)
  })
  view.webContents.on('did-navigate-in-page', (_event, navigationUrl) => {
    applyCachedPageFavicon(navigationUrl)
    void updateBrowserFavicon(view)
  })
  view.webContents.on('page-title-updated', syncBrowserState)
  view.webContents.on('page-favicon-updated', (_event, favicons) => {
    void updateBrowserFavicon(view, favicons)
  })
  view.webContents.on('dom-ready', () => {
    void injectBrowserCss()
    void updateBrowserFavicon(view)
    syncBrowserState()
  })
  view.webContents.on(
    'did-fail-load',
    (_event, errorCode, errorDescription, validatedURL, isMainFrame) => {
      if (!isMainFrame || errorCode === -3) {
        return
      }

      lastError =
        validatedURL && validatedURL.length > 0
          ? `${errorDescription} (${validatedURL})`
          : errorDescription
      sendBrowserState()
    }
  )
}

function ensureBrowserView(): WebContentsView {
  if (!mainWindow) {
    throw new Error('Okno aplikacji nie jest gotowe.')
  }

  const activePartition = getActiveUserPartition()

  if (!activePartition) {
    throw new Error('Najpierw wybierz użytkownika.')
  }

  if (browserView) {
    const currentPartition = browserView.webContents.session.getStoragePath()
    const nextPartition = configureUserSessionSecurity(activePartition).getStoragePath()

    if (currentPartition === nextPartition) {
      return browserView
    }

    destroyBrowserView()
  }

  const nextBrowserView = new WebContentsView({
    webPreferences: {
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
      partition: activePartition
    }
  })

  configureUserSessionSecurity(activePartition)
  browserView = nextBrowserView
  mainWindow.contentView.addChildView(nextBrowserView)
  wireBrowserView(nextBrowserView)
  updateBrowserBounds()

  return nextBrowserView
}

async function navigateBrowser(rawValue: string): Promise<void> {
  const view = ensureBrowserView()
  const destination = normalizeAddress(rawValue)
  browserMode = 'browser'
  lastError = null
  updateBrowserBounds()
  sendBrowserState()

  try {
    await view.webContents.loadURL(destination)
  } catch (error) {
    lastError = error instanceof Error ? error.message : 'Nie udało się otworzyć strony.'
    sendBrowserState()
  }
}

function createMainWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 840,
    minWidth: 960,
    minHeight: 640,
    backgroundColor: '#f8fafc',
    frame: false,
    autoHideMenuBar: true,
    title: 'Easybrowser',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true
    }
  })

  mainWindow.maximize()

  mainWindow.webContents.setWindowOpenHandler(({ url }: { url: string }) => {
    if (isSafeBrowserUrl(url)) {
      shell.openExternal(url)
    }

    return { action: 'deny' }
  })

  mainWindow.on('resize', updateBrowserBounds)
  mainWindow.on('resize', updatePermissionPromptBounds)
  mainWindow.on('move', updatePermissionPromptBounds)
  mainWindow.on('maximize', sendBrowserState)
  mainWindow.on('maximize', updatePermissionPromptBounds)
  mainWindow.on('unmaximize', sendBrowserState)
  mainWindow.on('unmaximize', updatePermissionPromptBounds)
  mainWindow.webContents.once('did-finish-load', () => {
    sendBrowserState()
  })

  if (process.env.ELECTRON_RENDERER_URL) {
    void mainWindow.loadURL(process.env.ELECTRON_RENDERER_URL)
  } else {
    void mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'))
  }
}

ipcMain.handle('users:get-state', () => {
  return getUserState()
})

ipcMain.handle('users:select', (_event, userId: string) => {
  const store = loadUserStore()

  if (!store.users.some((user) => user.id === userId)) {
    throw new Error('Nie znaleziono użytkownika.')
  }

  if (!hasStoredUserDataKey(userId)) {
    throw new Error('Nie znaleziono klucza danych użytkownika w systemowym magazynie.')
  }

  store.activeUserId = userId
  saveUserStore(store)
  browserMode = 'home'
  lastError = null

  if (mainWindow) {
    ensureBrowserView()
    updateBrowserBounds()
    sendBrowserState()
  }

  return getUserState()
})

ipcMain.handle('users:clear-active', () => {
  const store = loadUserStore()
  store.activeUserId = null
  saveUserStore(store)
  browserMode = 'home'
  lastError = null
  updateBrowserBounds()
  sendBrowserState()

  return getUserState()
})

ipcMain.handle('users:create', (_event, name: string) => {
  const trimmedName = name.trim()

  if (!trimmedName) {
    throw new Error('Nazwa użytkownika jest wymagana.')
  }

  const store = loadUserStore()
  const nextUser: UserProfile = {
    id: `user-${Date.now()}`,
    initials: getInitials(trimmedName),
    name: trimmedName,
    description: 'Nowy użytkownik',
    createdAt: new Date().toISOString()
  }

  createAndStoreUserDataKey(nextUser.id)

  store.users = [...store.users, nextUser]
  store.activeUserId = nextUser.id
  saveUserStore(store)
  browserMode = 'home'
  lastError = null

  if (mainWindow) {
    ensureBrowserView()
    updateBrowserBounds()
    sendBrowserState()
  }

  return getUserState()
})

ipcMain.handle('users:delete', async (_event, userId: string) => {
  const store = loadUserStore()

  if (!store.users.some((user) => user.id === userId)) {
    throw new Error('Nie znaleziono użytkownika.')
  }

  store.users = store.users.filter((user) => user.id !== userId)

  if (store.activeUserId === userId) {
    store.activeUserId = null
  }

  await clearUserBrowsingData(userId)
  removeStoredUserDataKey(userId)
  clearUserMediaPermissions(userId)
  clearUserFavorites(userId)
  saveUserStore(store)
  browserMode = 'home'
  lastError = null
  updateBrowserBounds()
  sendBrowserState()

  return getUserState()
})

ipcMain.handle('browser:navigate', async (_event, value: string) => {
  await navigateBrowser(value)
})

ipcMain.handle('browser:home', () => {
  browserMode = 'home'
  lastError = null
  updateBrowserBounds()
  sendBrowserState()
})

ipcMain.handle('browser:back', () => {
  browserView?.webContents.goBack()
})

ipcMain.handle('browser:forward', () => {
  browserView?.webContents.goForward()
})

ipcMain.handle('browser:reload', () => {
  browserView?.webContents.reload()
})

ipcMain.handle('browser:toggle-favorite', () => {
  return toggleFavoriteForCurrentPage()
})

ipcMain.handle('browser:remove-favorite', (_event, url: string) => {
  return removeFavoriteForActiveUser(url)
})

ipcMain.handle('browser:toggle-maximize', () => {
  if (!mainWindow) {
    return
  }

  if (mainWindow.isMaximized()) {
    mainWindow.unmaximize()
  } else {
    mainWindow.maximize()
  }

  sendBrowserState()
})

ipcMain.handle('window:minimize', () => {
  mainWindow?.minimize()
})

ipcMain.handle('window:close', () => {
  mainWindow?.close()
})

ipcMain.handle('clipboard:copy-text', (_event, value: string) => {
  clipboard.writeText(value ?? '')
})

ipcMain.handle('browser:set-chrome-height', (_event, height: number) => {
  if (!Number.isFinite(height) || height < 0) {
    return
  }

  browserChromeHeight = Math.round(height)
  updateBrowserBounds()
})

app.whenReady().then(() => {
  const store = loadUserStore()
  store.activeUserId = null
  saveUserStore(store)

  createMainWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow()
    }
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
