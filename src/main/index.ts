import {
  app,
  BrowserWindow,
  clipboard,
  dialog,
  ipcMain,
  type MessageBoxOptions,
  safeStorage,
  session,
  shell,
  WebContentsView
} from 'electron'
import { randomBytes } from 'node:crypto'
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

let mainWindow: BrowserWindow | null = null
let browserView: WebContentsView | null = null
let browserMode: BrowserMode = 'home'
let lastError: string | null = null
let browserChromeHeight = 122
let browserCssKey: string | null = null
let userStore: UserStore | null = null
let userKeyStore: UserKeyStore | null = null

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
const grantedMediaPermissionOrigins = new Set<string>()

function getUserStorePath(): string {
  return path.join(app.getPath('userData'), 'users.json')
}

function getUserKeyStorePath(): string {
  return path.join(app.getPath('userData'), 'user-keys.json')
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

async function requestMediaPermission(rawUrl: string, permission: string): Promise<boolean> {
  const origin = getSecureOrigin(rawUrl)

  if (!origin || permission !== 'media') {
    return false
  }

  if (grantedMediaPermissionOrigins.has(origin) || ALLOWED_BROWSER_PERMISSION_ORIGINS.has(origin)) {
    return true
  }

  const dialogOptions: MessageBoxOptions = {
    type: 'warning',
    buttons: ['Nie zezwalaj', 'Zezwalaj'],
    defaultId: 0,
    cancelId: 0,
    noLink: true,
    title: 'Prośba o dostęp',
    message: 'Ta strona prosi o dostęp do kamery lub mikrofonu.',
    detail: `${origin}\n\nZezwolić tej stronie na użycie kamery lub mikrofonu?`
  }

  const result = mainWindow
    ? await dialog.showMessageBox(mainWindow, dialogOptions)
    : await dialog.showMessageBox(dialogOptions)

  if (result.response !== 1) {
    return false
  }

  grantedMediaPermissionOrigins.add(origin)
  return true
}

function configureUserSessionSecurity(partition: string) {
  const targetSession = session.fromPartition(partition)

  targetSession.setPermissionRequestHandler((webContents, permission, callback, details) => {
    const requestingUrl = details.requestingUrl || webContents.getURL()

    if (permission === 'media') {
      void requestMediaPermission(requestingUrl, permission)
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

  targetSession.setPermissionCheckHandler((_webContents, permission, requestingOrigin) => {
    if (permission === 'media') {
      return grantedMediaPermissionOrigins.has(requestingOrigin)
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

  return {
    users: store.users,
    activeUserId: store.activeUserId
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

  mainWindow.webContents.send('browser:state', {
    mode: browserMode,
    url: browserView?.webContents.getURL() ?? '',
    title: browserView?.webContents.getTitle() || 'Easybrowser',
    isLoading: browserView?.webContents.isLoading() ?? false,
    canGoBack: browserView?.webContents.canGoBack() ?? false,
    canGoForward: browserView?.webContents.canGoForward() ?? false,
    isMaximized: mainWindow.isMaximized(),
    error: lastError
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

  view.webContents.on('did-start-loading', syncBrowserState)
  view.webContents.on('did-stop-loading', syncBrowserState)
  view.webContents.on('did-navigate', syncBrowserState)
  view.webContents.on('did-navigate-in-page', syncBrowserState)
  view.webContents.on('page-title-updated', syncBrowserState)
  view.webContents.on('dom-ready', () => {
    void injectBrowserCss()
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
  mainWindow.on('maximize', sendBrowserState)
  mainWindow.on('unmaximize', sendBrowserState)
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
