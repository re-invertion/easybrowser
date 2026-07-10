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
import {
  createCipheriv,
  createDecipheriv,
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual
} from 'node:crypto'
import fs from 'node:fs'
import { isIP } from 'node:net'
import path from 'node:path'
import { domainToUnicode } from 'node:url'
import { getDomain, getPublicSuffix, getSubdomain } from 'tldts'

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
type AdminSecurityStore = {
  pinSalt: string | null
  pinHash: string | null
  failedAttempts: number
  lockedUntil: string | null
}
type AdminPinStatus = {
  isSet: boolean
  isSessionUnlocked: boolean
  failedAttempts: number
  remainingAttempts: number
  lockedUntil: string | null
}
type AccessibilitySettings = {
  visibleFocus: boolean
}
type ReputationRuleSeverity = 'warning' | 'blocking'
type ReputationDecision = 'allow' | 'warning' | 'blocked'
type ReputationRuleId =
  | 'insecure-http'
  | 'domain-blocklist'
  | 'non-latin-script'
  | 'is-ip'
  | 'google-safe-browsing'
  | 'young-domain-age'
type NormalizedSiteCandidate = {
  rawUrl: string
  normalizedUrl: string
  protocol: 'http:' | 'https:'
  hostname: string
  asciiHostname: string
  unicodeHostname: string
  registrableDomain: string | null
  publicSuffix: string | null
  subdomain: string | null
  isIp: boolean
  port: string | null
  path: string
  query: string
}
type ReputationRuleResult = {
  ruleId: ReputationRuleId
  matched: boolean
  scoreDelta: number
  severity: ReputationRuleSeverity
  code: string
  message: string
}
type ReputationAssessment = {
  candidate: NormalizedSiteCandidate
  score: number
  decision: ReputationDecision
  matchedRules: ReputationRuleResult[]
}
type ReputationAssessmentPreview = {
  normalizedUrl: string
  score: number
  decision: ReputationDecision
  matchedRules: ReputationRuleResult[]
}
type ReputationInterventionState = {
  url: string
  decision: Exclude<ReputationDecision, 'allow'>
  eventCode: string
  title: string
  message: string
  canContinue: boolean
  matchedRules: ReputationRuleResult[]
}
type ReputationSettings = {
  enabled: boolean
  warningThreshold: number
  blockedThreshold: number
  disabledRuleIds: ReputationRuleId[]
  ruleWeights: Partial<Record<ReputationRuleId, number>>
  youngDomainMaxAgeDays: number
  googleSafeBrowsingApiKeyConfigured: boolean
}
type RdapBootstrap = {
  services: Array<[string[], string[]]>
}
type CachedDomainAgeEntry = {
  cachedAt: number
  ageDays: number | null
}
type CachedSafeBrowsingEntry = {
  expiresAt: number
  match: {
    threatType: string
    platformType: string
    cacheDurationMs: number
  } | null
}
type DnsFailureState = {
  url: string
  eventCode: 'no-dns-found'
}
type DomainBlocklistSource = {
  id: string
  url: string
  enabled: boolean
  scoreDelta: number
  isDefault: boolean
  createdAt: string
  updatedAt: string
}
type BrowserSettings = {
  accessibility: AccessibilitySettings
  adminSecurity: AdminSecurityStore
  domainBlocklistSources: DomainBlocklistSource[]
  googleSafeBrowsingApiKey: string | null
  reputation: ReputationSettings
}

let mainWindow: BrowserWindow | null = null
let browserView: WebContentsView | null = null
let permissionPromptWindow: BrowserWindow | null = null
let browserMode: BrowserMode = 'home'
let lastError: string | null = null
let browserChromeHeight = 122
let browserCssKey: string | null = null
let browserFaviconUrl: string | null = null
let allowedBrowserNavigationUrl: string | null = null
let reputationInterventionState: ReputationInterventionState | null = null
let dnsFailureState: DnsFailureState | null = null
let continuedWarningNavigationUrl: string | null = null
let userStore: UserStore | null = null
let userKeyStore: UserKeyStore | null = null
let userMediaPermissionStore: UserMediaPermissionStore | null = null
let userFavoritesStore: UserFavoritesStore | null = null
let browserSettingsStore: BrowserSettings | null = null
let isAdminSessionUnlocked = false
const pendingMediaPermissionRequests = new Map<string, Promise<PermissionPromptAction>>()
const faviconDataUrlCache = new Map<string, string | null>()
const pageFaviconCache = new Map<string, string>()
const domainAgeCache = new Map<string, CachedDomainAgeEntry>()
const googleSafeBrowsingCache = new Map<string, CachedSafeBrowsingEntry>()
let rdapBootstrapCache: RdapBootstrap | null = null

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
const ADMIN_PIN_ATTEMPT_LIMIT = 5
const ADMIN_PIN_LOCK_MS = 60_000
const DOMAIN_BLOCKLIST_FETCH_TIMEOUT_MS = 8_000
const DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA = 100
const DEFAULT_NON_LATIN_SCRIPT_SCORE_DELTA = 25
const DEFAULT_IP_ADDRESS_SCORE_DELTA = 40
const DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA = 100
const DEFAULT_YOUNG_DOMAIN_SCORE_DELTA = 35
const DEFAULT_YOUNG_DOMAIN_MAX_AGE_DAYS = 30
const DEFAULT_REPUTATION_WARNING_THRESHOLD = 50
const DEFAULT_REPUTATION_BLOCKED_THRESHOLD = 70
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
const RDAP_FETCH_TIMEOUT_MS = 5_000
const RDAP_DOMAIN_AGE_CACHE_TTL_MS = 1000 * 60 * 60 * 12
const GOOGLE_SAFE_BROWSING_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find'
const GOOGLE_SAFE_BROWSING_FETCH_TIMEOUT_MS = 5_000
const GOOGLE_SAFE_BROWSING_NEGATIVE_CACHE_MS = 1000 * 60 * 5
const DEFAULT_DOMAIN_BLOCKLIST_CREATED_AT = '2026-07-08T00:00:00.000Z'
const DEFAULT_DOMAIN_BLOCKLIST_SOURCES: DomainBlocklistSource[] = [
  {
    id: 'default-cert-hole',
    url: 'https://hole.cert.pl/domains/v2/domains.txt',
    enabled: true,
    scoreDelta: DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA,
    isDefault: true,
    createdAt: DEFAULT_DOMAIN_BLOCKLIST_CREATED_AT,
    updatedAt: DEFAULT_DOMAIN_BLOCKLIST_CREATED_AT
  },
  {
    id: 'default-urlhaus-online',
    url: 'https://urlhaus.abuse.ch/downloads/text_online/',
    enabled: true,
    scoreDelta: DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA,
    isDefault: true,
    createdAt: DEFAULT_DOMAIN_BLOCKLIST_CREATED_AT,
    updatedAt: DEFAULT_DOMAIN_BLOCKLIST_CREATED_AT
  }
]

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

function getBrowserSettingsPath(): string {
  return path.join(app.getPath('userData'), 'browser-settings.json')
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

function normalizeAdminSecurityStore(value: unknown): AdminSecurityStore {
  if (!value || typeof value !== 'object') {
    return {
      pinSalt: null,
      pinHash: null,
      failedAttempts: 0,
      lockedUntil: null
    }
  }

  const nextValue = value as Partial<AdminSecurityStore>

  return {
    pinSalt: typeof nextValue.pinSalt === 'string' && nextValue.pinSalt.length > 0 ? nextValue.pinSalt : null,
    pinHash: typeof nextValue.pinHash === 'string' && nextValue.pinHash.length > 0 ? nextValue.pinHash : null,
    failedAttempts:
      typeof nextValue.failedAttempts === 'number' && Number.isFinite(nextValue.failedAttempts)
        ? Math.max(0, Math.floor(nextValue.failedAttempts))
        : 0,
    lockedUntil: typeof nextValue.lockedUntil === 'string' && nextValue.lockedUntil.length > 0
      ? nextValue.lockedUntil
      : null
  }
}

function loadAdminSecurityStore(): AdminSecurityStore {
  return loadBrowserSettings().adminSecurity
}

function saveAdminSecurityStore(value: AdminSecurityStore): void {
  saveBrowserSettings({
    ...loadBrowserSettings(),
    adminSecurity: normalizeAdminSecurityStore(value)
  })
}

function isAdminPinSet(store: AdminSecurityStore = loadAdminSecurityStore()): boolean {
  return typeof store.pinSalt === 'string' && typeof store.pinHash === 'string'
}

function getAdminPinLockTimestamp(store: AdminSecurityStore = loadAdminSecurityStore()): number | null {
  if (!store.lockedUntil) {
    return null
  }

  const lockTimestamp = Date.parse(store.lockedUntil)
  return Number.isFinite(lockTimestamp) ? lockTimestamp : null
}

function clearExpiredAdminPinLock(): AdminSecurityStore {
  const store = loadAdminSecurityStore()
  const lockTimestamp = getAdminPinLockTimestamp(store)

  if (!lockTimestamp || lockTimestamp > Date.now()) {
    return store
  }

  const nextStore: AdminSecurityStore = {
    ...store,
    failedAttempts: 0,
    lockedUntil: null
  }
  saveAdminSecurityStore(nextStore)
  return nextStore
}

function getAdminPinStatus(): AdminPinStatus {
  const store = clearExpiredAdminPinLock()
  const remainingAttempts = isAdminPinSet(store)
    ? Math.max(0, ADMIN_PIN_ATTEMPT_LIMIT - store.failedAttempts)
    : ADMIN_PIN_ATTEMPT_LIMIT

  return {
    isSet: isAdminPinSet(store),
    isSessionUnlocked: isAdminSessionUnlocked,
    failedAttempts: store.failedAttempts,
    remainingAttempts,
    lockedUntil: store.lockedUntil
  }
}

function validateAdminPin(pin: string): string {
  const normalizedValue = pin.trim()

  if (!/^\d{4,6}$/.test(normalizedValue)) {
    throw new Error('PIN administratora musi mieć od 4 do 6 cyfr.')
  }

  return normalizedValue
}

function hashAdminPin(pin: string, salt: string): string {
  return scryptSync(pin, salt, 64).toString('base64')
}

function setAdminPin(pin: string): AdminPinStatus {
  const normalizedPin = validateAdminPin(pin)
  const currentStore = loadAdminSecurityStore()

  if (isAdminPinSet(currentStore)) {
    throw new Error('PIN administratora jest już ustawiony.')
  }

  const nextStore: AdminSecurityStore = {
    pinSalt: randomBytes(16).toString('base64'),
    pinHash: null,
    failedAttempts: 0,
    lockedUntil: null
  }
  const nextSalt = nextStore.pinSalt
  nextStore.pinHash = nextSalt ? hashAdminPin(normalizedPin, nextSalt) : null
  saveAdminSecurityStore(nextStore)
  isAdminSessionUnlocked = true

  return getAdminPinStatus()
}

function verifyAdminPin(pin: string): AdminPinStatus {
  const normalizedPin = validateAdminPin(pin)
  const currentStore = clearExpiredAdminPinLock()

  if (!isAdminPinSet(currentStore)) {
    throw new Error('PIN administratora nie jest jeszcze ustawiony.')
  }

  const lockTimestamp = getAdminPinLockTimestamp(currentStore)

  if (lockTimestamp && lockTimestamp > Date.now()) {
    throw new Error('Panel administracyjny jest chwilowo zablokowany. Spróbuj ponownie za chwilę.')
  }

  const currentPinHash = currentStore.pinHash
  const currentPinSalt = currentStore.pinSalt

  if (!currentPinHash || !currentPinSalt) {
    throw new Error('PIN administratora nie jest jeszcze ustawiony.')
  }

  const expectedHash = Buffer.from(currentPinHash, 'base64')
  const candidateHash = Buffer.from(hashAdminPin(normalizedPin, currentPinSalt), 'base64')

  if (expectedHash.length === candidateHash.length && timingSafeEqual(expectedHash, candidateHash)) {
    saveAdminSecurityStore({
      ...currentStore,
      failedAttempts: 0,
      lockedUntil: null
    })
    isAdminSessionUnlocked = true
    return getAdminPinStatus()
  }

  const nextFailedAttempts = currentStore.failedAttempts + 1
  const nextStore: AdminSecurityStore = {
    ...currentStore,
    failedAttempts: nextFailedAttempts,
    lockedUntil:
      nextFailedAttempts >= ADMIN_PIN_ATTEMPT_LIMIT
        ? new Date(Date.now() + ADMIN_PIN_LOCK_MS).toISOString()
        : null
  }
  saveAdminSecurityStore(nextStore)
  isAdminSessionUnlocked = false

  if (nextStore.lockedUntil) {
    throw new Error('Zbyt wiele nieudanych prób. Panel administracyjny został chwilowo zablokowany.')
  }

  throw new Error('Nieprawidłowy PIN administratora.')
}

function clearAdminPinSession(): AdminPinStatus {
  isAdminSessionUnlocked = false
  return getAdminPinStatus()
}

function normalizeAccessibilitySettings(value: unknown): AccessibilitySettings {
  if (!value || typeof value !== 'object') {
    return {
      visibleFocus: true
    }
  }

  const nextValue = value as Partial<AccessibilitySettings>

  return {
    visibleFocus: typeof nextValue.visibleFocus === 'boolean' ? nextValue.visibleFocus : true
  }
}

function normalizeReputationSettings(value: unknown): ReputationSettings {
  if (!value || typeof value !== 'object') {
    return {
      enabled: true,
      warningThreshold: DEFAULT_REPUTATION_WARNING_THRESHOLD,
      blockedThreshold: DEFAULT_REPUTATION_BLOCKED_THRESHOLD,
      disabledRuleIds: [],
      ruleWeights: {
        'non-latin-script': DEFAULT_NON_LATIN_SCRIPT_SCORE_DELTA,
        'is-ip': DEFAULT_IP_ADDRESS_SCORE_DELTA,
        'google-safe-browsing': DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA
      },
      youngDomainMaxAgeDays: DEFAULT_YOUNG_DOMAIN_MAX_AGE_DAYS,
      googleSafeBrowsingApiKeyConfigured: false
    }
  }

  const nextValue = value as Partial<ReputationSettings>
  const disabledRuleIds = Array.isArray(nextValue.disabledRuleIds)
    ? nextValue.disabledRuleIds.filter((value): value is ReputationRuleId => {
        return (
          value === 'insecure-http' ||
          value === 'domain-blocklist' ||
          value === 'non-latin-script' ||
          value === 'is-ip' ||
          value === 'google-safe-browsing' ||
          value === 'young-domain-age'
        )
      })
    : []
  const nextRuleWeights = nextValue.ruleWeights && typeof nextValue.ruleWeights === 'object'
    ? nextValue.ruleWeights
    : {}

  return {
    enabled: typeof nextValue.enabled === 'boolean' ? nextValue.enabled : true,
    warningThreshold:
      typeof nextValue.warningThreshold === 'number' && Number.isFinite(nextValue.warningThreshold)
        ? Math.max(0, Math.floor(nextValue.warningThreshold))
        : DEFAULT_REPUTATION_WARNING_THRESHOLD,
    blockedThreshold:
      typeof nextValue.blockedThreshold === 'number' && Number.isFinite(nextValue.blockedThreshold)
        ? Math.max(0, Math.floor(nextValue.blockedThreshold))
        : DEFAULT_REPUTATION_BLOCKED_THRESHOLD,
    disabledRuleIds,
    ruleWeights: {
      'insecure-http':
        typeof nextRuleWeights['insecure-http'] === 'number' &&
        Number.isFinite(nextRuleWeights['insecure-http'])
          ? Math.max(0, Math.floor(nextRuleWeights['insecure-http']))
          : undefined,
      'domain-blocklist':
        typeof nextRuleWeights['domain-blocklist'] === 'number' &&
        Number.isFinite(nextRuleWeights['domain-blocklist'])
          ? Math.max(0, Math.floor(nextRuleWeights['domain-blocklist']))
          : undefined,
      'non-latin-script':
        typeof nextRuleWeights['non-latin-script'] === 'number' &&
        Number.isFinite(nextRuleWeights['non-latin-script'])
          ? Math.max(0, Math.floor(nextRuleWeights['non-latin-script']))
          : DEFAULT_NON_LATIN_SCRIPT_SCORE_DELTA,
      'is-ip':
        typeof nextRuleWeights['is-ip'] === 'number' &&
        Number.isFinite(nextRuleWeights['is-ip'])
          ? Math.max(0, Math.floor(nextRuleWeights['is-ip']))
          : DEFAULT_IP_ADDRESS_SCORE_DELTA,
      'google-safe-browsing':
        typeof nextRuleWeights['google-safe-browsing'] === 'number' &&
        Number.isFinite(nextRuleWeights['google-safe-browsing'])
          ? Math.max(0, Math.floor(nextRuleWeights['google-safe-browsing']))
          : DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA,
      'young-domain-age':
        typeof nextRuleWeights['young-domain-age'] === 'number' &&
        Number.isFinite(nextRuleWeights['young-domain-age'])
          ? Math.max(0, Math.floor(nextRuleWeights['young-domain-age']))
          : DEFAULT_YOUNG_DOMAIN_SCORE_DELTA
    },
    youngDomainMaxAgeDays:
      typeof nextValue.youngDomainMaxAgeDays === 'number' &&
      Number.isFinite(nextValue.youngDomainMaxAgeDays)
        ? Math.max(1, Math.floor(nextValue.youngDomainMaxAgeDays))
        : DEFAULT_YOUNG_DOMAIN_MAX_AGE_DAYS,
    googleSafeBrowsingApiKeyConfigured: false
  }
}

function normalizeDomainBlocklistSourceUrl(value: string): string | null {
  const trimmed = value.trim()

  if (trimmed.length === 0) {
    return null
  }

  try {
    const parsedUrl = new URL(trimmed)

    if (parsedUrl.protocol !== 'https:') {
      return null
    }

    parsedUrl.hash = ''
    return parsedUrl.toString()
  } catch {
    return null
  }
}

function normalizeDomainBlocklistSource(
  value: unknown,
  fallback: DomainBlocklistSource
): DomainBlocklistSource {
  if (!value || typeof value !== 'object') {
    return fallback
  }

  const nextValue = value as Partial<DomainBlocklistSource>
  const normalizedUrl =
    typeof nextValue.url === 'string'
      ? normalizeDomainBlocklistSourceUrl(nextValue.url)
      : normalizeDomainBlocklistSourceUrl(fallback.url)

  return {
    id:
      typeof nextValue.id === 'string' && nextValue.id.trim().length > 0
        ? nextValue.id.trim()
        : fallback.id,
    url: normalizedUrl ?? fallback.url,
    enabled: typeof nextValue.enabled === 'boolean' ? nextValue.enabled : fallback.enabled,
    scoreDelta:
      typeof nextValue.scoreDelta === 'number' && Number.isFinite(nextValue.scoreDelta)
        ? Math.max(0, Math.floor(nextValue.scoreDelta))
        : fallback.scoreDelta,
    isDefault: typeof nextValue.isDefault === 'boolean' ? nextValue.isDefault : fallback.isDefault,
    createdAt:
      typeof nextValue.createdAt === 'string' && nextValue.createdAt.length > 0
        ? nextValue.createdAt
        : fallback.createdAt,
    updatedAt:
      typeof nextValue.updatedAt === 'string' && nextValue.updatedAt.length > 0
        ? nextValue.updatedAt
        : fallback.updatedAt
  }
}

function normalizeDomainBlocklistSources(value: unknown): DomainBlocklistSource[] {
  const normalizedEntries: DomainBlocklistSource[] = []
  const urlToIndex = new Map<string, number>()

  for (const defaultSource of DEFAULT_DOMAIN_BLOCKLIST_SOURCES) {
    urlToIndex.set(defaultSource.url, normalizedEntries.length)
    normalizedEntries.push({ ...defaultSource })
  }

  if (Array.isArray(value)) {
    for (const rawEntry of value) {
      const fallbackSource: DomainBlocklistSource = {
        id: `domain-blocklist-${randomUUID()}`,
        url: DEFAULT_DOMAIN_BLOCKLIST_SOURCES[0]?.url ?? 'https://example.com',
        enabled: true,
        scoreDelta: DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA,
        isDefault: false,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      }
      const nextEntry = normalizeDomainBlocklistSource(rawEntry, fallbackSource)
      const normalizedUrl = normalizeDomainBlocklistSourceUrl(nextEntry.url)

      if (!normalizedUrl) {
        continue
      }

      const existingIndex = urlToIndex.get(normalizedUrl)

      if (typeof existingIndex === 'number') {
        const existingEntry = normalizedEntries[existingIndex]
        normalizedEntries[existingIndex] = {
          ...existingEntry,
          enabled: nextEntry.enabled,
          scoreDelta: nextEntry.scoreDelta,
          updatedAt: nextEntry.updatedAt
        }
        continue
      }

      urlToIndex.set(normalizedUrl, normalizedEntries.length)
      normalizedEntries.push({
        ...nextEntry,
        url: normalizedUrl
      })
    }
  }

  return normalizedEntries
}

function normalizeBrowserSettings(value: unknown): BrowserSettings {
  if (!value || typeof value !== 'object') {
    return {
      accessibility: normalizeAccessibilitySettings(null),
      adminSecurity: normalizeAdminSecurityStore(null),
      domainBlocklistSources: normalizeDomainBlocklistSources(null),
      googleSafeBrowsingApiKey: null,
      reputation: normalizeReputationSettings(null)
    }
  }

  const nextValue = value as Partial<BrowserSettings> & {
    accessibility?: unknown
    adminSecurity?: unknown
    domainBlocklistSources?: unknown
    googleSafeBrowsingApiKey?: unknown
    reputation?: unknown
  }

  return {
    accessibility: normalizeAccessibilitySettings(nextValue.accessibility),
    adminSecurity: normalizeAdminSecurityStore(nextValue.adminSecurity),
    domainBlocklistSources: normalizeDomainBlocklistSources(nextValue.domainBlocklistSources),
    googleSafeBrowsingApiKey:
      typeof nextValue.googleSafeBrowsingApiKey === 'string' &&
      nextValue.googleSafeBrowsingApiKey.trim().length > 0
        ? nextValue.googleSafeBrowsingApiKey.trim()
        : null,
    reputation: normalizeReputationSettings(nextValue.reputation)
  }
}

function encryptBrowserSettingsPayload(payload: string): string {
  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  return safeStorage.encryptString(payload).toString('base64')
}

function decryptBrowserSettingsPayload(payload: string): string {
  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  return safeStorage.decryptString(Buffer.from(payload, 'base64'))
}

function encryptUserStorePayload(payload: string): string {
  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  return safeStorage.encryptString(payload).toString('base64')
}

function decryptUserStorePayload(payload: string): string {
  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  return safeStorage.decryptString(Buffer.from(payload, 'base64'))
}

function loadBrowserSettings(): BrowserSettings {
  if (browserSettingsStore) {
    return browserSettingsStore
  }

  const filePath = getBrowserSettingsPath()

  try {
    if (fs.existsSync(filePath)) {
      const encryptedPayload = fs.readFileSync(filePath, 'utf8')
      const decryptedPayload = decryptBrowserSettingsPayload(encryptedPayload)
      const rawValue = JSON.parse(decryptedPayload) as unknown
      browserSettingsStore = normalizeBrowserSettings(rawValue)
      return browserSettingsStore
    }
  } catch {
    // Fall back to defaults when browser settings cannot be read.
  }

  browserSettingsStore = normalizeBrowserSettings(null)
  return browserSettingsStore
}

function saveBrowserSettings(value: BrowserSettings): BrowserSettings {
  browserSettingsStore = normalizeBrowserSettings(value)
  const encryptedPayload = encryptBrowserSettingsPayload(
    JSON.stringify(browserSettingsStore, null, 2)
  )
  fs.writeFileSync(getBrowserSettingsPath(), encryptedPayload, 'utf8')
  return browserSettingsStore
}

function loadAccessibilitySettings(): AccessibilitySettings {
  return loadBrowserSettings().accessibility
}

function setVisibleFocusSetting(visibleFocus: boolean): AccessibilitySettings {
  const nextBrowserSettings = saveBrowserSettings({
    ...loadBrowserSettings(),
    accessibility: {
      ...loadAccessibilitySettings(),
      visibleFocus
    }
  })
  return nextBrowserSettings.accessibility
}

function loadDomainBlocklistSources(): DomainBlocklistSource[] {
  return loadBrowserSettings().domainBlocklistSources
}

function saveDomainBlocklistSources(value: DomainBlocklistSource[]): DomainBlocklistSource[] {
  const nextBrowserSettings = saveBrowserSettings({
    ...loadBrowserSettings(),
    domainBlocklistSources: normalizeDomainBlocklistSources(value)
  })

  return nextBrowserSettings.domainBlocklistSources
}

function validateDomainBlocklistSourceUrl(value: string): string {
  const normalizedUrl = normalizeDomainBlocklistSourceUrl(value)

  if (!normalizedUrl) {
    throw new Error('Adres listy musi być poprawnym adresem HTTPS.')
  }

  return normalizedUrl
}

function addDomainBlocklistSource(value: string): DomainBlocklistSource[] {
  const normalizedUrl = validateDomainBlocklistSourceUrl(value)
  const currentSources = loadDomainBlocklistSources()
  const existingEntry = currentSources.find((entry) => entry.url === normalizedUrl)

  if (existingEntry) {
    return saveDomainBlocklistSources(
      currentSources.map((entry) =>
        entry.url === normalizedUrl
          ? {
              ...entry,
              enabled: true,
              updatedAt: new Date().toISOString()
            }
          : entry
      )
    )
  }

  const now = new Date().toISOString()
  return saveDomainBlocklistSources([
    ...currentSources,
    {
      id: `domain-blocklist-${randomUUID()}`,
      url: normalizedUrl,
      enabled: true,
      scoreDelta: DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA,
      isDefault: false,
      createdAt: now,
      updatedAt: now
    }
  ])
}

function setDomainBlocklistSourceEnabled(id: string, enabled: boolean): DomainBlocklistSource[] {
  const currentSources = loadDomainBlocklistSources()
  const sourceExists = currentSources.some((entry) => entry.id === id)

  if (!sourceExists) {
    throw new Error('Nie znaleziono wskazanej listy ostrzeżeń.')
  }

  return saveDomainBlocklistSources(
    currentSources.map((entry) =>
      entry.id === id
        ? {
            ...entry,
            enabled,
            updatedAt: new Date().toISOString()
          }
        : entry
    )
  )
}

function setDomainBlocklistSourceScoreDelta(id: string, scoreDelta: number): DomainBlocklistSource[] {
  const currentSources = loadDomainBlocklistSources()
  const sourceExists = currentSources.some((entry) => entry.id === id)

  if (!sourceExists) {
    throw new Error('Nie znaleziono wskazanej listy ostrzeżeń.')
  }

  const normalizedScoreDelta = Math.max(0, Math.floor(scoreDelta))

  return saveDomainBlocklistSources(
    currentSources.map((entry) =>
      entry.id === id
        ? {
            ...entry,
            scoreDelta: normalizedScoreDelta,
            updatedAt: new Date().toISOString()
          }
        : entry
    )
  )
}

function removeDomainBlocklistSource(id: string): DomainBlocklistSource[] {
  const currentSources = loadDomainBlocklistSources()
  const sourceToRemove = currentSources.find((entry) => entry.id === id)

  if (!sourceToRemove) {
    throw new Error('Nie znaleziono wskazanej listy ostrzeżeń.')
  }

  if (sourceToRemove.isDefault) {
    throw new Error('Domyślnej listy ostrzeżeń nie można usunąć.')
  }

  return saveDomainBlocklistSources(currentSources.filter((entry) => entry.id !== id))
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

function normalizeHostname(value: string): string | null {
  const trimmed = value.trim().toLowerCase().replace(/\.+$/g, '').replace(/^\*\./, '').replace(/^\./, '')

  if (trimmed.length === 0) {
    return null
  }

  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(trimmed)) {
    return trimmed
  }

  if (!/^[a-z0-9.-]+$/i.test(trimmed)) {
    return null
  }

  return trimmed
}

function getHostnameFromUrl(rawUrl: string): string | null {
  try {
    const parsedUrl = new URL(rawUrl)
    return normalizeHostname(parsedUrl.hostname)
  } catch {
    return null
  }
}

function loadReputationSettings(): ReputationSettings {
  return {
    ...loadBrowserSettings().reputation,
    googleSafeBrowsingApiKeyConfigured: hasGoogleSafeBrowsingApiKey()
  }
}

function saveReputationSettings(value: ReputationSettings): ReputationSettings {
  const nextBrowserSettings = saveBrowserSettings({
    ...loadBrowserSettings(),
    reputation: normalizeReputationSettings(value)
  })

  return {
    ...nextBrowserSettings.reputation,
    googleSafeBrowsingApiKeyConfigured: hasGoogleSafeBrowsingApiKey(nextBrowserSettings)
  }
}

function updateReputationSettings(
  value: Partial<
    Pick<
      ReputationSettings,
      | 'enabled'
      | 'warningThreshold'
      | 'blockedThreshold'
      | 'ruleWeights'
      | 'youngDomainMaxAgeDays'
      | 'disabledRuleIds'
    >
  >
): ReputationSettings {
  const currentSettings = loadReputationSettings()
  return saveReputationSettings({
    ...currentSettings,
    ...value,
    ruleWeights: {
      ...currentSettings.ruleWeights,
      ...(value.ruleWeights ?? {})
    }
  })
}

function hasGoogleSafeBrowsingApiKey(
  settings: BrowserSettings = loadBrowserSettings()
): boolean {
  return typeof settings.googleSafeBrowsingApiKey === 'string' && settings.googleSafeBrowsingApiKey.length > 0
}

function getGoogleSafeBrowsingApiKey(): string | null {
  return loadBrowserSettings().googleSafeBrowsingApiKey
}

function setGoogleSafeBrowsingApiKey(value: string | null): ReputationSettings {
  const normalizedValue =
    typeof value === 'string' && value.trim().length > 0 ? value.trim() : null

  const nextBrowserSettings = saveBrowserSettings({
    ...loadBrowserSettings(),
    googleSafeBrowsingApiKey: normalizedValue
  })

  googleSafeBrowsingCache.clear()

  return {
    ...nextBrowserSettings.reputation,
    googleSafeBrowsingApiKeyConfigured: Boolean(normalizedValue)
  }
}

function getDomainBlocklistEventCode(sourceUrl: string): string {
  const sourceHostname = getHostnameFromUrl(sourceUrl) ?? 'unknown-source'
  return `phising-detected-list-filter:${sourceHostname}`
}

function extractDomainBlocklistHostnames(payload: string): Set<string> {
  const hostnames = new Set<string>()

  for (const rawLine of payload.split(/\r?\n/)) {
    const commentIndex = rawLine.indexOf('#')
    const line = (commentIndex >= 0 ? rawLine.slice(0, commentIndex) : rawLine).trim()

    if (line.length === 0) {
      continue
    }

    const tokens = line.split(/\s+/).filter(Boolean)

    for (const token of tokens) {
      let nextHostname: string | null = null

      if (/^https?:\/\//i.test(token)) {
        nextHostname = getHostnameFromUrl(token)
      } else {
        nextHostname = normalizeHostname(token)
      }

      if (nextHostname) {
        hostnames.add(nextHostname)
      }
    }
  }

  return hostnames
}

function isHostnameBlocked(hostname: string, blockedEntries: Set<string>): string | null {
  for (const blockedEntry of blockedEntries) {
    if (hostname === blockedEntry || hostname.endsWith(`.${blockedEntry}`)) {
      return blockedEntry
    }
  }

  return null
}

function setReputationIntervention(value: ReputationInterventionState | null): void {
  reputationInterventionState = value
  updateBrowserBounds()
}

function setDnsFailure(value: DnsFailureState | null): void {
  dnsFailureState = value
  updateBrowserBounds()
}

function isDnsResolutionFailure(errorCode: number, errorDescription: string): boolean {
  return (
    errorCode === -105 ||
    errorCode === -137 ||
    errorDescription.includes('ERR_NAME_NOT_RESOLVED')
  )
}

function isDnsResolutionError(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false
  }

  return (
    error.message.includes('ERR_NAME_NOT_RESOLVED') ||
    error.message.includes('net_error -105') ||
    error.message.includes('net_error -100')
  )
}

async function fetchDomainBlocklistSourceEntries(source: DomainBlocklistSource): Promise<Set<string>> {
  const response = await fetch(source.url, {
    cache: 'no-store',
    signal: AbortSignal.timeout(DOMAIN_BLOCKLIST_FETCH_TIMEOUT_MS)
  })

  if (!response.ok) {
    throw new Error(`Nie udało się pobrać listy ostrzeżeń: ${source.url}`)
  }

  const payload = await response.text()
  return extractDomainBlocklistHostnames(payload)
}

function normalizeSiteCandidate(rawUrl: string): NormalizedSiteCandidate {
  const parsedUrl = new URL(rawUrl)
  const asciiHostname = normalizeHostname(parsedUrl.hostname)

  if (!asciiHostname) {
    throw new Error(`Nie udało się znormalizować hosta dla adresu: ${rawUrl}`)
  }

  const unicodeHostname = domainToUnicode(asciiHostname).toLowerCase() || asciiHostname

  return {
    rawUrl,
    normalizedUrl: parsedUrl.toString(),
    protocol: parsedUrl.protocol as 'http:' | 'https:',
    hostname: asciiHostname,
    asciiHostname,
    unicodeHostname,
    registrableDomain: getDomain(asciiHostname) ?? null,
    publicSuffix: getPublicSuffix(asciiHostname) ?? null,
    subdomain: getSubdomain(asciiHostname) || null,
    isIp: isIP(asciiHostname) !== 0,
    port: parsedUrl.port || null,
    path: parsedUrl.pathname,
    query: parsedUrl.search
  }
}

function getRuleScoreDelta(
  ruleId: ReputationRuleId,
  fallbackScoreDelta: number,
  settings: ReputationSettings
): number {
  return settings.ruleWeights[ruleId] ?? fallbackScoreDelta
}

function hasNonLatinLetters(value: string): boolean {
  for (const char of value) {
    if (!/\p{Letter}/u.test(char)) {
      continue
    }

    if (!/\p{Script=Latin}/u.test(char)) {
      return true
    }
  }

  return false
}

async function loadRdapBootstrap(): Promise<RdapBootstrap> {
  if (rdapBootstrapCache) {
    return rdapBootstrapCache
  }

  const response = await fetch(RDAP_BOOTSTRAP_URL, {
    cache: 'force-cache',
    signal: AbortSignal.timeout(RDAP_FETCH_TIMEOUT_MS)
  })

  if (!response.ok) {
    throw new Error('Nie udało się pobrać konfiguracji RDAP.')
  }

  const payload = (await response.json()) as Partial<RdapBootstrap>
  rdapBootstrapCache = {
    services: Array.isArray(payload.services) ? payload.services : []
  }
  return rdapBootstrapCache
}

function getRdapBaseUrlForDomain(domain: string, bootstrap: RdapBootstrap): string | null {
  const labels = domain.toLowerCase().split('.').filter(Boolean)

  for (let index = 0; index < labels.length; index += 1) {
    const suffix = labels.slice(index).join('.')

    for (const service of bootstrap.services) {
      const [tlds, baseUrls] = service

      if (!Array.isArray(tlds) || !Array.isArray(baseUrls) || baseUrls.length === 0) {
        continue
      }

      if (tlds.some((tld) => typeof tld === 'string' && tld.toLowerCase() === suffix)) {
        return baseUrls[0] ?? null
      }
    }
  }

  return null
}

function parseRdapEventDate(payload: unknown): Date | null {
  if (!payload || typeof payload !== 'object') {
    return null
  }

  const events = (payload as { events?: unknown }).events

  if (!Array.isArray(events)) {
    return null
  }

  const matchingEvent = events.find((event) => {
    if (!event || typeof event !== 'object') {
      return false
    }

    const eventAction = (event as { eventAction?: unknown }).eventAction
    return eventAction === 'registration' || eventAction === 'registered'
  }) as { eventDate?: unknown } | undefined

  if (!matchingEvent || typeof matchingEvent.eventDate !== 'string') {
    return null
  }

  const timestamp = Date.parse(matchingEvent.eventDate)
  return Number.isFinite(timestamp) ? new Date(timestamp) : null
}

async function getDomainAgeInDays(domain: string): Promise<number | null> {
  const cachedEntry = domainAgeCache.get(domain)

  if (cachedEntry && Date.now() - cachedEntry.cachedAt < RDAP_DOMAIN_AGE_CACHE_TTL_MS) {
    return cachedEntry.ageDays
  }

  try {
    const bootstrap = await loadRdapBootstrap()
    const baseUrl = getRdapBaseUrlForDomain(domain, bootstrap)

    if (!baseUrl) {
      domainAgeCache.set(domain, { cachedAt: Date.now(), ageDays: null })
      return null
    }

    const rdapUrl = new URL(`domain/${domain}`, baseUrl).toString()
    const response = await fetch(rdapUrl, {
      cache: 'no-store',
      signal: AbortSignal.timeout(RDAP_FETCH_TIMEOUT_MS),
      headers: {
        accept: 'application/rdap+json, application/json'
      }
    })

    if (!response.ok) {
      domainAgeCache.set(domain, { cachedAt: Date.now(), ageDays: null })
      return null
    }

    const payload = await response.json()
    const createdAt = parseRdapEventDate(payload)

    if (!createdAt) {
      domainAgeCache.set(domain, { cachedAt: Date.now(), ageDays: null })
      return null
    }

    const ageDays = Math.max(0, Math.floor((Date.now() - createdAt.getTime()) / (1000 * 60 * 60 * 24)))
    domainAgeCache.set(domain, { cachedAt: Date.now(), ageDays })
    return ageDays
  } catch {
    domainAgeCache.set(domain, { cachedAt: Date.now(), ageDays: null })
    return null
  }
}

function parseGoogleSafeBrowsingCacheDurationMs(value: unknown): number {
  if (typeof value !== 'string') {
    return GOOGLE_SAFE_BROWSING_NEGATIVE_CACHE_MS
  }

  const match = /^([0-9]+(?:\.[0-9]+)?)s$/.exec(value)

  if (!match) {
    return GOOGLE_SAFE_BROWSING_NEGATIVE_CACHE_MS
  }

  return Math.max(1000, Math.floor(Number(match[1]) * 1000))
}

async function lookupGoogleSafeBrowsingMatch(
  normalizedUrl: string
): Promise<CachedSafeBrowsingEntry['match']> {
  const apiKey = getGoogleSafeBrowsingApiKey()

  if (!apiKey) {
    return null
  }

  const cachedEntry = googleSafeBrowsingCache.get(normalizedUrl)

  if (cachedEntry && cachedEntry.expiresAt > Date.now()) {
    return cachedEntry.match
  }

  try {
    const requestUrl = `${GOOGLE_SAFE_BROWSING_ENDPOINT}?key=${encodeURIComponent(apiKey)}`
    const response = await fetch(requestUrl, {
      method: 'POST',
      signal: AbortSignal.timeout(GOOGLE_SAFE_BROWSING_FETCH_TIMEOUT_MS),
      headers: {
        'content-type': 'application/json'
      },
      body: JSON.stringify({
        client: {
          clientId: 'easybrowser',
          clientVersion: app.getVersion()
        },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url: normalizedUrl }]
        }
      })
    })

    if (!response.ok) {
      return null
    }

    const payload = (await response.json()) as {
      matches?: Array<{
        threatType?: unknown
        platformType?: unknown
        cacheDuration?: unknown
      }>
    }

    const firstMatch = Array.isArray(payload.matches) ? payload.matches[0] : undefined

    if (!firstMatch) {
      googleSafeBrowsingCache.set(normalizedUrl, {
        expiresAt: Date.now() + GOOGLE_SAFE_BROWSING_NEGATIVE_CACHE_MS,
        match: null
      })
      return null
    }

    const match = {
      threatType:
        typeof firstMatch.threatType === 'string' ? firstMatch.threatType : 'UNKNOWN_THREAT',
      platformType:
        typeof firstMatch.platformType === 'string'
          ? firstMatch.platformType
          : 'UNKNOWN_PLATFORM',
      cacheDurationMs: parseGoogleSafeBrowsingCacheDurationMs(firstMatch.cacheDuration)
    }

    googleSafeBrowsingCache.set(normalizedUrl, {
      expiresAt: Date.now() + match.cacheDurationMs,
      match
    })
    return match
  } catch {
    return null
  }
}

async function evaluateInsecureHttpRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  if (candidate.protocol !== 'http:') {
    return null
  }

  return {
    ruleId: 'insecure-http',
    matched: true,
    scoreDelta: getRuleScoreDelta('insecure-http', 50, settings),
    severity: 'warning',
    code: 'http-not-encrypted',
    message:
      'Strona używa połączenia HTTP, więc przesyłane dane nie są chronione tak jak przy HTTPS.'
  }
}

async function evaluateDomainBlocklistRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  const enabledSources = loadDomainBlocklistSources().filter((source) => source.enabled)

  if (enabledSources.length === 0) {
    return null
  }

  const sourceResults = await Promise.all(
    enabledSources.map(async (source) => {
      const blockedEntries = await fetchDomainBlocklistSourceEntries(source)
      return {
        source,
        matchedEntry: isHostnameBlocked(candidate.asciiHostname, blockedEntries)
      }
    })
  )

  const blockedResult = sourceResults.find((result) => typeof result.matchedEntry === 'string')

  if (!blockedResult?.matchedEntry) {
    return null
  }

  return {
    ruleId: 'domain-blocklist',
    matched: true,
    scoreDelta: blockedResult.source.scoreDelta,
    severity: 'blocking',
    code: getDomainBlocklistEventCode(blockedResult.source.url),
    message: `Domena znajduje się na liście ostrzeżeń: ${blockedResult.source.url}`
  }
}

async function evaluateNonLatinScriptRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  if (!hasNonLatinLetters(candidate.unicodeHostname)) {
    return null
  }

  return {
    ruleId: 'non-latin-script',
    matched: true,
    scoreDelta: getRuleScoreDelta(
      'non-latin-script',
      DEFAULT_NON_LATIN_SCRIPT_SCORE_DELTA,
      settings
    ),
    severity: 'warning',
    code: 'non-latin-script-domain',
    message:
      'Domena zawiera litery spoza alfabetu łacińskiego, co może utrudniać rozpoznanie prawdziwego adresu.'
  }
}

async function evaluateIpAddressRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  if (!candidate.isIp) {
    return null
  }

  return {
    ruleId: 'is-ip',
    matched: true,
    scoreDelta: getRuleScoreDelta('is-ip', DEFAULT_IP_ADDRESS_SCORE_DELTA, settings),
    severity: 'warning',
    code: 'ip-address-navigation',
    message:
      'Adres prowadzi bezpośrednio na numer IP zamiast na zwykłą domenę, co bywa częste przy podejrzanych linkach.'
  }
}

async function evaluateGoogleSafeBrowsingRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  const match = await lookupGoogleSafeBrowsingMatch(candidate.normalizedUrl)

  if (!match) {
    return null
  }

  return {
    ruleId: 'google-safe-browsing',
    matched: true,
    scoreDelta: getRuleScoreDelta(
      'google-safe-browsing',
      DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA,
      settings
    ),
    severity: 'blocking',
    code: `google-safe-browsing:${match.threatType.toLowerCase()}`,
    message: `Google Safe Browsing oznaczył ten adres jako ${match.threatType} dla ${match.platformType}.`
  }
}

async function evaluateYoungDomainAgeRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  if (!candidate.registrableDomain || candidate.isIp) {
    return null
  }

  const ageDays = await getDomainAgeInDays(candidate.registrableDomain)

  if (ageDays === null || ageDays > settings.youngDomainMaxAgeDays) {
    return null
  }

  return {
    ruleId: 'young-domain-age',
    matched: true,
    scoreDelta: getRuleScoreDelta(
      'young-domain-age',
      DEFAULT_YOUNG_DOMAIN_SCORE_DELTA,
      settings
    ),
    severity: 'warning',
    code: 'young-domain-rdap',
    message: `Domena ma około ${ageDays} dni i mieści się w progu ${settings.youngDomainMaxAgeDays} dni.`
  }
}

async function assessNavigationReputation(rawUrl: string): Promise<ReputationAssessment> {
  if (!isSafeBrowserUrl(rawUrl)) {
    throw new Error(`Zablokowano niebezpieczny adres: ${rawUrl}`)
  }

  const candidate = normalizeSiteCandidate(rawUrl)
  const settings = loadReputationSettings()

  if (!settings.enabled) {
    return {
      candidate,
      score: 0,
      decision: 'allow',
      matchedRules: []
    }
  }

  const rules = [
    {
      id: 'insecure-http' as const,
      evaluate: evaluateInsecureHttpRule
    },
    {
      id: 'domain-blocklist' as const,
      evaluate: evaluateDomainBlocklistRule
    },
    {
      id: 'non-latin-script' as const,
      evaluate: evaluateNonLatinScriptRule
    },
    {
      id: 'is-ip' as const,
      evaluate: evaluateIpAddressRule
    },
    {
      id: 'google-safe-browsing' as const,
      evaluate: evaluateGoogleSafeBrowsingRule
    },
    {
      id: 'young-domain-age' as const,
      evaluate: evaluateYoungDomainAgeRule
    }
  ]
  const matchedRules: ReputationRuleResult[] = []

  for (const rule of rules) {
    if (settings.disabledRuleIds.includes(rule.id)) {
      continue
    }

    const result = await rule.evaluate(candidate, settings)

    if (result?.matched) {
      matchedRules.push(result)
    }
  }

  const score = matchedRules.reduce((sum, result) => sum + result.scoreDelta, 0)
  const decision: ReputationDecision =
    score >= settings.blockedThreshold
      ? 'blocked'
      : score >= settings.warningThreshold
        ? 'warning'
        : 'allow'

  return {
    candidate,
    score,
    decision,
    matchedRules
  }
}

async function assessReputationPreview(rawUrl: string): Promise<ReputationAssessmentPreview> {
  const assessment = await assessNavigationReputation(rawUrl)

  return {
    normalizedUrl: assessment.candidate.normalizedUrl,
    score: assessment.score,
    decision: assessment.decision,
    matchedRules: assessment.matchedRules
  }
}

function createReputationInterventionState(
  assessment: ReputationAssessment
): ReputationInterventionState | null {
  if (assessment.decision === 'allow' || assessment.matchedRules.length === 0) {
    return null
  }

  const primaryRule = assessment.matchedRules[0]

  if (assessment.decision === 'warning') {
    return {
      url: assessment.candidate.normalizedUrl,
      decision: 'warning',
      eventCode: 'filters-warning',
      title: 'Filtry bezpieczeństwa oznaczyły tę stronę jako potencjalnie niebezpieczną',
      message:
        'Ta strona wygląda podejrzanie według naszych zabezpieczeń. Jeśli jej nie rozpoznajesz albo nie masz do niej pełnego zaufania, lepiej nie kontynuować.',
      canContinue: true,
      matchedRules: assessment.matchedRules
    }
  }

  return {
    url: assessment.candidate.normalizedUrl,
    decision: 'blocked',
    eventCode: 'filters-block',
    title: 'Filtry bezpieczeństwa oznaczyły tę stronę jako niebezpieczną',
    message:
      'Zablokowaliśmy tę stronę, ponieważ nasze zabezpieczenia wykryły wysokie ryzyko. Dzięki temu możesz bezpiecznie wrócić i nie przechodzić dalej.',
    canContinue: false,
    matchedRules: assessment.matchedRules
  }
}

async function shouldAllowNavigation(rawUrl: string): Promise<boolean> {
  const assessment = await assessNavigationReputation(rawUrl)

  if (continuedWarningNavigationUrl === assessment.candidate.normalizedUrl) {
    continuedWarningNavigationUrl = null
    setReputationIntervention(null)
    return true
  }

  const interventionState = createReputationInterventionState(assessment)

  if (!interventionState) {
    setReputationIntervention(null)
    return true
  }

  setReputationIntervention(interventionState)
  lastError = interventionState.message
  sendBrowserState()
  return false
}

async function openExternalUrlIfAllowed(rawUrl: string): Promise<void> {
  try {
    if (!(await shouldAllowNavigation(rawUrl))) {
      return
    }
    setReputationIntervention(null)
    setDnsFailure(null)
    lastError = null
    await shell.openExternal(rawUrl)
  } catch (error) {
    setReputationIntervention(null)
    lastError =
      error instanceof Error ? error.message : 'Nie udało się sprawdzić bezpieczeństwa adresu.'
    sendBrowserState()
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
  setReputationIntervention(null)
  setDnsFailure(null)
  continuedWarningNavigationUrl = null
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
  const encryptedPayload = encryptUserStorePayload(JSON.stringify(store, null, 2))
  fs.writeFileSync(getUserStorePath(), encryptedPayload, 'utf8')
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
      const encryptedPayload = fs.readFileSync(filePath, 'utf8')
      const decryptedPayload = decryptUserStorePayload(encryptedPayload)
      const parsedStore = JSON.parse(decryptedPayload) as UserStore
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

  if (browserMode !== 'browser' || reputationInterventionState || dnsFailureState) {
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
    url: reputationInterventionState?.url ?? dnsFailureState?.url ?? currentUrl,
    title: browserView?.webContents.getTitle() || 'Easybrowser',
    isLoading: browserView?.webContents.isLoading() ?? false,
    canGoBack: browserView?.webContents.navigationHistory.canGoBack() ?? false,
    canGoForward: browserView?.webContents.navigationHistory.canGoForward() ?? false,
    isMaximized: mainWindow.isMaximized(),
    error: lastError,
    hasMicrophoneAccess: mediaAccessState.hasMicrophoneAccess,
    hasCameraAccess: mediaAccessState.hasCameraAccess,
    isFavorite: isFavoriteUrl(activeUserId, currentUrl),
    browserFaviconUrl: reputationInterventionState || dnsFailureState ? null : effectiveBrowserFaviconUrl,
    reputationIntervention: reputationInterventionState,
    dnsFailure: dnsFailureState,
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
      void openExternalUrlIfAllowed(url)
    }

    return { action: 'deny' }
  })

  view.webContents.on('will-navigate', (event, navigationUrl) => {
    if (allowedBrowserNavigationUrl === navigationUrl) {
      allowedBrowserNavigationUrl = null
      return
    }

    event.preventDefault()

    void (async () => {
      try {
        if (!(await shouldAllowNavigation(navigationUrl))) {
          return
        }
        setReputationIntervention(null)
        setDnsFailure(null)
        lastError = null
        allowedBrowserNavigationUrl = navigationUrl
        await view.webContents.loadURL(navigationUrl)
        if (allowedBrowserNavigationUrl === navigationUrl) {
          allowedBrowserNavigationUrl = null
        }
      } catch (error) {
        allowedBrowserNavigationUrl = null
        setReputationIntervention(null)
        setDnsFailure(null)
        lastError =
          error instanceof Error ? error.message : 'Nie udało się otworzyć strony.'
        sendBrowserState()
      }
    })()
  })

  view.webContents.on('did-start-loading', () => {
    syncBrowserState()
  })
  view.webContents.on('did-stop-loading', syncBrowserState)
  view.webContents.on('did-navigate', (_event, navigationUrl) => {
    setDnsFailure(null)
    setReputationIntervention(null)
    applyCachedPageFavicon(navigationUrl, true)
    void updateBrowserFavicon(view)
  })
  view.webContents.on('did-navigate-in-page', (_event, navigationUrl) => {
    setDnsFailure(null)
    setReputationIntervention(null)
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

      if (isDnsResolutionFailure(errorCode, errorDescription)) {
        setReputationIntervention(null)
        setDnsFailure({
          url: validatedURL && validatedURL.length > 0 ? validatedURL : view.webContents.getURL(),
          eventCode: 'no-dns-found'
        })
        lastError = 'Nie udało się znaleźć tej strony w DNS.'
        sendBrowserState()
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
  setReputationIntervention(null)
  setDnsFailure(null)
  lastError = null
  updateBrowserBounds()
  sendBrowserState()

  try {
    if (!(await shouldAllowNavigation(destination))) {
      return
    }
    setReputationIntervention(null)
    setDnsFailure(null)
    allowedBrowserNavigationUrl = destination
    await view.webContents.loadURL(destination)
    if (allowedBrowserNavigationUrl === destination) {
      allowedBrowserNavigationUrl = null
    }
  } catch (error) {
    allowedBrowserNavigationUrl = null
    if (isDnsResolutionError(error)) {
      setReputationIntervention(null)
      setDnsFailure({
        url: destination,
        eventCode: 'no-dns-found'
      })
      lastError = 'Nie udało się znaleźć tej strony w DNS.'
      sendBrowserState()
      return
    } else {
      setReputationIntervention(null)
      setDnsFailure(null)
    }
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
      void openExternalUrlIfAllowed(url)
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
  setReputationIntervention(null)
  setDnsFailure(null)
  continuedWarningNavigationUrl = null
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
  setReputationIntervention(null)
  setDnsFailure(null)
  continuedWarningNavigationUrl = null
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
  setReputationIntervention(null)
  setDnsFailure(null)
  continuedWarningNavigationUrl = null
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
  setReputationIntervention(null)
  setDnsFailure(null)
  continuedWarningNavigationUrl = null
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
  setReputationIntervention(null)
  setDnsFailure(null)
  continuedWarningNavigationUrl = null
  lastError = null
  updateBrowserBounds()
  sendBrowserState()
})

ipcMain.handle('browser:continue-reputation-warning', async () => {
  const pendingUrl = reputationInterventionState?.canContinue ? reputationInterventionState.url : null

  if (!pendingUrl) {
    return
  }

  continuedWarningNavigationUrl = pendingUrl
  await navigateBrowser(pendingUrl)
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

ipcMain.handle('admin:get-pin-status', () => {
  return getAdminPinStatus()
})

ipcMain.handle('admin:set-pin', (_event, pin: string) => {
  return setAdminPin(pin)
})

ipcMain.handle('admin:verify-pin', (_event, pin: string) => {
  return verifyAdminPin(pin)
})

ipcMain.handle('admin:clear-session', () => {
  return clearAdminPinSession()
})

ipcMain.handle('accessibility:get-settings', () => {
  return loadAccessibilitySettings()
})

ipcMain.handle('accessibility:set-visible-focus', (_event, visibleFocus: boolean) => {
  return setVisibleFocusSetting(visibleFocus)
})

ipcMain.handle('reputation:get-settings', () => {
  return loadReputationSettings()
})

ipcMain.handle(
  'reputation:update-settings',
  (
    _event,
    value: Partial<
      Pick<
        ReputationSettings,
        | 'enabled'
        | 'warningThreshold'
        | 'blockedThreshold'
        | 'ruleWeights'
        | 'youngDomainMaxAgeDays'
        | 'disabledRuleIds'
      >
    >
  ) => {
    return updateReputationSettings(value)
  }
)

ipcMain.handle('reputation:set-google-safe-browsing-api-key', (_event, value: string | null) => {
  return setGoogleSafeBrowsingApiKey(value)
})

ipcMain.handle('reputation:assess-url', (_event, rawUrl: string) => {
  return assessReputationPreview(rawUrl)
})

ipcMain.handle('domain-blocklists:get-sources', () => {
  return loadDomainBlocklistSources()
})

ipcMain.handle('domain-blocklists:add-source', (_event, url: string) => {
  return addDomainBlocklistSource(url)
})

ipcMain.handle('domain-blocklists:set-enabled', (_event, id: string, enabled: boolean) => {
  return setDomainBlocklistSourceEnabled(id, enabled)
})

ipcMain.handle('domain-blocklists:set-score-delta', (_event, id: string, scoreDelta: number) => {
  return setDomainBlocklistSourceScoreDelta(id, scoreDelta)
})

ipcMain.handle('domain-blocklists:remove-source', (_event, id: string) => {
  return removeDomainBlocklistSource(id)
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
