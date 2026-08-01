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
import AdmZip from 'adm-zip'
import {
  createHash,
  randomBytes,
  randomUUID,
  scryptSync,
  timingSafeEqual
} from 'node:crypto'
import fs from 'node:fs'
import { isIP } from 'node:net'
import path from 'node:path'
import initSqlJs from 'sql.js'
import { getDomain } from 'tldts'
import {
  getTrustedDomainLookalikeMetadata,
  isLookalikeDomain
} from './lookalike'
import {
  analyzePageContent,
  extractDomainBlocklistHostnames,
  getHostnameFromUrl,
  hasNonLatinLetters,
  isGovernmentDomainCandidate,
  isHostnameBlocked,
  isTrustedDomainMatchAllowed,
  isTrustedDomainEntryMentionedInSubdomain,
  normalizeCustomTrustedDomain,
  normalizeHostname,
  normalizeSiteCandidate,
  type ContentAnalysisFindingId,
  type ContentTrustedBrand,
  type NormalizedSiteCandidate
} from './reputationCore'

type SqlJsModule = Awaited<ReturnType<typeof initSqlJs>>
type SqlJsDatabase = InstanceType<SqlJsModule['Database']>

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

type MediaAccessType = 'audio' | 'video'
type UserMediaPermissionStore = Record<string, Record<string, MediaAccessType[]>>
type FavoriteEntry = {
  url: string
  title: string
  faviconUrl: string | null
  createdAt: string
  updatedAt: string
}
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
  | 'lookalike-trusted-domain'
  | 'trusted-domain-in-subdomain'
  | 'is-ip'
  | 'google-safe-browsing'
  | 'young-domain-age'
  | 'url-risk-pattern'
  | ContentAnalysisFindingId
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
type ReputationStatusSnapshot = {
  url: string
  score: number
  decision: ReputationDecision
  warningThreshold: number
  blockedThreshold: number
  matchedRuleCount: number
} | null
type SecurityTooltipPayload = {
  anchor: {
    left: number
    right: number
    bottom: number
  }
  label: string
  description: string
  detail: string | null
  color: string
  score: number | null
  decision: ReputationDecision | null
  warningThreshold: number | null
  blockedThreshold: number | null
  matchedRuleCount: number | null
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
type SecurityEventLogRule = {
  ruleId: string
  scoreDelta: number
  severity: string
  code: string
}
type SecurityEventLog = {
  id: string
  userId: string | null
  url: string
  hostname: string | null
  decision: Exclude<ReputationDecision, 'allow'>
  eventCode: string
  score: number
  matchedRules: SecurityEventLogRule[]
  createdAt: string
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
type TrustedDomainSourceKind = 'tranco' | 'manual'
type TrustedDomainSource = {
  id: string
  name: string
  kind: TrustedDomainSourceKind
  url: string
  enabled: boolean
  isDefault: boolean
  maxDomains: number
  lastSyncedAt: string | null
  lastDomainCount: number
  lastSyncError: string | null
  createdAt: string
  updatedAt: string
}
type CustomTrustedDomain = {
  domain: string
  createdAt: string
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
let securityTooltipWindow: BrowserWindow | null = null
let browserMode: BrowserMode = 'home'
let lastError: string | null = null
let browserChromeHeight = 122
let browserCssKey: string | null = null
let browserFaviconUrl: string | null = null
let allowedBrowserNavigationUrl: string | null = null
let reputationInterventionState: ReputationInterventionState | null = null
let dnsFailureState: DnsFailureState | null = null
let lastReputationStatus: ReputationStatusSnapshot = null
let continuedWarningNavigationUrl: string | null = null
let userStore: UserStore | null = null
let userMediaPermissionStore: UserMediaPermissionStore | null = null
let isAdminSessionUnlocked = false
const pendingMediaPermissionRequests = new Map<string, Promise<PermissionPromptAction>>()
const faviconDataUrlCache = new Map<string, string | null>()
const pageFaviconCache = new Map<string, string>()
const domainAgeCache = new Map<string, CachedDomainAgeEntry>()
const googleSafeBrowsingCache = new Map<string, CachedSafeBrowsingEntry>()
let rdapBootstrapCache: RdapBootstrap | null = null
let sqlJsModulePromise: Promise<SqlJsModule> | null = null
let appDatabase: SqlJsDatabase | null = null

const DEFAULT_USERS: UserProfile[] = []

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

const DEFAULT_SEARCH_HOME_URL = 'https://www.google.pl/?hl=pl&gl=PL&pws=0'
const ALLOWED_BROWSER_PERMISSION_ORIGINS = new Set<string>([])
const ALLOWED_BROWSER_PROTOCOLS = new Set(['https:', 'http:'])
const ADMIN_PIN_ATTEMPT_LIMIT = 5
const ADMIN_PIN_LOCK_MS = 60_000
const DOMAIN_BLOCKLIST_FETCH_TIMEOUT_MS = 8_000
const DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA = 100
const DEFAULT_NON_LATIN_SCRIPT_SCORE_DELTA = 25
const DEFAULT_LOOKALIKE_TRUSTED_DOMAIN_SCORE_DELTA = 60
const DEFAULT_TRUSTED_DOMAIN_IN_SUBDOMAIN_SCORE_DELTA = 50
const DEFAULT_IP_ADDRESS_SCORE_DELTA = 40
const DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA = 100
const DEFAULT_YOUNG_DOMAIN_SCORE_DELTA = 35
const DEFAULT_URL_RISK_PATTERN_SCORE_DELTA = 70
const DEFAULT_CONTENT_SENSITIVE_FORM_SCORE_DELTA = 30
const DEFAULT_CONTENT_CROSS_ORIGIN_FORM_SCORE_DELTA = 45
const DEFAULT_CONTENT_BRAND_IMPERSONATION_SCORE_DELTA = 55
const DEFAULT_CONTENT_URGENT_LANGUAGE_SCORE_DELTA = 15
const DEFAULT_CONTENT_SUSPICIOUS_IFRAME_SCORE_DELTA = 25
const DEFAULT_CONTENT_DOWNLOAD_RISK_SCORE_DELTA = 30
const DEFAULT_CONTENT_THREAT_LINK_CATALOG_SCORE_DELTA = 70
const DEFAULT_YOUNG_DOMAIN_MAX_AGE_DAYS = 30
const DEFAULT_REPUTATION_WARNING_THRESHOLD = 50
const DEFAULT_REPUTATION_BLOCKED_THRESHOLD = 70
const DEFAULT_TRANCO_TRUSTED_DOMAINS_URL = 'https://tranco-list.eu/top-1m.csv.zip'
const DEFAULT_TRANCO_TRUSTED_DOMAINS_LIMIT = 50_000
const MANUAL_TRUSTED_DOMAIN_SOURCE_ID = 'trusted-source-manual'
const RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json'
const RDAP_FETCH_TIMEOUT_MS = 5_000
const RDAP_DOMAIN_AGE_CACHE_TTL_MS = 1000 * 60 * 60 * 12
const GOOGLE_SAFE_BROWSING_ENDPOINT =
  'https://safebrowsing.googleapis.com/v4/threatMatches:find'
const GOOGLE_SAFE_BROWSING_FETCH_TIMEOUT_MS = 5_000
const GOOGLE_SAFE_BROWSING_NEGATIVE_CACHE_MS = 1000 * 60 * 5
const TRUSTED_DOMAINS_FETCH_TIMEOUT_MS = 15_000
const CONTENT_ANALYSIS_FETCH_TIMEOUT_MS = 6_000
const CONTENT_ANALYSIS_MAX_HTML_CHARS = 500_000
const GENERIC_TRUSTED_LABEL_DOMAIN_COUNT_THRESHOLD = 3
const SECURITY_EVENT_RETENTION_DAYS = 30
const SECURITY_EVENT_RETENTION_MS = SECURITY_EVENT_RETENTION_DAYS * 24 * 60 * 60 * 1000
const SECURITY_EVENT_LIST_LIMIT = 500
const DEFAULT_DOMAIN_BLOCKLIST_CREATED_AT = '2026-07-08T00:00:00.000Z'
const DEFAULT_TRUSTED_DOMAIN_SOURCES: TrustedDomainSource[] = [
  {
    id: MANUAL_TRUSTED_DOMAIN_SOURCE_ID,
    name: 'Własne zaufane domeny',
    kind: 'manual',
    url: 'manual://trusted-domains',
    enabled: true,
    isDefault: true,
    maxDomains: 0,
    lastSyncedAt: null,
    lastDomainCount: 0,
    lastSyncError: null,
    createdAt: '2026-07-12T00:00:00.000Z',
    updatedAt: '2026-07-12T00:00:00.000Z'
  },
  {
    id: 'trusted-source-tranco-default',
    name: 'Tranco top domains',
    kind: 'tranco',
    url: DEFAULT_TRANCO_TRUSTED_DOMAINS_URL,
    enabled: true,
    isDefault: true,
    maxDomains: DEFAULT_TRANCO_TRUSTED_DOMAINS_LIMIT,
    lastSyncedAt: null,
    lastDomainCount: 0,
    lastSyncError: null,
    createdAt: '2026-07-12T00:00:00.000Z',
    updatedAt: '2026-07-12T00:00:00.000Z'
  }
]
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

function getAppDatabasePath(): string {
  return path.join(app.getPath('userData'), 'browser-data.sqlite.enc')
}

function getTrustedDomainsDatabasePath(): string {
  return getAppDatabasePath()
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
        'lookalike-trusted-domain': DEFAULT_LOOKALIKE_TRUSTED_DOMAIN_SCORE_DELTA,
        'trusted-domain-in-subdomain': DEFAULT_TRUSTED_DOMAIN_IN_SUBDOMAIN_SCORE_DELTA,
        'is-ip': DEFAULT_IP_ADDRESS_SCORE_DELTA,
        'google-safe-browsing': DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA,
        'url-risk-pattern': DEFAULT_URL_RISK_PATTERN_SCORE_DELTA,
        'content-sensitive-form': DEFAULT_CONTENT_SENSITIVE_FORM_SCORE_DELTA,
        'content-cross-origin-form': DEFAULT_CONTENT_CROSS_ORIGIN_FORM_SCORE_DELTA,
        'content-brand-impersonation': DEFAULT_CONTENT_BRAND_IMPERSONATION_SCORE_DELTA,
        'content-urgent-language': DEFAULT_CONTENT_URGENT_LANGUAGE_SCORE_DELTA,
        'content-suspicious-iframe': DEFAULT_CONTENT_SUSPICIOUS_IFRAME_SCORE_DELTA,
        'content-download-risk': DEFAULT_CONTENT_DOWNLOAD_RISK_SCORE_DELTA,
        'content-threat-link-catalog': DEFAULT_CONTENT_THREAT_LINK_CATALOG_SCORE_DELTA
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
          value === 'lookalike-trusted-domain' ||
          value === 'trusted-domain-in-subdomain' ||
          value === 'is-ip' ||
          value === 'google-safe-browsing' ||
          value === 'young-domain-age' ||
          value === 'url-risk-pattern' ||
          value === 'content-sensitive-form' ||
          value === 'content-cross-origin-form' ||
          value === 'content-brand-impersonation' ||
          value === 'content-urgent-language' ||
          value === 'content-suspicious-iframe' ||
          value === 'content-download-risk' ||
          value === 'content-threat-link-catalog'
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
      'lookalike-trusted-domain':
        typeof nextRuleWeights['lookalike-trusted-domain'] === 'number' &&
        Number.isFinite(nextRuleWeights['lookalike-trusted-domain'])
          ? Math.max(0, Math.floor(nextRuleWeights['lookalike-trusted-domain']))
          : DEFAULT_LOOKALIKE_TRUSTED_DOMAIN_SCORE_DELTA,
      'trusted-domain-in-subdomain':
        typeof nextRuleWeights['trusted-domain-in-subdomain'] === 'number' &&
        Number.isFinite(nextRuleWeights['trusted-domain-in-subdomain'])
          ? Math.max(0, Math.floor(nextRuleWeights['trusted-domain-in-subdomain']))
          : DEFAULT_TRUSTED_DOMAIN_IN_SUBDOMAIN_SCORE_DELTA,
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
          : DEFAULT_YOUNG_DOMAIN_SCORE_DELTA,
      'url-risk-pattern':
        typeof nextRuleWeights['url-risk-pattern'] === 'number' &&
        Number.isFinite(nextRuleWeights['url-risk-pattern'])
          ? Math.max(0, Math.floor(nextRuleWeights['url-risk-pattern']))
          : DEFAULT_URL_RISK_PATTERN_SCORE_DELTA,
      'content-sensitive-form':
        typeof nextRuleWeights['content-sensitive-form'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-sensitive-form'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-sensitive-form']))
          : DEFAULT_CONTENT_SENSITIVE_FORM_SCORE_DELTA,
      'content-cross-origin-form':
        typeof nextRuleWeights['content-cross-origin-form'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-cross-origin-form'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-cross-origin-form']))
          : DEFAULT_CONTENT_CROSS_ORIGIN_FORM_SCORE_DELTA,
      'content-brand-impersonation':
        typeof nextRuleWeights['content-brand-impersonation'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-brand-impersonation'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-brand-impersonation']))
          : DEFAULT_CONTENT_BRAND_IMPERSONATION_SCORE_DELTA,
      'content-urgent-language':
        typeof nextRuleWeights['content-urgent-language'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-urgent-language'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-urgent-language']))
          : DEFAULT_CONTENT_URGENT_LANGUAGE_SCORE_DELTA,
      'content-suspicious-iframe':
        typeof nextRuleWeights['content-suspicious-iframe'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-suspicious-iframe'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-suspicious-iframe']))
          : DEFAULT_CONTENT_SUSPICIOUS_IFRAME_SCORE_DELTA,
      'content-download-risk':
        typeof nextRuleWeights['content-download-risk'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-download-risk'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-download-risk']))
          : DEFAULT_CONTENT_DOWNLOAD_RISK_SCORE_DELTA,
      'content-threat-link-catalog':
        typeof nextRuleWeights['content-threat-link-catalog'] === 'number' &&
        Number.isFinite(nextRuleWeights['content-threat-link-catalog'])
          ? Math.max(0, Math.floor(nextRuleWeights['content-threat-link-catalog']))
          : DEFAULT_CONTENT_THREAT_LINK_CATALOG_SCORE_DELTA
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

function encryptTrustedDomainsDatabasePayload(payload: Uint8Array): string {
  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  return safeStorage.encryptString(Buffer.from(payload).toString('base64')).toString('base64')
}

function decryptTrustedDomainsDatabasePayload(payload: string): Uint8Array {
  assertSecureUserKeyStorageAvailable()

  if (!safeStorage.isEncryptionAvailable()) {
    throw new Error('Systemowy magazyn kluczy nie jest dostępny.')
  }

  const base64Payload = safeStorage.decryptString(Buffer.from(payload, 'base64'))
  return Uint8Array.from(Buffer.from(base64Payload, 'base64'))
}

function loadBrowserSettings(): BrowserSettings {
  const database = getAppDatabase()
  const adminResult = database.exec(`
    SELECT pin_salt, pin_hash, failed_attempts, locked_until
    FROM admin_security
    WHERE id = 1
  `)
  const adminRow = adminResult[0]?.values[0] ?? []
  const reputationResult = database.exec(`
    SELECT enabled, warning_threshold, blocked_threshold, young_domain_max_age_days,
           google_safe_browsing_api_key
    FROM reputation_settings
    WHERE id = 1
  `)
  const reputationRow = reputationResult[0]?.values[0] ?? []
  const ruleResult = database.exec(`
    SELECT rule_id, enabled, score_delta
    FROM reputation_rule_settings
  `)
  const disabledRuleIds: ReputationRuleId[] = []
  const ruleWeights: Partial<Record<ReputationRuleId, number>> = {}

  for (const row of ruleResult[0]?.values ?? []) {
    const ruleId = row[0] as ReputationRuleId
    const enabled = Number(row[1]) === 1
    const scoreDelta = Number(row[2])

    if (!enabled) {
      disabledRuleIds.push(ruleId)
    }

    if (Number.isFinite(scoreDelta)) {
      ruleWeights[ruleId] = scoreDelta
    }
  }

  const blocklistSources = getDomainBlocklistSourceRows(database)

  return normalizeBrowserSettings({
    accessibility: getAppSetting(database, 'accessibility', normalizeAccessibilitySettings(null)),
    adminSecurity: {
      pinSalt: typeof adminRow[0] === 'string' ? adminRow[0] : null,
      pinHash: typeof adminRow[1] === 'string' ? adminRow[1] : null,
      failedAttempts: Number(adminRow[2]) || 0,
      lockedUntil: typeof adminRow[3] === 'string' ? adminRow[3] : null
    },
    domainBlocklistSources: blocklistSources,
    googleSafeBrowsingApiKey: typeof reputationRow[4] === 'string' ? reputationRow[4] : null,
    reputation: {
      enabled: Number(reputationRow[0]) === 1,
      warningThreshold: Number(reputationRow[1]) || DEFAULT_REPUTATION_WARNING_THRESHOLD,
      blockedThreshold: Number(reputationRow[2]) || DEFAULT_REPUTATION_BLOCKED_THRESHOLD,
      disabledRuleIds,
      ruleWeights,
      youngDomainMaxAgeDays:
        Number(reputationRow[3]) || DEFAULT_YOUNG_DOMAIN_MAX_AGE_DAYS,
      googleSafeBrowsingApiKeyConfigured: typeof reputationRow[4] === 'string'
    }
  })
}

function saveBrowserSettings(value: BrowserSettings): BrowserSettings {
  const database = getAppDatabase()
  const normalizedValue = normalizeBrowserSettings(value)
  const now = new Date().toISOString()

  setAppSetting(database, 'accessibility', normalizedValue.accessibility)
  database.run(
    `
      UPDATE admin_security
      SET pin_salt = $pinSalt,
          pin_hash = $pinHash,
          failed_attempts = $failedAttempts,
          locked_until = $lockedUntil,
          updated_at = $updatedAt
      WHERE id = 1
    `,
    {
      $pinSalt: normalizedValue.adminSecurity.pinSalt,
      $pinHash: normalizedValue.adminSecurity.pinHash,
      $failedAttempts: normalizedValue.adminSecurity.failedAttempts,
      $lockedUntil: normalizedValue.adminSecurity.lockedUntil,
      $updatedAt: now
    }
  )
  database.run(
    `
      UPDATE reputation_settings
      SET enabled = $enabled,
          warning_threshold = $warningThreshold,
          blocked_threshold = $blockedThreshold,
          young_domain_max_age_days = $youngDomainMaxAgeDays,
          google_safe_browsing_api_key = $googleSafeBrowsingApiKey,
          updated_at = $updatedAt
      WHERE id = 1
    `,
    {
      $enabled: normalizedValue.reputation.enabled ? 1 : 0,
      $warningThreshold: normalizedValue.reputation.warningThreshold,
      $blockedThreshold: normalizedValue.reputation.blockedThreshold,
      $youngDomainMaxAgeDays: normalizedValue.reputation.youngDomainMaxAgeDays,
      $googleSafeBrowsingApiKey: normalizedValue.googleSafeBrowsingApiKey,
      $updatedAt: now
    }
  )

  for (const [ruleId, scoreDelta] of Object.entries(normalizedValue.reputation.ruleWeights)) {
    database.run(
      `
        UPDATE reputation_rule_settings
        SET enabled = $enabled,
            score_delta = $scoreDelta,
            updated_at = $updatedAt
        WHERE rule_id = $ruleId
      `,
      {
        $enabled: normalizedValue.reputation.disabledRuleIds.includes(ruleId as ReputationRuleId)
          ? 0
          : 1,
        $scoreDelta: scoreDelta ?? 0,
        $updatedAt: now,
        $ruleId: ruleId
      }
    )
  }

  saveDomainBlocklistSourcesToDatabase(database, normalizedValue.domainBlocklistSources)
  saveTrustedDomainsDatabase(database)
  return loadBrowserSettings()
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
  const database = getAppDatabase()
  const normalizedSources = normalizeDomainBlocklistSources(value)
  saveDomainBlocklistSourcesToDatabase(database, normalizedSources)
  saveTrustedDomainsDatabase(database)
  return getDomainBlocklistSourceRows(database)
}

function getDomainBlocklistSourceRows(database: SqlJsDatabase): DomainBlocklistSource[] {
  const statement = database.prepare(`
    SELECT id, url, enabled, score_delta, is_default, created_at, updated_at
    FROM domain_blocklist_sources
    ORDER BY is_default DESC, url COLLATE NOCASE ASC
  `)
  const rows: DomainBlocklistSource[] = []

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    rows.push({
      id: String(row.id),
      url: String(row.url),
      enabled: Number(row.enabled) === 1,
      scoreDelta: Number(row.score_delta) || DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA,
      isDefault: Number(row.is_default) === 1,
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at)
    })
  }

  statement.free()
  return rows
}

function saveDomainBlocklistSourcesToDatabase(
  database: SqlJsDatabase,
  sources: DomainBlocklistSource[]
): void {
  database.run('DELETE FROM domain_blocklist_sources')

  const statement = database.prepare(`
    INSERT INTO domain_blocklist_sources (
      id, url, enabled, score_delta, is_default, created_at, updated_at
    )
    VALUES ($id, $url, $enabled, $scoreDelta, $isDefault, $createdAt, $updatedAt)
  `)

  for (const source of sources) {
    statement.run({
      $id: source.id,
      $url: source.url,
      $enabled: source.enabled ? 1 : 0,
      $scoreDelta: source.scoreDelta,
      $isDefault: source.isDefault ? 1 : 0,
      $createdAt: source.createdAt,
      $updatedAt: source.updatedAt
    })
  }

  statement.free()
}

async function getSqlJsModule(): Promise<SqlJsModule> {
  if (!sqlJsModulePromise) {
    sqlJsModulePromise = initSqlJs({
      locateFile: (file) => path.join(process.cwd(), 'node_modules/sql.js/dist', file)
    })
  }

  return sqlJsModulePromise
}

function applyTrustedDomainsDatabaseSchema(database: SqlJsDatabase): void {
  database.run(`
    PRAGMA foreign_keys = ON;

    CREATE TABLE IF NOT EXISTS app_settings (
      key TEXT PRIMARY KEY,
      value_json TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      initials TEXT NOT NULL,
      description TEXT NOT NULL,
      created_at TEXT NOT NULL,
      is_active INTEGER NOT NULL DEFAULT 0
    );

    CREATE TABLE IF NOT EXISTS favorites (
      id TEXT PRIMARY KEY,
      user_id TEXT NOT NULL,
      url TEXT NOT NULL,
      title TEXT NOT NULL,
      favicon_url TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      UNIQUE(user_id, url),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_favorites_user_id
      ON favorites(user_id);

    CREATE TABLE IF NOT EXISTS admin_security (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      pin_salt TEXT,
      pin_hash TEXT,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reputation_settings (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      enabled INTEGER NOT NULL,
      warning_threshold INTEGER NOT NULL,
      blocked_threshold INTEGER NOT NULL,
      young_domain_max_age_days INTEGER NOT NULL,
      google_safe_browsing_api_key TEXT,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS reputation_rule_settings (
      rule_id TEXT PRIMARY KEY,
      enabled INTEGER NOT NULL,
      score_delta INTEGER NOT NULL,
      severity TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS domain_blocklist_sources (
      id TEXT PRIMARY KEY,
      url TEXT NOT NULL UNIQUE,
      enabled INTEGER NOT NULL,
      score_delta INTEGER NOT NULL,
      is_default INTEGER NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS trusted_sources (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      kind TEXT NOT NULL,
      url TEXT NOT NULL,
      enabled INTEGER NOT NULL,
      is_default INTEGER NOT NULL,
      max_domains INTEGER NOT NULL,
      last_synced_at TEXT,
      last_domain_count INTEGER NOT NULL DEFAULT 0,
      last_sync_error TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS trusted_domains (
      source_id TEXT NOT NULL,
      domain TEXT NOT NULL,
      label TEXT,
      skeleton TEXT,
      label_length INTEGER,
      rank INTEGER,
      created_at TEXT NOT NULL,
      PRIMARY KEY (source_id, domain),
      FOREIGN KEY (source_id) REFERENCES trusted_sources(id) ON DELETE CASCADE
    );

    CREATE INDEX IF NOT EXISTS idx_trusted_domains_domain
      ON trusted_domains(domain);

    CREATE INDEX IF NOT EXISTS idx_trusted_domains_source_rank
      ON trusted_domains(source_id, rank);

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      user_id TEXT,
      url TEXT NOT NULL,
      hostname TEXT,
      decision TEXT NOT NULL,
      event_code TEXT NOT NULL,
      details_json TEXT,
      created_at TEXT NOT NULL
    );

    CREATE INDEX IF NOT EXISTS idx_security_events_created_at
      ON security_events(created_at);
  `)
}

function ensureColumn(database: SqlJsDatabase, tableName: string, columnName: string, definition: string): void {
  const tableInfo = database.exec(`PRAGMA table_info(${tableName})`)
  const hasColumn = (tableInfo[0]?.values ?? []).some((row) => row[1] === columnName)

  if (!hasColumn) {
    database.run(`ALTER TABLE ${tableName} ADD COLUMN ${columnName} ${definition}`)
  }
}

function ensureTrustedDomainLookalikeColumns(database: SqlJsDatabase): void {
  ensureColumn(database, 'trusted_domains', 'label', 'TEXT')
  ensureColumn(database, 'trusted_domains', 'skeleton', 'TEXT')
  ensureColumn(database, 'trusted_domains', 'label_length', 'INTEGER')
  database.run('CREATE INDEX IF NOT EXISTS idx_trusted_domains_skeleton ON trusted_domains(skeleton)')
  database.run(
    'CREATE INDEX IF NOT EXISTS idx_trusted_domains_label_length ON trusted_domains(label_length)'
  )
}

function backfillTrustedDomainLookalikeMetadata(database: SqlJsDatabase): void {
  const statement = database.prepare(`
    SELECT source_id, domain
    FROM trusted_domains
    WHERE label IS NULL OR skeleton IS NULL OR label_length IS NULL
  `)
  const rows: Array<{ sourceId: string; domain: string }> = []

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    rows.push({
      sourceId: String(row.source_id),
      domain: String(row.domain)
    })
  }

  statement.free()

  if (rows.length === 0) {
    return
  }

  const updateStatement = database.prepare(`
    UPDATE trusted_domains
    SET label = $label,
        skeleton = $skeleton,
        label_length = $labelLength
    WHERE source_id = $sourceId AND domain = $domain
  `)

  for (const row of rows) {
    const metadata = getTrustedDomainLookalikeMetadata(row.domain)
    updateStatement.run({
      $label: metadata.label,
      $skeleton: metadata.skeleton,
      $labelLength: metadata.labelLength,
      $sourceId: row.sourceId,
      $domain: row.domain
    })
  }

  updateStatement.free()
}

function saveTrustedDomainsDatabase(database: SqlJsDatabase): void {
  const encryptedPayload = encryptTrustedDomainsDatabasePayload(database.export())
  fs.writeFileSync(getTrustedDomainsDatabasePath(), encryptedPayload, 'utf8')
}

function setAppSetting(database: SqlJsDatabase, key: string, value: unknown): void {
  database.run(
    `
      INSERT INTO app_settings (key, value_json, updated_at)
      VALUES ($key, $valueJson, $updatedAt)
      ON CONFLICT(key) DO UPDATE SET
        value_json = excluded.value_json,
        updated_at = excluded.updated_at
    `,
    {
      $key: key,
      $valueJson: JSON.stringify(value),
      $updatedAt: new Date().toISOString()
    }
  )
}

function getAppSetting<T>(database: SqlJsDatabase, key: string, fallback: T): T {
  const result = database.exec('SELECT value_json FROM app_settings WHERE key = $key LIMIT 1', {
    $key: key
  })
  const value = result[0]?.values[0]?.[0]

  if (typeof value !== 'string') {
    return fallback
  }

  try {
    return JSON.parse(value) as T
  } catch {
    return fallback
  }
}

function upsertDefaultDomainBlocklistSource(
  database: SqlJsDatabase,
  source: DomainBlocklistSource
): void {
  database.run(
    `
      INSERT INTO domain_blocklist_sources (
        id, url, enabled, score_delta, is_default, created_at, updated_at
      )
      VALUES ($id, $url, $enabled, $scoreDelta, $isDefault, $createdAt, $updatedAt)
      ON CONFLICT(id) DO UPDATE SET
        url = excluded.url,
        is_default = excluded.is_default,
        updated_at = excluded.updated_at
    `,
    {
      $id: source.id,
      $url: source.url,
      $enabled: source.enabled ? 1 : 0,
      $scoreDelta: source.scoreDelta,
      $isDefault: source.isDefault ? 1 : 0,
      $createdAt: source.createdAt,
      $updatedAt: source.updatedAt
    }
  )
}

function ensureAppDatabaseDefaults(database: SqlJsDatabase): void {
  const now = new Date().toISOString()
  database.run(
    `
      INSERT OR IGNORE INTO admin_security (
        id, pin_salt, pin_hash, failed_attempts, locked_until, updated_at
      )
      VALUES (1, NULL, NULL, 0, NULL, $updatedAt)
    `,
    { $updatedAt: now }
  )
  database.run(
    `
      INSERT OR IGNORE INTO reputation_settings (
        id, enabled, warning_threshold, blocked_threshold,
        young_domain_max_age_days, google_safe_browsing_api_key, updated_at
      )
      VALUES (1, 1, $warningThreshold, $blockedThreshold, $youngDomainMaxAgeDays, NULL, $updatedAt)
    `,
    {
      $warningThreshold: DEFAULT_REPUTATION_WARNING_THRESHOLD,
      $blockedThreshold: DEFAULT_REPUTATION_BLOCKED_THRESHOLD,
      $youngDomainMaxAgeDays: DEFAULT_YOUNG_DOMAIN_MAX_AGE_DAYS,
      $updatedAt: now
    }
  )

  const defaultRules: Array<{
    ruleId: ReputationRuleId
    enabled: boolean
    scoreDelta: number
    severity: ReputationRuleSeverity
  }> = [
    { ruleId: 'insecure-http', enabled: true, scoreDelta: 50, severity: 'warning' },
    {
      ruleId: 'domain-blocklist',
      enabled: true,
      scoreDelta: DEFAULT_DOMAIN_BLOCKLIST_SCORE_DELTA,
      severity: 'blocking'
    },
    {
      ruleId: 'non-latin-script',
      enabled: true,
      scoreDelta: DEFAULT_NON_LATIN_SCRIPT_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'lookalike-trusted-domain',
      enabled: true,
      scoreDelta: DEFAULT_LOOKALIKE_TRUSTED_DOMAIN_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'trusted-domain-in-subdomain',
      enabled: true,
      scoreDelta: DEFAULT_TRUSTED_DOMAIN_IN_SUBDOMAIN_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'is-ip',
      enabled: true,
      scoreDelta: DEFAULT_IP_ADDRESS_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'google-safe-browsing',
      enabled: true,
      scoreDelta: DEFAULT_GOOGLE_SAFE_BROWSING_SCORE_DELTA,
      severity: 'blocking'
    },
    {
      ruleId: 'young-domain-age',
      enabled: true,
      scoreDelta: DEFAULT_YOUNG_DOMAIN_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'url-risk-pattern',
      enabled: true,
      scoreDelta: DEFAULT_URL_RISK_PATTERN_SCORE_DELTA,
      severity: 'blocking'
    },
    {
      ruleId: 'content-sensitive-form',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_SENSITIVE_FORM_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'content-cross-origin-form',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_CROSS_ORIGIN_FORM_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'content-brand-impersonation',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_BRAND_IMPERSONATION_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'content-urgent-language',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_URGENT_LANGUAGE_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'content-suspicious-iframe',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_SUSPICIOUS_IFRAME_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'content-download-risk',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_DOWNLOAD_RISK_SCORE_DELTA,
      severity: 'warning'
    },
    {
      ruleId: 'content-threat-link-catalog',
      enabled: true,
      scoreDelta: DEFAULT_CONTENT_THREAT_LINK_CATALOG_SCORE_DELTA,
      severity: 'blocking'
    }
  ]

  for (const rule of defaultRules) {
    database.run(
      `
        INSERT OR IGNORE INTO reputation_rule_settings (
          rule_id, enabled, score_delta, severity, updated_at
        )
        VALUES ($ruleId, $enabled, $scoreDelta, $severity, $updatedAt)
      `,
      {
        $ruleId: rule.ruleId,
        $enabled: rule.enabled ? 1 : 0,
        $scoreDelta: rule.scoreDelta,
        $severity: rule.severity,
        $updatedAt: now
      }
    )
  }

  for (const source of DEFAULT_DOMAIN_BLOCKLIST_SOURCES) {
    upsertDefaultDomainBlocklistSource(database, source)
  }

  for (const source of DEFAULT_TRUSTED_DOMAIN_SOURCES) {
    upsertTrustedDomainSource(database, source)
  }
}

function normalizeTrustedDomain(value: string): string | null {
  const normalizedHostname = normalizeHostname(value)

  if (!normalizedHostname || isIP(normalizedHostname) !== 0) {
    return null
  }

  return getDomain(normalizedHostname) ?? normalizedHostname
}

function upsertTrustedDomainSource(database: SqlJsDatabase, source: TrustedDomainSource): void {
  database.run(
    `
      INSERT INTO trusted_sources (
        id, name, kind, url, enabled, is_default, max_domains,
        last_synced_at, last_domain_count, last_sync_error, created_at, updated_at
      )
      VALUES (
        $id, $name, $kind, $url, $enabled, $isDefault, $maxDomains,
        $lastSyncedAt, $lastDomainCount, $lastSyncError, $createdAt, $updatedAt
      )
      ON CONFLICT(id) DO UPDATE SET
        name = excluded.name,
        kind = excluded.kind,
        url = excluded.url,
        is_default = excluded.is_default,
        max_domains = excluded.max_domains,
        updated_at = excluded.updated_at
    `,
    {
      $id: source.id,
      $name: source.name,
      $kind: source.kind,
      $url: source.url,
      $enabled: source.enabled ? 1 : 0,
      $isDefault: source.isDefault ? 1 : 0,
      $maxDomains: source.maxDomains,
      $lastSyncedAt: source.lastSyncedAt,
      $lastDomainCount: source.lastDomainCount,
      $lastSyncError: source.lastSyncError,
      $createdAt: source.createdAt,
      $updatedAt: source.updatedAt
    }
  )
}

function getTrustedDomainSourceRows(database: SqlJsDatabase): TrustedDomainSource[] {
  const statement = database.prepare(`
    SELECT
      id, name, kind, url, enabled, is_default, max_domains,
      last_synced_at, last_domain_count, last_sync_error, created_at, updated_at
    FROM trusted_sources
    ORDER BY is_default DESC, name COLLATE NOCASE ASC
  `)
  const rows: TrustedDomainSource[] = []

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    const kind = row.kind === 'manual' ? 'manual' : 'tranco'
    rows.push({
      id: String(row.id),
      name: String(row.name),
      kind,
      url: String(row.url),
      enabled: Number(row.enabled) === 1,
      isDefault: Number(row.is_default) === 1,
      maxDomains: Number(row.max_domains),
      lastSyncedAt: typeof row.last_synced_at === 'string' ? row.last_synced_at : null,
      lastDomainCount: Number(row.last_domain_count) || 0,
      lastSyncError: typeof row.last_sync_error === 'string' ? row.last_sync_error : null,
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at)
    })
  }

  statement.free()
  return rows
}

async function initializeAppDatabase(): Promise<void> {
  if (appDatabase) {
    return
  }

  const SQL = await getSqlJsModule()
  const filePath = getAppDatabasePath()

  if (fs.existsSync(filePath)) {
    try {
      const encryptedPayload = fs.readFileSync(filePath, 'utf8')
      const decryptedPayload = decryptTrustedDomainsDatabasePayload(encryptedPayload)
      appDatabase = new SQL.Database(decryptedPayload)
    } catch {
      appDatabase = new SQL.Database()
    }
  } else {
    appDatabase = new SQL.Database()
  }

  applyTrustedDomainsDatabaseSchema(appDatabase)
  ensureTrustedDomainLookalikeColumns(appDatabase)
  ensureAppDatabaseDefaults(appDatabase)
  backfillTrustedDomainLookalikeMetadata(appDatabase)
  purgeExpiredSecurityEvents(appDatabase)
  saveTrustedDomainsDatabase(appDatabase)
}

function getAppDatabase(): SqlJsDatabase {
  if (!appDatabase) {
    throw new Error('Baza danych aplikacji nie została jeszcze zainicjalizowana.')
  }

  return appDatabase
}

function getSecurityEventRetentionCutoff(): string {
  return new Date(Date.now() - SECURITY_EVENT_RETENTION_MS).toISOString()
}

function purgeExpiredSecurityEvents(database = getAppDatabase()): void {
  database.run('DELETE FROM security_events WHERE created_at < $cutoff', {
    $cutoff: getSecurityEventRetentionCutoff()
  })
}

function parseSecurityEventDetails(value: unknown): Pick<SecurityEventLog, 'score' | 'matchedRules'> {
  if (typeof value !== 'string' || value.trim().length === 0) {
    return { score: 0, matchedRules: [] }
  }

  try {
    const parsedValue = JSON.parse(value) as {
      score?: unknown
      matchedRules?: unknown
    }
    const matchedRules = Array.isArray(parsedValue.matchedRules)
      ? parsedValue.matchedRules
          .filter((rule): rule is Record<string, unknown> => Boolean(rule) && typeof rule === 'object')
          .map((rule) => ({
            ruleId: typeof rule.ruleId === 'string' ? rule.ruleId : 'unknown',
            scoreDelta: Number(rule.scoreDelta) || 0,
            severity: typeof rule.severity === 'string' ? rule.severity : 'warning',
            code: typeof rule.code === 'string' ? rule.code : 'unknown'
          }))
      : []

    return {
      score: Number(parsedValue.score) || 0,
      matchedRules
    }
  } catch {
    return { score: 0, matchedRules: [] }
  }
}

function listRecentSecurityEvents(): SecurityEventLog[] {
  const database = getAppDatabase()
  purgeExpiredSecurityEvents(database)

  const statement = database.prepare(`
    SELECT id, user_id, url, hostname, decision, event_code, details_json, created_at
    FROM security_events
    WHERE created_at >= $cutoff
    ORDER BY created_at DESC
    LIMIT $limit
  `)
  statement.bind({
    $cutoff: getSecurityEventRetentionCutoff(),
    $limit: SECURITY_EVENT_LIST_LIMIT
  })

  const rows: SecurityEventLog[] = []

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    const details = parseSecurityEventDetails(row.details_json)
    const decision = row.decision === 'blocked' ? 'blocked' : 'warning'

    rows.push({
      id: String(row.id),
      userId: typeof row.user_id === 'string' ? row.user_id : null,
      url: String(row.url),
      hostname: typeof row.hostname === 'string' ? row.hostname : null,
      decision,
      eventCode: String(row.event_code),
      score: details.score,
      matchedRules: details.matchedRules,
      createdAt: String(row.created_at)
    })
  }

  statement.free()
  saveTrustedDomainsDatabase(database)
  return rows
}

function recordSecurityEvent(
  assessment: ReputationAssessment,
  interventionState: ReputationInterventionState
): void {
  try {
    const database = getAppDatabase()
    purgeExpiredSecurityEvents(database)
    database.run(
      `
        INSERT INTO security_events (
          id, user_id, url, hostname, decision, event_code, details_json, created_at
        )
        VALUES (
          $id, $userId, $url, $hostname, $decision, $eventCode, $detailsJson, $createdAt
        )
      `,
      {
        $id: `security-event-${randomUUID()}`,
        $userId: getActiveUserId(),
        $url: assessment.candidate.normalizedUrl,
        $hostname: assessment.candidate.hostname,
        $decision: assessment.decision,
        $eventCode: interventionState.eventCode,
        $detailsJson: JSON.stringify({
          score: assessment.score,
          matchedRules: assessment.matchedRules.map((rule) => ({
            ruleId: rule.ruleId,
            scoreDelta: rule.scoreDelta,
            severity: rule.severity,
            code: rule.code
          }))
        }),
        $createdAt: new Date().toISOString()
      }
    )
    saveTrustedDomainsDatabase(database)
  } catch (error) {
    console.warn('[security-event] failed to persist event', error)
  }
}

async function getTrustedDomainsDatabase(): Promise<SqlJsDatabase> {
  await initializeAppDatabase()
  return getAppDatabase()
}

async function loadTrustedDomainSources(): Promise<TrustedDomainSource[]> {
  const database = await getTrustedDomainsDatabase()
  return getTrustedDomainSourceRows(database)
}

async function setTrustedDomainSourceEnabled(
  sourceId: string,
  enabled: boolean
): Promise<TrustedDomainSource[]> {
  const database = await getTrustedDomainsDatabase()
  database.run(
    `
      UPDATE trusted_sources
      SET enabled = $enabled, updated_at = $updatedAt
      WHERE id = $id
    `,
    {
      $enabled: enabled ? 1 : 0,
      $updatedAt: new Date().toISOString(),
      $id: sourceId
    }
  )
  saveTrustedDomainsDatabase(database)
  return getTrustedDomainSourceRows(database)
}

async function loadCustomTrustedDomains(): Promise<CustomTrustedDomain[]> {
  const database = await getTrustedDomainsDatabase()
  const statement = database.prepare(
    `
      SELECT domain, created_at
      FROM trusted_domains
      WHERE source_id = $sourceId
      ORDER BY domain COLLATE NOCASE ASC
    `,
    {
      $sourceId: MANUAL_TRUSTED_DOMAIN_SOURCE_ID
    }
  )
  const rows: CustomTrustedDomain[] = []

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    rows.push({
      domain: String(row.domain),
      createdAt: String(row.created_at)
    })
  }

  statement.free()
  return rows
}

async function addCustomTrustedDomain(value: string): Promise<CustomTrustedDomain[]> {
  const normalizedDomain = normalizeCustomTrustedDomain(value)

  if (!normalizedDomain) {
    throw new Error('Wpisz poprawną domenę, na przykład example.com.')
  }

  const database = await getTrustedDomainsDatabase()
  const now = new Date().toISOString()
  const metadata = getTrustedDomainLookalikeMetadata(normalizedDomain)

  database.run(
    `
      INSERT INTO trusted_domains (
        source_id, domain, label, skeleton, label_length, rank, created_at
      )
      VALUES (
        $sourceId, $domain, $label, $skeleton, $labelLength, NULL, $createdAt
      )
      ON CONFLICT(source_id, domain) DO NOTHING
    `,
    {
      $sourceId: MANUAL_TRUSTED_DOMAIN_SOURCE_ID,
      $domain: normalizedDomain,
      $label: metadata.label,
      $skeleton: metadata.skeleton,
      $labelLength: metadata.labelLength,
      $createdAt: now
    }
  )
  database.run(
    `
      UPDATE trusted_sources
      SET last_domain_count = (
            SELECT COUNT(*)
            FROM trusted_domains
            WHERE source_id = $sourceId
          ),
          updated_at = $updatedAt
      WHERE id = $sourceId
    `,
    {
      $sourceId: MANUAL_TRUSTED_DOMAIN_SOURCE_ID,
      $updatedAt: now
    }
  )
  saveTrustedDomainsDatabase(database)
  return loadCustomTrustedDomains()
}

async function removeCustomTrustedDomain(domain: string): Promise<CustomTrustedDomain[]> {
  const normalizedDomain = normalizeCustomTrustedDomain(domain)

  if (!normalizedDomain) {
    throw new Error('Nie znaleziono wskazanej domeny.')
  }

  const database = await getTrustedDomainsDatabase()
  const now = new Date().toISOString()

  database.run(
    `
      DELETE FROM trusted_domains
      WHERE source_id = $sourceId AND domain = $domain
    `,
    {
      $sourceId: MANUAL_TRUSTED_DOMAIN_SOURCE_ID,
      $domain: normalizedDomain
    }
  )
  database.run(
    `
      UPDATE trusted_sources
      SET last_domain_count = (
            SELECT COUNT(*)
            FROM trusted_domains
            WHERE source_id = $sourceId
          ),
          updated_at = $updatedAt
      WHERE id = $sourceId
    `,
    {
      $sourceId: MANUAL_TRUSTED_DOMAIN_SOURCE_ID,
      $updatedAt: now
    }
  )
  saveTrustedDomainsDatabase(database)
  return loadCustomTrustedDomains()
}

function extractTrancoDomainsFromZipPayload(
  payload: Buffer,
  maxDomains: number
): Array<{ domain: string; rank: number }> {
  const zipArchive = new AdmZip(payload)
  const csvEntry =
    zipArchive.getEntry('top-1m.csv') ??
    zipArchive
      .getEntries()
      .find((entry) => entry.entryName.toLowerCase().endsWith('.csv'))

  if (!csvEntry) {
    throw new Error('Nie udało się odczytać pliku CSV z archiwum Tranco.')
  }

  const csvPayload = zipArchive.readAsText(csvEntry)
  const domains: Array<{ domain: string; rank: number }> = []

  for (const rawLine of csvPayload.split(/\r?\n/)) {
    const line = rawLine.trim()

    if (!line) {
      continue
    }

    const [rankToken, domainToken] = line.split(',', 2)
    const rank = Number(rankToken)
    const domain = normalizeTrustedDomain(domainToken ?? '')

    if (!Number.isFinite(rank) || !domain) {
      continue
    }

    domains.push({ domain, rank })

    if (domains.length >= maxDomains) {
      break
    }
  }

  return domains
}

async function syncTrustedDomainSource(sourceId: string): Promise<TrustedDomainSource[]> {
  const database = await getTrustedDomainsDatabase()
  const source = getTrustedDomainSourceRows(database).find((entry) => entry.id === sourceId)

  if (!source) {
    throw new Error('Nie znaleziono źródła zaufanych domen.')
  }

  try {
    if (source.kind !== 'tranco') {
      throw new Error('Ten typ źródła nie jest jeszcze obsługiwany.')
    }

    const response = await fetch(source.url, {
      cache: 'no-store',
      signal: AbortSignal.timeout(TRUSTED_DOMAINS_FETCH_TIMEOUT_MS)
    })

    if (!response.ok) {
      throw new Error('Nie udało się pobrać listy zaufanych domen.')
    }

    const domains = extractTrancoDomainsFromZipPayload(
      Buffer.from(await response.arrayBuffer()),
      source.maxDomains
    )
    const now = new Date().toISOString()

    database.run('BEGIN')

    try {
      database.run('DELETE FROM trusted_domains WHERE source_id = $sourceId', {
        $sourceId: source.id
      })

      const insertStatement = database.prepare(`
        INSERT INTO trusted_domains (
          source_id, domain, label, skeleton, label_length, rank, created_at
        )
        VALUES (
          $sourceId, $domain, $label, $skeleton, $labelLength, $rank, $createdAt
        )
      `)

      for (const domain of domains) {
        const metadata = getTrustedDomainLookalikeMetadata(domain.domain)
        insertStatement.run({
          $sourceId: source.id,
          $domain: domain.domain,
          $label: metadata.label,
          $skeleton: metadata.skeleton,
          $labelLength: metadata.labelLength,
          $rank: domain.rank,
          $createdAt: now
        })
      }

      insertStatement.free()

      database.run(
        `
          UPDATE trusted_sources
          SET last_synced_at = $lastSyncedAt,
              last_domain_count = $lastDomainCount,
              last_sync_error = NULL,
              updated_at = $updatedAt
          WHERE id = $id
        `,
        {
          $lastSyncedAt: now,
          $lastDomainCount: domains.length,
          $updatedAt: now,
          $id: source.id
        }
      )

      database.run('COMMIT')
    } catch (error) {
      database.run('ROLLBACK')
      throw error
    }

    saveTrustedDomainsDatabase(database)
  } catch (error) {
    const errorMessage =
      error instanceof Error ? error.message : 'Nie udało się zsynchronizować źródła.'

    database.run(
      `
        UPDATE trusted_sources
        SET last_sync_error = $lastSyncError, updated_at = $updatedAt
        WHERE id = $id
      `,
      {
        $lastSyncError: errorMessage,
        $updatedAt: new Date().toISOString(),
        $id: source.id
      }
    )
    saveTrustedDomainsDatabase(database)
    throw error
  }

  return getTrustedDomainSourceRows(database)
}

async function ensureTrustedDomainSourcesReady(): Promise<void> {
  const sources = await loadTrustedDomainSources()
  const trancoSource = sources.find((source) => source.kind === 'tranco')

  if (trancoSource && trancoSource.lastDomainCount === 0 && trancoSource.enabled) {
    try {
      await syncTrustedDomainSource(trancoSource.id)
    } catch {
      // Keep the app usable even if the initial trusted-domain sync fails.
    }
  }
}

async function isTrustedDomain(hostname: string): Promise<boolean> {
  const normalizedHostname = normalizeHostname(hostname)

  if (!normalizedHostname || isIP(normalizedHostname) !== 0) {
    return false
  }

  const database = await getTrustedDomainsDatabase()
  const statement = database.prepare(
    `
      SELECT td.domain, td.label
      FROM trusted_domains td
      INNER JOIN trusted_sources ts ON ts.id = td.source_id
      WHERE ts.enabled = 1 AND (td.domain = $hostname OR $hostname LIKE '%.' || td.domain)
      ORDER BY td.domain = $hostname DESC, length(td.domain) DESC
    `,
    {
      $hostname: normalizedHostname
    }
  )

  try {
    while (statement.step()) {
      const row = statement.getAsObject() as Record<string, unknown>

      if (isTrustedDomainMatchAllowed(normalizedHostname, String(row.domain))) {
        return true
      }
    }

    return false
  } finally {
    statement.free()
  }
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
  const database = getAppDatabase()
  const statement = database.prepare(
    `
      SELECT url, title, favicon_url, created_at, updated_at
      FROM favorites
      WHERE user_id = $userId
      ORDER BY title COLLATE NOCASE ASC
    `,
    { $userId: userId }
  )
  const favorites: FavoriteEntry[] = []

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    favorites.push({
      url: String(row.url),
      title: String(row.title),
      faviconUrl: typeof row.favicon_url === 'string' ? row.favicon_url : null,
      createdAt: String(row.created_at),
      updatedAt: String(row.updated_at)
    })
  }

  statement.free()
  return normalizeFavoriteEntries(favorites)
}

function saveUserFavorites(userId: string, favorites: FavoriteEntry[]): void {
  const normalizedFavorites = normalizeFavoriteEntries(favorites)
  const database = getAppDatabase()
  database.run('DELETE FROM favorites WHERE user_id = $userId', { $userId: userId })

  const statement = database.prepare(`
    INSERT INTO favorites (id, user_id, url, title, favicon_url, created_at, updated_at)
    VALUES ($id, $userId, $url, $title, $faviconUrl, $createdAt, $updatedAt)
  `)

  for (const favorite of normalizedFavorites) {
    statement.run({
      $id: `favorite-${randomUUID()}`,
      $userId: userId,
      $url: favorite.url,
      $title: favorite.title,
      $faviconUrl: favorite.faviconUrl,
      $createdAt: favorite.createdAt,
      $updatedAt: favorite.updatedAt
    })
  }

  statement.free()
  saveTrustedDomainsDatabase(database)
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
  const database = getAppDatabase()
  database.run('DELETE FROM favorites WHERE user_id = $userId', { $userId: userId })
  saveTrustedDomainsDatabase(database)
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

function loadReputationSettings(): ReputationSettings {
  const browserSettings = loadBrowserSettings()
  const hasApiKey = hasGoogleSafeBrowsingApiKey(browserSettings)
  const disabledRuleIds: ReputationRuleId[] = hasApiKey
    ? browserSettings.reputation.disabledRuleIds
    : Array.from(
        new Set<ReputationRuleId>([
          ...browserSettings.reputation.disabledRuleIds,
          'google-safe-browsing'
        ])
      )

  return {
    ...browserSettings.reputation,
    disabledRuleIds,
    googleSafeBrowsingApiKeyConfigured: hasApiKey
  }
}

function normalizeReputationSettingsForApiKey(
  settings: ReputationSettings,
  hasApiKey: boolean
): ReputationSettings {
  if (hasApiKey) {
    return settings
  }

  return {
    ...settings,
    disabledRuleIds: Array.from(
      new Set<ReputationRuleId>([...settings.disabledRuleIds, 'google-safe-browsing'])
    )
  }
}

function saveReputationSettings(value: ReputationSettings): ReputationSettings {
  const currentBrowserSettings = loadBrowserSettings()
  const hasApiKey = hasGoogleSafeBrowsingApiKey(currentBrowserSettings)
  const normalizedReputation = normalizeReputationSettingsForApiKey(value, hasApiKey)
  const nextBrowserSettings = saveBrowserSettings({
    ...currentBrowserSettings,
    reputation: normalizeReputationSettings(normalizedReputation)
  })
  const nextHasApiKey = hasGoogleSafeBrowsingApiKey(nextBrowserSettings)

  return {
    ...normalizeReputationSettingsForApiKey(nextBrowserSettings.reputation, nextHasApiKey),
    googleSafeBrowsingApiKeyConfigured: nextHasApiKey
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
  const currentBrowserSettings = loadBrowserSettings()
  const nextReputation = normalizedValue
    ? currentBrowserSettings.reputation
    : normalizeReputationSettingsForApiKey(currentBrowserSettings.reputation, false)

  const nextBrowserSettings = saveBrowserSettings({
    ...currentBrowserSettings,
    googleSafeBrowsingApiKey: normalizedValue,
    reputation: nextReputation
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

function setReputationIntervention(value: ReputationInterventionState | null): void {
  reputationInterventionState = value
  if (value) {
    hideSecurityTooltip()
  }
  updateBrowserBounds()
}

function setDnsFailure(value: DnsFailureState | null): void {
  dnsFailureState = value
  if (value) {
    hideSecurityTooltip()
  }
  updateBrowserBounds()
}

function setLastReputationStatus(assessment: ReputationAssessment | null): void {
  lastReputationStatus = assessment
    ? {
        url: assessment.candidate.normalizedUrl,
        score: assessment.score,
        decision: assessment.decision,
        warningThreshold: loadReputationSettings().warningThreshold,
        blockedThreshold: loadReputationSettings().blockedThreshold,
        matchedRuleCount: assessment.matchedRules.length
      }
    : null
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

function hideSecurityTooltip(): void {
  if (!securityTooltipWindow) {
    return
  }

  securityTooltipWindow.close()
  securityTooltipWindow = null
}

function showSecurityTooltip(payload: SecurityTooltipPayload): void {
  if (!mainWindow || mainWindow.isDestroyed()) {
    return
  }

  const tooltipWidth = 500
  const tooltipHeight = 274
  const margin = 10
  const mainBounds = mainWindow.getBounds()
  const rawRiskScore = payload.score ?? 0
  const riskScore = Math.max(0, Math.min(100, Math.round(rawRiskScore)))
  const securityScore = Math.max(0, Math.min(100, 100 - riskScore))
  const warningThreshold = payload.warningThreshold ?? 50
  const blockedThreshold = payload.blockedThreshold ?? 70
  const markerLeft = Math.max(0, Math.min(100, riskScore))
  const warningLeft = Math.max(0, Math.min(100, warningThreshold))
  const blockedLeft = Math.max(0, Math.min(100, blockedThreshold))
  const safeWidth = warningLeft
  const warningWidth = Math.max(0, blockedLeft - warningLeft)
  const blockedWidth = Math.max(0, 100 - blockedLeft)
  const statusColor = payload.color
  const statusSoftColor =
    payload.decision === 'blocked'
      ? '#fee2e2'
      : payload.decision === 'warning'
        ? '#fef3c7'
        : payload.decision === 'allow'
          ? '#dcfce7'
          : '#e2e8f0'
  const heroIconHtml =
    payload.decision === 'warning'
      ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
          <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
          <path d="M12 9v4"></path>
          <path d="M12 17h.01"></path>
        </svg>`
      : payload.decision === 'blocked'
        ? `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="m9.5 9.5 5 5"></path>
            <path d="m14.5 9.5-5 5"></path>
          </svg>`
        : `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
            <path d="m9 12 2 2 4-5"></path>
          </svg>`
  const x = Math.max(
    mainBounds.x + margin,
    Math.min(
      mainBounds.x + Math.round(payload.anchor.right - tooltipWidth + 26),
      mainBounds.x + mainBounds.width - tooltipWidth - margin
    )
  )
  const y = Math.max(
    mainBounds.y + margin,
    Math.min(
      mainBounds.y + Math.round(payload.anchor.bottom + 8),
      mainBounds.y + mainBounds.height - tooltipHeight - margin
    )
  )

  if (!securityTooltipWindow || securityTooltipWindow.isDestroyed()) {
    securityTooltipWindow = new BrowserWindow({
      parent: mainWindow,
      width: tooltipWidth,
      height: tooltipHeight,
      x,
      y,
      frame: false,
      transparent: true,
      resizable: false,
      movable: false,
      minimizable: false,
      maximizable: false,
      focusable: false,
      skipTaskbar: true,
      show: false,
      backgroundColor: '#00000000',
      webPreferences: {
        contextIsolation: true,
        nodeIntegration: false,
        sandbox: true
      }
    })

    securityTooltipWindow.on('closed', () => {
      securityTooltipWindow = null
    })
  } else {
    securityTooltipWindow.setBounds({ x, y, width: tooltipWidth, height: tooltipHeight })
  }

  const html = `
    <!doctype html>
    <html>
      <head>
        <meta charset="utf-8" />
        <style>
          * { box-sizing: border-box; }
          body {
            margin: 0;
            padding: 12px;
            background: transparent;
            font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            color: #111827;
            overflow: hidden;
          }
          .card {
            position: relative;
            width: 100%;
            min-height: ${tooltipHeight - 24}px;
            border: 1px solid #e2e8f0;
            border-radius: 20px;
            background: rgba(255, 255, 255, 0.98);
            box-shadow: 0 16px 38px rgba(15, 23, 42, 0.12);
            padding: 22px 26px 18px;
          }
          .card::before {
            position: absolute;
            top: -12px;
            right: 96px;
            width: 22px;
            height: 22px;
            border-top: 1px solid #e2e8f0;
            border-left: 1px solid #e2e8f0;
            background: rgba(255, 255, 255, 0.98);
            content: "";
            transform: rotate(45deg);
          }
          .top {
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            gap: 16px;
          }
          .left {
            display: flex;
            align-items: flex-start;
            gap: 14px;
            min-width: 0;
          }
          .icon {
            display: flex;
            width: 44px;
            height: 44px;
            flex: 0 0 auto;
            align-items: center;
            justify-content: center;
            border-radius: 9999px;
            background: ${statusSoftColor};
            color: ${statusColor};
          }
          .icon svg {
            width: 24px;
            height: 24px;
          }
          .title {
            margin: 0;
            color: #111827;
            font-size: 18px;
            font-weight: 700;
            line-height: 1.2;
          }
          .description {
            margin: 8px 0 0;
            color: #6b7280;
            font-size: 13px;
            font-weight: 600;
            line-height: 1.35;
          }
          .score {
            text-align: right;
            white-space: nowrap;
          }
          .score strong {
            color: ${statusColor};
            font-size: 22px;
            font-weight: 700;
            letter-spacing: -0.04em;
          }
          .score span {
            color: #64748b;
            font-size: 14px;
            font-weight: 600;
          }
          .score p {
            margin: 4px 0 0;
            color: #6b7280;
            font-size: 12px;
            font-weight: 600;
          }
          .scale {
            position: relative;
            margin-top: 32px;
            height: 38px;
          }
          .bar {
            display: flex;
            height: 9px;
            overflow: hidden;
            border-radius: 9999px;
            background: #e5e7eb;
          }
          .safe { width: ${safeWidth}%; background: #22c55e; }
          .warn { width: ${warningWidth}%; background: #f59e0b; }
          .block { width: ${blockedWidth}%; background: #ef4444; }
          .marker {
            position: absolute;
            top: -6px;
            left: ${markerLeft}%;
            width: 18px;
            height: 18px;
            border: 4px solid #ffffff;
            border-radius: 9999px;
            background: ${statusColor};
            box-shadow: 0 6px 16px rgba(15, 23, 42, 0.22);
            transform: translateX(-50%);
          }
          .tick {
            position: absolute;
            top: 19px;
            color: #6b7280;
            font-size: 13px;
            font-weight: 500;
            transform: translateX(-50%);
          }
          .tick-start { left: 0; transform: none; }
          .tick-warning { left: ${warningLeft}%; }
          .tick-blocked { left: ${blockedLeft}%; }
          .tick-end { right: 0; transform: none; }
          .legend {
            display: grid;
            grid-template-columns: 1fr 1fr 1fr;
            gap: 12px;
            margin-top: 12px;
            border-top: 1px solid #f1f5f9;
            padding-top: 14px;
          }
          .legend-item {
            display: flex;
            gap: 9px;
            align-items: flex-start;
          }
          .legend-item + .legend-item {
            border-left: 1px solid #edf2f7;
            padding-left: 12px;
          }
          .legend-icon {
            display: flex;
            width: 30px;
            height: 30px;
            flex: 0 0 auto;
            align-items: center;
            justify-content: center;
            border-radius: 9999px;
          }
          .legend-title {
            margin: 0;
            font-size: 13px;
            font-weight: 650;
          }
          .legend-copy {
            margin: 6px 0 0;
            color: #6b7280;
            font-size: 11px;
            font-weight: 500;
          }
          .safe-text { color: #15803d; }
          .warn-text { color: #d97706; }
          .block-text { color: #ef4444; }
          .safe-bg { background: #dcfce7; }
          .warn-bg { background: #fef3c7; }
          .block-bg { background: #fee2e2; }
        </style>
      </head>
      <body>
        <section class="card">
          <div class="top">
            <div class="left">
              <div class="icon">
                ${heroIconHtml}
              </div>
              <div>
                <p class="title">${escapeHtml(payload.label)}</p>
                <p class="description">${escapeHtml(payload.description)}</p>
              </div>
            </div>
            <div class="score">
              <strong>${securityScore}</strong><span>/100</span>
              <p>Security Score</p>
            </div>
          </div>
          <div class="scale">
            <div class="bar">
              <div class="safe"></div>
              <div class="warn"></div>
              <div class="block"></div>
            </div>
            <div class="marker"></div>
            <span class="tick tick-start">0</span>
            <span class="tick tick-warning">${warningThreshold}</span>
            <span class="tick tick-blocked">${blockedThreshold}</span>
            <span class="tick tick-end">100</span>
          </div>
          <div class="legend">
            <div class="legend-item">
              <div class="legend-icon safe-bg safe-text">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                  <path d="m9 12 2 2 4-5"></path>
                </svg>
              </div>
              <div><p class="legend-title safe-text">0 - ${warningThreshold}</p><p class="legend-copy">Bezpieczna</p></div>
            </div>
            <div class="legend-item">
              <div class="legend-icon warn-bg warn-text">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
                  <path d="M12 9v4"></path>
                  <path d="M12 17h.01"></path>
                </svg>
              </div>
              <div><p class="legend-title warn-text">${warningThreshold} - ${blockedThreshold}</p><p class="legend-copy">Ostrzeżenie</p></div>
            </div>
            <div class="legend-item">
              <div class="legend-icon block-bg block-text">
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.1" stroke-linecap="round" stroke-linejoin="round">
                  <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
                  <path d="m9.5 9.5 5 5"></path>
                  <path d="m14.5 9.5-5 5"></path>
                </svg>
              </div>
              <div><p class="legend-title block-text">${blockedThreshold} - 100</p><p class="legend-copy">Zablokowana</p></div>
            </div>
          </div>
        </section>
      </body>
    </html>
  `

  securityTooltipWindow.loadURL(`data:text/html;charset=utf-8,${encodeURIComponent(html)}`)
  securityTooltipWindow.showInactive()
}

async function refreshReputationStatusForLoadedUrl(
  rawUrl: string,
  view: WebContentsView
): Promise<void> {
  if (!rawUrl || !isSafeBrowserUrl(rawUrl) || dnsFailureState) {
    setLastReputationStatus(null)
    sendBrowserState()
    return
  }

  try {
    const assessment = await assessNavigationReputation(rawUrl)

    if (view.webContents.getURL() !== assessment.candidate.normalizedUrl) {
      return
    }

    setLastReputationStatus(assessment)
    sendBrowserState()
  } catch {
    setLastReputationStatus(null)
    sendBrowserState()
  }
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

function getRuleScoreDelta(
  ruleId: ReputationRuleId,
  fallbackScoreDelta: number,
  settings: ReputationSettings
): number {
  return settings.ruleWeights[ruleId] ?? fallbackScoreDelta
}

async function findLookalikeTrustedDomain(candidateDomain: string): Promise<string | null> {
  const database = await getTrustedDomainsDatabase()
  const metadata = getTrustedDomainLookalikeMetadata(candidateDomain)
  const exactSkeletonStatement = database.prepare(
    `
      SELECT td.domain, td.label,
        (
          SELECT COUNT(DISTINCT td2.domain)
          FROM trusted_domains td2
          INNER JOIN trusted_sources ts2 ON ts2.id = td2.source_id
          WHERE ts2.enabled = 1 AND td2.label = td.label
        ) AS label_domain_count
      FROM trusted_domains td
      INNER JOIN trusted_sources ts ON ts.id = td.source_id
      WHERE ts.enabled = 1
        AND td.domain != $domain
        AND td.skeleton = $skeleton
      ORDER BY ts.kind = 'manual' DESC, td.rank IS NULL ASC, td.rank ASC
      LIMIT 1
    `,
    {
      $domain: candidateDomain,
      $skeleton: metadata.skeleton
    }
  )

  try {
    if (exactSkeletonStatement.step()) {
      const row = exactSkeletonStatement.getAsObject() as Record<string, unknown>
      return String(row.domain)
    }
  } finally {
    exactSkeletonStatement.free()
  }

  const manualStatement = database.prepare(
    `
      SELECT td.domain
      FROM trusted_domains td
      INNER JOIN trusted_sources ts ON ts.id = td.source_id
      WHERE ts.enabled = 1
        AND ts.kind = 'manual'
        AND td.domain != $domain
        AND td.label_length BETWEEN $minLabelLength AND $maxLabelLength
      ORDER BY td.domain COLLATE NOCASE ASC
    `,
    {
      $domain: candidateDomain,
      $minLabelLength: Math.max(1, metadata.labelLength - 2),
      $maxLabelLength: metadata.labelLength + 2
    }
  )

  try {
    while (manualStatement.step()) {
      const row = manualStatement.getAsObject() as Record<string, unknown>
      const trustedDomain = String(row.domain)

      if (isLookalikeDomain(candidateDomain, trustedDomain)) {
        return trustedDomain
      }
    }
  } finally {
    manualStatement.free()
  }

  const trancoStatement = database.prepare(
    `
      SELECT td.domain
      FROM trusted_domains td
      INNER JOIN trusted_sources ts ON ts.id = td.source_id
      WHERE ts.enabled = 1
        AND ts.kind = 'tranco'
        AND td.domain != $domain
        AND td.label_length BETWEEN $minLabelLength AND $maxLabelLength
      ORDER BY td.rank IS NULL ASC, td.rank ASC
      LIMIT 1000
    `,
    {
      $domain: candidateDomain,
      $minLabelLength: Math.max(1, metadata.labelLength - 2),
      $maxLabelLength: metadata.labelLength + 2
    }
  )

  try {
    while (trancoStatement.step()) {
      const row = trancoStatement.getAsObject() as Record<string, unknown>
      const trustedDomain = String(row.domain)

      if (isLookalikeDomain(candidateDomain, trustedDomain)) {
        return trustedDomain
      }
    }
  } finally {
    trancoStatement.free()
  }

  return null
}

async function findTrustedDomainMentionedInSubdomain(
  candidate: NormalizedSiteCandidate
): Promise<string | null> {
  if (!candidate.registrableDomain || !candidate.subdomain || candidate.isIp) {
    return null
  }

  const subdomain = candidate.subdomain.toLowerCase()
  const database = await getTrustedDomainsDatabase()
  const statement = database.prepare(
    `
      SELECT td.domain
      FROM trusted_domains td
      INNER JOIN trusted_sources ts ON ts.id = td.source_id
      WHERE ts.enabled = 1
        AND td.domain != $registrableDomain
        AND (
          $subdomain = td.domain
          OR $subdomain LIKE td.domain || '.%'
          OR $subdomain LIKE '%.' || td.domain
          OR $subdomain LIKE '%.' || td.domain || '.%'
          OR (
            td.label_length >= 5
            AND (
              $subdomain = td.label
              OR $subdomain LIKE td.label || '.%'
              OR $subdomain LIKE '%.' || td.label
              OR $subdomain LIKE '%.' || td.label || '.%'
              OR $subdomain LIKE td.label || '-%'
              OR $subdomain LIKE '%-' || td.label
              OR $subdomain LIKE '%-' || td.label || '-%'
            )
          )
        )
      ORDER BY ts.kind = 'manual' DESC, td.rank IS NULL ASC, td.rank ASC
      LIMIT 50
    `,
    {
      $registrableDomain: candidate.registrableDomain,
      $subdomain: subdomain
    }
  )

  try {
    while (statement.step()) {
      const row = statement.getAsObject() as Record<string, unknown>
      const trustedDomain = String(row.domain)
      const trustedLabel = typeof row.label === 'string' ? row.label : null
      const labelDomainCount = Number(row.label_domain_count) || 0
      const isGenericTrustedLabel =
        labelDomainCount >= GENERIC_TRUSTED_LABEL_DOMAIN_COUNT_THRESHOLD

      if (
        isTrustedDomainEntryMentionedInSubdomain(
          candidate,
          trustedDomain,
          trustedLabel,
          isGenericTrustedLabel
        )
      ) {
        return trustedDomain
      }
    }
  } finally {
    statement.free()
  }

  return null
}

async function loadContentTrustedBrands(): Promise<ContentTrustedBrand[]> {
  const database = await getTrustedDomainsDatabase()
  const statement = database.prepare(`
    SELECT td.domain, td.label,
      (
        SELECT COUNT(DISTINCT td2.domain)
        FROM trusted_domains td2
        INNER JOIN trusted_sources ts2 ON ts2.id = td2.source_id
        WHERE ts2.enabled = 1 AND td2.label = td.label
      ) AS label_domain_count
    FROM trusted_domains td
    INNER JOIN trusted_sources ts ON ts.id = td.source_id
    WHERE ts.enabled = 1
      AND td.label IS NOT NULL
      AND td.label_length >= 5
    ORDER BY ts.kind = 'manual' DESC, td.rank IS NULL ASC, td.rank ASC
    LIMIT 2000
  `)
  const brands: ContentTrustedBrand[] = []

  try {
    while (statement.step()) {
      const row = statement.getAsObject() as Record<string, unknown>
      const domain = typeof row.domain === 'string' ? row.domain : ''
      const label = typeof row.label === 'string' ? row.label : ''
      const labelDomainCount = Number(row.label_domain_count) || 0

      if (domain && label) {
        brands.push({
          domain,
          label,
          isGenericLabel: labelDomainCount >= GENERIC_TRUSTED_LABEL_DOMAIN_COUNT_THRESHOLD
        })
      }
    }
  } finally {
    statement.free()
  }

  return brands
}

async function fetchPageHtmlForContentAnalysis(
  candidate: NormalizedSiteCandidate
): Promise<string | null> {
  try {
    const response = await fetch(candidate.normalizedUrl, {
      cache: 'no-store',
      redirect: 'follow',
      signal: AbortSignal.timeout(CONTENT_ANALYSIS_FETCH_TIMEOUT_MS),
      headers: {
        accept: 'text/html,application/xhtml+xml'
      }
    })

    if (!response.ok) {
      return null
    }

    const contentType = response.headers.get('content-type') ?? ''

    if (!contentType.toLowerCase().includes('text/html')) {
      return null
    }

    const html = await response.text()
    return html.slice(0, CONTENT_ANALYSIS_MAX_HTML_CHARS)
  } catch {
    return null
  }
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
  if (await isTrustedDomain(candidate.asciiHostname)) {
    return null
  }

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

async function evaluateLookalikeTrustedDomainRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  if (!candidate.registrableDomain || candidate.isIp) {
    return null
  }

  const matchedTrustedDomain = await findLookalikeTrustedDomain(candidate.registrableDomain)

  if (!matchedTrustedDomain) {
    return null
  }

  return {
    ruleId: 'lookalike-trusted-domain',
    matched: true,
    scoreDelta: getRuleScoreDelta(
      'lookalike-trusted-domain',
      DEFAULT_LOOKALIKE_TRUSTED_DOMAIN_SCORE_DELTA,
      settings
    ),
    severity: 'warning',
    code: `lookalike-trusted-domain:${matchedTrustedDomain}`,
    message:
      'Domena wygląda podobnie do jednej z zaufanych domen, ale nie jest tą samą domeną.'
  }
}

async function evaluateTrustedDomainInSubdomainRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  const matchedTrustedDomain = await findTrustedDomainMentionedInSubdomain(candidate)

  if (!matchedTrustedDomain) {
    return null
  }

  return {
    ruleId: 'trusted-domain-in-subdomain',
    matched: true,
    scoreDelta: getRuleScoreDelta(
      'trusted-domain-in-subdomain',
      DEFAULT_TRUSTED_DOMAIN_IN_SUBDOMAIN_SCORE_DELTA,
      settings
    ),
    severity: 'warning',
    code: `trusted-domain-in-subdomain:${matchedTrustedDomain}`,
    message:
      'Subdomena zawiera nazwę zaufanej domeny, ale prawdziwa domena strony jest inna.'
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

function getUrlRiskPatternMatch(candidate: NormalizedSiteCandidate): string | null {
  const urlSignal = `${candidate.path}${candidate.query}`.toLowerCase()
  const patterns: Array<[RegExp, string]> = [
    [/\bphishing\b/i, 'phishing'],
    [/\bmalware\b/i, 'malware'],
    [/\bunwanted\b/i, 'unwanted'],
    [/\bpua\b/i, 'pua'],
    [/\bsuspicious\b/i, 'suspicious'],
    [/\bbad[_-]login\b/i, 'bad-login'],
    [/\blow[_-]rep[_-]login\b/i, 'low-reputation-login'],
    [/\btrick[_-]to[_-]bill\b/i, 'billing-trick'],
    [/\bcookie[_-]theft\b/i, 'cookie-theft'],
    [/\bbadrep\b/i, 'bad-reputation-download'],
    [/\bbad[_-]app\b/i, 'bad-application-download'],
    [/\bforce[_-]csd\b/i, 'forced-download-scan'],
    [/\blocal[_-]trigger[_-]csd\b/i, 'local-download-scan'],
    [/\brestricted[_-]content\b/i, 'restricted-content'],
    [/\.(?:exe|apk|msi|scr|bat|cmd|vbs|ps1|jar)(?:$|[?#])/i, 'dangerous-file-extension'],
    [/\.(?:zip|rar|7z)(?:$|[?#])/i, 'archive-download']
  ]

  return patterns.find(([pattern]) => pattern.test(urlSignal))?.[1] ?? null
}

async function evaluateUrlRiskPatternRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  const matchedPattern = getUrlRiskPatternMatch(candidate)

  if (!matchedPattern) {
    return null
  }

  return {
    ruleId: 'url-risk-pattern',
    matched: true,
    scoreDelta: getRuleScoreDelta(
      'url-risk-pattern',
      DEFAULT_URL_RISK_PATTERN_SCORE_DELTA,
      settings
    ),
    severity: 'blocking',
    code: `url-risk-pattern:${matchedPattern}`,
    message:
      'Adres zawiera wzorzec często spotykany przy stronach phishingowych, malware albo ryzykownych pobraniach.'
  }
}

async function evaluateYoungDomainAgeRule(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult | null> {
  if (!candidate.registrableDomain || candidate.isIp) {
    return null
  }

  if (await isTrustedDomain(candidate.asciiHostname)) {
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

function getContentRuleFallbackScore(ruleId: ContentAnalysisFindingId): number {
  switch (ruleId) {
    case 'content-sensitive-form':
      return DEFAULT_CONTENT_SENSITIVE_FORM_SCORE_DELTA
    case 'content-cross-origin-form':
      return DEFAULT_CONTENT_CROSS_ORIGIN_FORM_SCORE_DELTA
    case 'content-brand-impersonation':
      return DEFAULT_CONTENT_BRAND_IMPERSONATION_SCORE_DELTA
    case 'content-urgent-language':
      return DEFAULT_CONTENT_URGENT_LANGUAGE_SCORE_DELTA
    case 'content-suspicious-iframe':
      return DEFAULT_CONTENT_SUSPICIOUS_IFRAME_SCORE_DELTA
    case 'content-download-risk':
      return DEFAULT_CONTENT_DOWNLOAD_RISK_SCORE_DELTA
    case 'content-threat-link-catalog':
      return DEFAULT_CONTENT_THREAT_LINK_CATALOG_SCORE_DELTA
  }
}

async function evaluatePageContentRules(
  candidate: NormalizedSiteCandidate,
  settings: ReputationSettings
): Promise<ReputationRuleResult[]> {
  const contentRuleIds: ContentAnalysisFindingId[] = [
    'content-sensitive-form',
    'content-cross-origin-form',
    'content-brand-impersonation',
    'content-urgent-language',
    'content-suspicious-iframe',
    'content-download-risk',
    'content-threat-link-catalog'
  ]

  if (contentRuleIds.every((ruleId) => settings.disabledRuleIds.includes(ruleId))) {
    return []
  }

  if (await isTrustedDomain(candidate.asciiHostname)) {
    return []
  }

  const html = await fetchPageHtmlForContentAnalysis(candidate)

  if (!html) {
    return []
  }

  const trustedBrands = await loadContentTrustedBrands()
  const findings = analyzePageContent(html, candidate, trustedBrands)

  return findings
    .filter((finding) => !settings.disabledRuleIds.includes(finding.id))
    .map((finding) => ({
      ruleId: finding.id,
      matched: true,
      scoreDelta: getRuleScoreDelta(
        finding.id,
        getContentRuleFallbackScore(finding.id),
        settings
      ),
      severity: 'warning',
      code: finding.code,
      message: finding.message
    }))
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

  if (isGovernmentDomainCandidate(candidate) || (await isTrustedDomain(candidate.asciiHostname))) {
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
      id: 'lookalike-trusted-domain' as const,
      evaluate: evaluateLookalikeTrustedDomainRule
    },
    {
      id: 'trusted-domain-in-subdomain' as const,
      evaluate: evaluateTrustedDomainInSubdomainRule
    },
    {
      id: 'is-ip' as const,
      evaluate: evaluateIpAddressRule
    },
    {
      id: 'url-risk-pattern' as const,
      evaluate: evaluateUrlRiskPatternRule
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

  const preliminaryScore = matchedRules.reduce((sum, result) => sum + result.scoreDelta, 0)

  if (preliminaryScore < settings.blockedThreshold) {
    matchedRules.push(...(await evaluatePageContentRules(candidate, settings)))
  }

  const score = Math.min(100, matchedRules.reduce((sum, result) => sum + result.scoreDelta, 0))
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
  setLastReputationStatus(assessment)

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

  recordSecurityEvent(assessment, interventionState)
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
  hideSecurityTooltip()
  setReputationIntervention(null)
  setDnsFailure(null)
  setLastReputationStatus(null)
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
  const database = getAppDatabase()
  database.run('DELETE FROM users')

  const statement = database.prepare(`
    INSERT INTO users (id, name, initials, description, created_at, is_active)
    VALUES ($id, $name, $initials, $description, $createdAt, $isActive)
  `)

  for (const user of store.users) {
    statement.run({
      $id: user.id,
      $name: user.name,
      $initials: user.initials,
      $description: user.description,
      $createdAt: user.createdAt,
      $isActive: store.activeUserId === user.id ? 1 : 0
    })
  }

  statement.free()
  userStore = normalizeStore(store)
  saveTrustedDomainsDatabase(database)
}

function loadUserStore(): UserStore {
  if (userStore) {
    return userStore
  }

  const database = getAppDatabase()
  const statement = database.prepare(`
    SELECT id, name, initials, description, created_at, is_active
    FROM users
    ORDER BY created_at ASC
  `)
  const users: UserProfile[] = []
  let activeUserId: string | null = null

  while (statement.step()) {
    const row = statement.getAsObject() as Record<string, unknown>
    const user: UserProfile = {
      id: String(row.id),
      name: String(row.name),
      initials: String(row.initials),
      description: String(row.description),
      createdAt: String(row.created_at)
    }
    users.push(user)

    if (Number(row.is_active) === 1) {
      activeUserId = user.id
    }
  }

  statement.free()
  userStore = normalizeStore({ users, activeUserId })
  return userStore
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
  void userId
}

function hasStoredUserDataKey(userId: string): boolean {
  void userId
  return true
}

function removeStoredUserDataKey(userId: string): void {
  void userId
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
    return DEFAULT_SEARCH_HOME_URL
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return isSafeBrowserUrl(trimmed) ? trimmed : DEFAULT_SEARCH_HOME_URL
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
    reputationStatus: dnsFailureState ? null : lastReputationStatus,
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

    if (
      isSafeBrowserUrl(navigationUrl) &&
      isGovernmentDomainCandidate(normalizeSiteCandidate(navigationUrl))
    ) {
      setReputationIntervention(null)
      setDnsFailure(null)
      lastError = null
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
  view.webContents.on('did-stop-loading', () => {
    syncBrowserState()
    void refreshReputationStatusForLoadedUrl(view.webContents.getURL(), view)
  })
  view.webContents.on('did-navigate', (_event, navigationUrl) => {
    setDnsFailure(null)
    setReputationIntervention(null)
    applyCachedPageFavicon(navigationUrl, true)
    void updateBrowserFavicon(view)
    void refreshReputationStatusForLoadedUrl(navigationUrl, view)
  })
  view.webContents.on('did-navigate-in-page', (_event, navigationUrl) => {
    setDnsFailure(null)
    setReputationIntervention(null)
    applyCachedPageFavicon(navigationUrl)
    void updateBrowserFavicon(view)
    void refreshReputationStatusForLoadedUrl(navigationUrl, view)
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
  mainWindow.on('resize', hideSecurityTooltip)
  mainWindow.on('resize', updatePermissionPromptBounds)
  mainWindow.on('move', hideSecurityTooltip)
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
  hideSecurityTooltip()
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
  hideSecurityTooltip()
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
  hideSecurityTooltip()
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

ipcMain.handle('security-events:list-recent', () => {
  return listRecentSecurityEvents()
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

ipcMain.handle('trusted-domains:get-sources', () => {
  return loadTrustedDomainSources()
})

ipcMain.handle('trusted-domains:set-enabled', (_event, id: string, enabled: boolean) => {
  return setTrustedDomainSourceEnabled(id, enabled)
})

ipcMain.handle('trusted-domains:sync-source', (_event, id: string) => {
  return syncTrustedDomainSource(id)
})

ipcMain.handle('trusted-domains:get-custom-domains', () => {
  return loadCustomTrustedDomains()
})

ipcMain.handle('trusted-domains:add-custom-domain', (_event, value: string) => {
  return addCustomTrustedDomain(value)
})

ipcMain.handle('trusted-domains:remove-custom-domain', (_event, domain: string) => {
  return removeCustomTrustedDomain(domain)
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

ipcMain.handle('security-tooltip:show', (_event, payload: SecurityTooltipPayload) => {
  showSecurityTooltip(payload)
})

ipcMain.handle('security-tooltip:hide', () => {
  hideSecurityTooltip()
})

ipcMain.handle('browser:set-chrome-height', (_event, height: number) => {
  if (!Number.isFinite(height) || height < 0) {
    return
  }

  browserChromeHeight = Math.round(height)
  updateBrowserBounds()
})

app
  .whenReady()
  .then(async () => {
    await initializeAppDatabase()

    const store = loadUserStore()
    store.activeUserId = null
    saveUserStore(store)
    void ensureTrustedDomainSourcesReady()

    createMainWindow()

    app.on('activate', () => {
      if (BrowserWindow.getAllWindows().length === 0) {
        createMainWindow()
      }
    })
  })
  .catch((error) => {
    console.error('[app-startup] failed to initialize application', error)
    app.quit()
  })

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
