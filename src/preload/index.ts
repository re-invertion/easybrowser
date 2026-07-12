import { contextBridge, ipcRenderer } from 'electron'

type BrowserState = {
  mode: 'home' | 'browser'
  url: string
  title: string
  isLoading: boolean
  canGoBack: boolean
  canGoForward: boolean
  isMaximized: boolean
  error: string | null
  hasMicrophoneAccess: boolean
  hasCameraAccess: boolean
  isFavorite: boolean
  browserFaviconUrl: string | null
  reputationIntervention: {
    url: string
    decision: 'warning' | 'blocked'
    eventCode: string
    title: string
    message: string
    canContinue: boolean
    matchedRules: Array<{
      ruleId:
        | 'insecure-http'
        | 'domain-blocklist'
        | 'non-latin-script'
        | 'is-ip'
        | 'google-safe-browsing'
        | 'young-domain-age'
      matched: boolean
      scoreDelta: number
      severity: 'warning' | 'blocking'
      code: string
      message: string
    }>
  } | null
  dnsFailure: {
    url: string
    eventCode: 'no-dns-found'
  } | null
}

type UserProfile = {
  id: string
  initials: string
  name: string
  description: string
  createdAt: string
}

type FavoriteEntry = {
  url: string
  title: string
  faviconUrl: string | null
  createdAt: string
  updatedAt: string
}

type UserState = {
  users: UserProfile[]
  activeUserId: string | null
  favorites: FavoriteEntry[]
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
type ReputationSettings = {
  enabled: boolean
  warningThreshold: number
  blockedThreshold: number
  disabledRuleIds: Array<
    | 'insecure-http'
    | 'domain-blocklist'
    | 'non-latin-script'
    | 'is-ip'
    | 'google-safe-browsing'
    | 'young-domain-age'
  >
  ruleWeights: Partial<
    Record<
      | 'insecure-http'
      | 'domain-blocklist'
      | 'non-latin-script'
      | 'is-ip'
      | 'google-safe-browsing'
      | 'young-domain-age',
      number
    >
  >
  youngDomainMaxAgeDays: number
  googleSafeBrowsingApiKeyConfigured: boolean
}
type ReputationAssessmentPreview = {
  normalizedUrl: string
  score: number
  decision: 'allow' | 'warning' | 'blocked'
  matchedRules: Array<{
    ruleId:
      | 'insecure-http'
      | 'domain-blocklist'
      | 'non-latin-script'
      | 'is-ip'
      | 'google-safe-browsing'
      | 'young-domain-age'
    matched: boolean
    scoreDelta: number
    severity: 'warning' | 'blocking'
    code: string
    message: string
  }>
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
type TrustedDomainSource = {
  id: string
  name: string
  kind: 'tranco'
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

contextBridge.exposeInMainWorld('easybrowser', {
  version: '1.0.0',
  getUserState: () => ipcRenderer.invoke('users:get-state') as Promise<UserState>,
  selectUser: (userId: string) =>
    ipcRenderer.invoke('users:select', userId) as Promise<UserState>,
  clearActiveUser: () =>
    ipcRenderer.invoke('users:clear-active') as Promise<UserState>,
  createUser: (name: string) =>
    ipcRenderer.invoke('users:create', name) as Promise<UserState>,
  deleteUser: (userId: string) =>
    ipcRenderer.invoke('users:delete', userId) as Promise<UserState>,
  navigate: (value: string) => ipcRenderer.invoke('browser:navigate', value),
  goHome: () => ipcRenderer.invoke('browser:home'),
  continueReputationWarning: () => ipcRenderer.invoke('browser:continue-reputation-warning'),
  goBack: () => ipcRenderer.invoke('browser:back'),
  goForward: () => ipcRenderer.invoke('browser:forward'),
  reload: () => ipcRenderer.invoke('browser:reload'),
  toggleFavorite: () => ipcRenderer.invoke('browser:toggle-favorite') as Promise<boolean>,
  removeFavorite: (url: string) =>
    ipcRenderer.invoke('browser:remove-favorite', url) as Promise<UserState>,
  getAdminPinStatus: () => ipcRenderer.invoke('admin:get-pin-status') as Promise<AdminPinStatus>,
  setAdminPin: (pin: string) => ipcRenderer.invoke('admin:set-pin', pin) as Promise<AdminPinStatus>,
  verifyAdminPin: (pin: string) =>
    ipcRenderer.invoke('admin:verify-pin', pin) as Promise<AdminPinStatus>,
  clearAdminSession: () =>
    ipcRenderer.invoke('admin:clear-session') as Promise<AdminPinStatus>,
  getAccessibilitySettings: () =>
    ipcRenderer.invoke('accessibility:get-settings') as Promise<AccessibilitySettings>,
  setVisibleFocus: (visibleFocus: boolean) =>
    ipcRenderer.invoke('accessibility:set-visible-focus', visibleFocus) as Promise<AccessibilitySettings>,
  getReputationSettings: () =>
    ipcRenderer.invoke('reputation:get-settings') as Promise<ReputationSettings>,
  updateReputationSettings: (
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
  ) => ipcRenderer.invoke('reputation:update-settings', value) as Promise<ReputationSettings>,
  setGoogleSafeBrowsingApiKey: (value: string | null) =>
    ipcRenderer.invoke('reputation:set-google-safe-browsing-api-key', value) as Promise<ReputationSettings>,
  assessReputationUrl: (rawUrl: string) =>
    ipcRenderer.invoke('reputation:assess-url', rawUrl) as Promise<ReputationAssessmentPreview>,
  getDomainBlocklistSources: () =>
    ipcRenderer.invoke('domain-blocklists:get-sources') as Promise<DomainBlocklistSource[]>,
  addDomainBlocklistSource: (url: string) =>
    ipcRenderer.invoke('domain-blocklists:add-source', url) as Promise<DomainBlocklistSource[]>,
  setDomainBlocklistSourceEnabled: (id: string, enabled: boolean) =>
    ipcRenderer.invoke('domain-blocklists:set-enabled', id, enabled) as Promise<DomainBlocklistSource[]>,
  setDomainBlocklistSourceScoreDelta: (id: string, scoreDelta: number) =>
    ipcRenderer.invoke('domain-blocklists:set-score-delta', id, scoreDelta) as Promise<DomainBlocklistSource[]>,
  removeDomainBlocklistSource: (id: string) =>
    ipcRenderer.invoke('domain-blocklists:remove-source', id) as Promise<DomainBlocklistSource[]>,
  getTrustedDomainSources: () =>
    ipcRenderer.invoke('trusted-domains:get-sources') as Promise<TrustedDomainSource[]>,
  setTrustedDomainSourceEnabled: (id: string, enabled: boolean) =>
    ipcRenderer.invoke('trusted-domains:set-enabled', id, enabled) as Promise<TrustedDomainSource[]>,
  syncTrustedDomainSource: (id: string) =>
    ipcRenderer.invoke('trusted-domains:sync-source', id) as Promise<TrustedDomainSource[]>,
  toggleMaximize: () => ipcRenderer.invoke('browser:toggle-maximize'),
  minimizeWindow: () => ipcRenderer.invoke('window:minimize'),
  closeWindow: () => ipcRenderer.invoke('window:close'),
  copyText: (value: string) => ipcRenderer.invoke('clipboard:copy-text', value),
  setBrowserChromeHeight: (height: number) =>
    ipcRenderer.invoke('browser:set-chrome-height', height),
  onBrowserStateChange: (callback: (state: BrowserState) => void) => {
    const listener = (_event: unknown, state: BrowserState) => {
      callback(state)
    }

    ipcRenderer.on('browser:state', listener)

    return () => {
      ipcRenderer.removeListener('browser:state', listener)
    }
  }
})
