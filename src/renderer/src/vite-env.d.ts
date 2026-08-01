/// <reference types="vite/client" />

declare global {
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
    | 'content-sensitive-form'
    | 'content-cross-origin-form'
    | 'content-brand-impersonation'
    | 'content-urgent-language'
    | 'content-suspicious-iframe'
    | 'content-download-risk'
    | 'content-threat-link-catalog'

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
    reputationStatus: {
      url: string
      score: number
      decision: 'allow' | 'warning' | 'blocked'
      warningThreshold: number
      blockedThreshold: number
      matchedRuleCount: number
    } | null
    reputationIntervention: {
      url: string
      decision: 'warning' | 'blocked'
      eventCode: string
      title: string
      message: string
      canContinue: boolean
      matchedRules: Array<{
        ruleId: ReputationRuleId
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
    disabledRuleIds: ReputationRuleId[]
    ruleWeights: Partial<Record<ReputationRuleId, number>>
    youngDomainMaxAgeDays: number
    googleSafeBrowsingApiKeyConfigured: boolean
  }

  type ReputationAssessmentPreview = {
    normalizedUrl: string
    score: number
    decision: 'allow' | 'warning' | 'blocked'
    matchedRules: Array<{
      ruleId: ReputationRuleId
      matched: boolean
      scoreDelta: number
      severity: 'warning' | 'blocking'
      code: string
      message: string
    }>
  }

  type SecurityEventLog = {
    id: string
    userId: string | null
    url: string
    hostname: string | null
    decision: 'warning' | 'blocked'
    eventCode: string
    score: number
    matchedRules: Array<{
      ruleId: string
      scoreDelta: number
      severity: string
      code: string
    }>
    createdAt: string
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
    kind: 'tranco' | 'manual'
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
    decision: 'allow' | 'warning' | 'blocked' | null
    warningThreshold: number | null
    blockedThreshold: number | null
    matchedRuleCount: number | null
  }

  interface Window {
    easybrowser: {
      version: string
      getUserState: () => Promise<UserState>
      selectUser: (userId: string) => Promise<UserState>
      clearActiveUser: () => Promise<UserState>
      createUser: (name: string) => Promise<UserState>
      deleteUser: (userId: string) => Promise<UserState>
      navigate: (value: string) => Promise<void>
      goHome: () => Promise<void>
      continueReputationWarning: () => Promise<void>
      goBack: () => Promise<void>
      goForward: () => Promise<void>
      reload: () => Promise<void>
      toggleFavorite: () => Promise<boolean>
      removeFavorite: (url: string) => Promise<UserState>
      getAdminPinStatus: () => Promise<AdminPinStatus>
      setAdminPin: (pin: string) => Promise<AdminPinStatus>
      verifyAdminPin: (pin: string) => Promise<AdminPinStatus>
      clearAdminSession: () => Promise<AdminPinStatus>
      getAccessibilitySettings: () => Promise<AccessibilitySettings>
      setVisibleFocus: (visibleFocus: boolean) => Promise<AccessibilitySettings>
      getReputationSettings: () => Promise<ReputationSettings>
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
      ) => Promise<ReputationSettings>
      setGoogleSafeBrowsingApiKey: (value: string | null) => Promise<ReputationSettings>
      assessReputationUrl: (rawUrl: string) => Promise<ReputationAssessmentPreview>
      getSecurityEventLogs: () => Promise<SecurityEventLog[]>
      getDomainBlocklistSources: () => Promise<DomainBlocklistSource[]>
      addDomainBlocklistSource: (url: string) => Promise<DomainBlocklistSource[]>
      setDomainBlocklistSourceEnabled: (
        id: string,
        enabled: boolean
      ) => Promise<DomainBlocklistSource[]>
      setDomainBlocklistSourceScoreDelta: (
        id: string,
        scoreDelta: number
      ) => Promise<DomainBlocklistSource[]>
      removeDomainBlocklistSource: (id: string) => Promise<DomainBlocklistSource[]>
      getTrustedDomainSources: () => Promise<TrustedDomainSource[]>
      setTrustedDomainSourceEnabled: (
        id: string,
        enabled: boolean
      ) => Promise<TrustedDomainSource[]>
      syncTrustedDomainSource: (id: string) => Promise<TrustedDomainSource[]>
      getCustomTrustedDomains: () => Promise<CustomTrustedDomain[]>
      addCustomTrustedDomain: (value: string) => Promise<CustomTrustedDomain[]>
      removeCustomTrustedDomain: (domain: string) => Promise<CustomTrustedDomain[]>
      toggleMaximize: () => Promise<void>
      minimizeWindow: () => Promise<void>
      closeWindow: () => Promise<void>
      copyText: (value: string) => Promise<void>
      showSecurityTooltip: (payload: SecurityTooltipPayload) => Promise<void>
      hideSecurityTooltip: () => Promise<void>
      setBrowserChromeHeight: (height: number) => Promise<void>
      onBrowserStateChange: (
        callback: (state: BrowserState) => void
      ) => () => void
    }
  }
}

export {}
