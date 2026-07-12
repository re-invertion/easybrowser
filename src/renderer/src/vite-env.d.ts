/// <reference types="vite/client" />

declare global {
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
        | 'lookalike-trusted-domain'
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
        | 'lookalike-trusted-domain'
      | 'is-ip'
      | 'google-safe-browsing'
      | 'young-domain-age'
    >
    ruleWeights: Partial<
      Record<
        | 'insecure-http'
        | 'domain-blocklist'
        | 'non-latin-script'
        | 'lookalike-trusted-domain'
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
        | 'lookalike-trusted-domain'
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
      setBrowserChromeHeight: (height: number) => Promise<void>
      onBrowserStateChange: (
        callback: (state: BrowserState) => void
      ) => () => void
    }
  }
}

export {}
