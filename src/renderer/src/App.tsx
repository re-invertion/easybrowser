import { FormEvent, useEffect, useRef, useState } from 'react'
import {
  FiAlertTriangle,
  FiCamera,
  FiChevronDown,
  FiChevronUp,
  FiMic,
  FiMoreVertical,
  FiRefreshCw,
  FiShield,
  FiStar,
  FiTrash2,
  FiX
} from 'react-icons/fi'

type ViewMode = 'home' | 'browser'
type AppMenuMode = 'closed' | 'main'
type AdminGateMode = 'closed' | 'setup' | 'verify'
type AdminTab = 'overview' | 'security'

type BrowserAccessIndicatorState = {
  hasMicrophoneAccess: boolean
  hasCameraAccess: boolean
}

const GOOGLE_HOME_URL = 'https://www.google.pl/?hl=pl&gl=PL&pws=0'

function getAdminLockMessage(lockedUntil: string | null): string | null {
  if (!lockedUntil) {
    return null
  }

  const remainingMs = Date.parse(lockedUntil) - Date.now()

  if (!Number.isFinite(remainingMs) || remainingMs <= 0) {
    return null
  }

  const remainingSeconds = Math.max(1, Math.ceil(remainingMs / 1000))
  return `Panel administracyjny jest zablokowany jeszcze przez około ${remainingSeconds} s.`
}

function getFavoriteFaviconUrl(rawUrl: string): string | null {
  try {
    const parsedUrl = new URL(rawUrl)
    return `${parsedUrl.origin}/favicon.ico`
  } catch {
    return null
  }
}

function getPageFallbackFaviconUrl(rawUrl: string): string | null {
  try {
    const parsedUrl = new URL(rawUrl)

    if (!/^https?:$/.test(parsedUrl.protocol)) {
      return null
    }

    return `https://www.google.com/s2/favicons?domain=${encodeURIComponent(parsedUrl.hostname)}&sz=64`
  } catch {
    return null
  }
}

function getSecurityEventDecisionLabel(decision: SecurityEventLog['decision']): string {
  return decision === 'blocked' ? 'Blokada' : 'Ostrzeżenie'
}

function getSecurityEventDecisionClass(decision: SecurityEventLog['decision']): string {
  return decision === 'blocked'
    ? 'border-red-200 bg-red-50 text-red-700'
    : 'border-amber-200 bg-amber-50 text-amber-800'
}

function getFaviconCandidates(rawUrl: string, faviconUrl: string | null): string[] {
  const candidates = [
    faviconUrl,
    getFavoriteFaviconUrl(rawUrl),
    getPageFallbackFaviconUrl(rawUrl)
  ]

  return candidates.filter((candidate, index): candidate is string => {
    return typeof candidate === 'string' && candidate.length > 0 && candidates.indexOf(candidate) === index
  })
}

function getFavoriteBadgeLabel(title: string): string {
  const trimmedTitle = title.trim()

  if (!trimmedTitle) {
    return '?'
  }

  return trimmedTitle.slice(0, 1).toUpperCase()
}

function normalizeAddress(value: string): string {
  const trimmed = value.trim()

  if (trimmed.length === 0) {
    return GOOGLE_HOME_URL
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }

  if (/^[^\s]+\.[^\s]+$/.test(trimmed)) {
    return `https://${trimmed}`
  }

  return `https://www.google.pl/search?hl=pl&gl=PL&pws=0&q=${encodeURIComponent(trimmed)}`
}

function normalizeReputationTestUrl(value: string): string {
  const trimmed = value.trim()

  if (trimmed.length === 0) {
    throw new Error('Wpisz adres URL do sprawdzenia.')
  }

  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed
  }

  if (/^[^\s]+\.[^\s]+$/.test(trimmed)) {
    return `https://${trimmed}`
  }

  throw new Error('Wpisz poprawny adres URL, na przykład https://example.com.')
}

function getFilterDraftFromSettings(settings: ReputationSettings) {
  return {
    httpEnabled: !settings.disabledRuleIds.includes('insecure-http'),
    httpScore: settings.ruleWeights['insecure-http'] ?? 50,
    nonLatinEnabled: !settings.disabledRuleIds.includes('non-latin-script'),
    nonLatinScore: settings.ruleWeights['non-latin-script'] ?? 25,
    lookalikeTrustedDomainEnabled: !settings.disabledRuleIds.includes('lookalike-trusted-domain'),
    lookalikeTrustedDomainScore: settings.ruleWeights['lookalike-trusted-domain'] ?? 60,
    trustedDomainInSubdomainEnabled: !settings.disabledRuleIds.includes(
      'trusted-domain-in-subdomain'
    ),
    trustedDomainInSubdomainScore: settings.ruleWeights['trusted-domain-in-subdomain'] ?? 50,
    ipEnabled: !settings.disabledRuleIds.includes('is-ip'),
    ipScore: settings.ruleWeights['is-ip'] ?? 40,
    googleSafeBrowsingEnabled:
      settings.googleSafeBrowsingApiKeyConfigured &&
      !settings.disabledRuleIds.includes('google-safe-browsing'),
    googleSafeBrowsingScore: settings.ruleWeights['google-safe-browsing'] ?? 100,
    youngDomainEnabled: !settings.disabledRuleIds.includes('young-domain-age'),
    youngDomainScore: settings.ruleWeights['young-domain-age'] ?? 35,
    youngDomainMaxAgeDays: settings.youngDomainMaxAgeDays,
    blocklistsEnabled: !settings.disabledRuleIds.includes('domain-blocklist')
  }
}

function WindowControls({
  isMaximized,
  onMinimize,
  onToggleMaximize,
  onClose
}: {
  isMaximized: boolean
  onMinimize: () => void
  onToggleMaximize: () => void
  onClose: () => void
}) {
  return (
    <div className="app-no-drag flex items-center gap-2">
      <button
        aria-label="Minimalizuj okno"
        className="window-control-button"
        type="button"
        onClick={onMinimize}
      >
        <span className="window-control-line" />
      </button>

      <button
        aria-label={isMaximized ? 'Przywróć rozmiar okna' : 'Maksymalizuj okno'}
        className="window-control-button"
        type="button"
        onClick={onToggleMaximize}
      >
        {isMaximized ? (
          <svg
            aria-hidden="true"
            className="h-3.5 w-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <rect x="7" y="7" width="10" height="10" rx="1" />
            <path d="M10 7V5h9v9h-2" />
          </svg>
        ) : (
          <svg
            aria-hidden="true"
            className="h-3.5 w-3.5"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
          >
            <rect x="5" y="5" width="14" height="14" rx="1" />
          </svg>
        )}
      </button>

      <button
        aria-label="Zamknij okno"
        className="window-control-button window-control-button-close"
        type="button"
        onClick={onClose}
      >
        <svg
          aria-hidden="true"
          className="h-3.5 w-3.5"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="2"
        >
          <path d="m6 6 12 12" />
          <path d="M18 6 6 18" />
        </svg>
      </button>
    </div>
  )
}

function BrowserAccessIndicator({
  hasMicrophoneAccess,
  hasCameraAccess
}: BrowserAccessIndicatorState) {
  if (!hasMicrophoneAccess && !hasCameraAccess) {
    return null
  }

  if (hasMicrophoneAccess && hasCameraAccess) {
    return (
      <div className="flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm font-bold text-emerald-800">
        <div className="flex items-center gap-1.5 text-emerald-700">
          <FiCamera aria-hidden="true" className="h-4 w-4" />
          <FiMic aria-hidden="true" className="h-4 w-4" />
        </div>
        <span>Ta strona korzysta z mikrofonu i kamery</span>
      </div>
    )
  }

  if (hasCameraAccess) {
    return (
      <div className="flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm font-bold text-emerald-800">
        <FiCamera aria-hidden="true" className="h-4 w-4 text-emerald-700" />
        <span>Ta strona korzysta z kamery</span>
      </div>
    )
  }

  return (
    <div className="flex items-center gap-2 rounded-full border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm font-bold text-emerald-800">
      <FiMic aria-hidden="true" className="h-4 w-4 text-emerald-700" />
      <span>Ta strona korzysta z mikrofonu</span>
    </div>
  )
}

function FavoriteTileIcon({
  title,
  url,
  faviconUrl
}: {
  title: string
  url: string
  faviconUrl: string | null
}) {
  const [faviconCandidateIndex, setFaviconCandidateIndex] = useState(0)
  const faviconCandidates = getFaviconCandidates(url, faviconUrl)
  const resolvedFaviconUrl = faviconCandidates[faviconCandidateIndex] ?? null

  useEffect(() => {
    setFaviconCandidateIndex(0)
  }, [faviconUrl, url])

  if (!resolvedFaviconUrl) {
    return (
      <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-amber-100 text-base font-bold text-amber-700">
        {getFavoriteBadgeLabel(title)}
      </div>
    )
  }

  return (
    <div className="flex h-11 w-11 items-center justify-center overflow-hidden rounded-2xl bg-white ring-1 ring-slate-200">
      <img
        src={resolvedFaviconUrl}
        alt=""
        className="h-6 w-6 object-contain"
        onError={() => {
          setFaviconCandidateIndex((currentIndex) => currentIndex + 1)
        }}
      />
    </div>
  )
}

function BrowserAddressFavicon({
  faviconUrl,
  url,
  title
}: {
  faviconUrl: string | null
  url: string
  title: string
}) {
  const [faviconCandidateIndex, setFaviconCandidateIndex] = useState(0)
  const faviconCandidates = getFaviconCandidates(url, faviconUrl)
  const resolvedFaviconUrl = faviconCandidates[faviconCandidateIndex] ?? null

  useEffect(() => {
    setFaviconCandidateIndex(0)
  }, [faviconUrl, url])

  if (!resolvedFaviconUrl) {
    return (
      <div className="flex h-7 min-h-7 w-7 min-w-7 shrink-0 aspect-square items-center justify-center rounded-full bg-slate-100 text-xs font-bold text-slate-500">
        {getFavoriteBadgeLabel(title)}
      </div>
    )
  }

  return (
    <div className="flex h-7 min-h-7 w-7 min-w-7 shrink-0 aspect-square items-center justify-center overflow-hidden rounded-full bg-white ring-1 ring-slate-200">
      <img
        src={resolvedFaviconUrl}
        alt=""
        className="h-4 w-4 object-contain"
        onError={() => {
          setFaviconCandidateIndex((currentIndex) => currentIndex + 1)
        }}
      />
    </div>
  )
}

function AppBrandMenu({
  isOpen,
  onOpen,
  onOpenAdminPanel
}: {
  isOpen: boolean
  onOpen: () => void
  onOpenAdminPanel: () => void
}) {
  return (
    <div className="app-no-drag relative" data-app-menu-root="main">
      <div
        className="inline-flex items-center rounded-xl px-2 py-1 text-sm font-bold text-app-text"
        onContextMenu={(event) => {
          event.preventDefault()
          onOpen()
        }}
      >
        Przegladarka
      </div>

      {isOpen ? (
        <div className="absolute top-[calc(100%+0.45rem)] left-0 z-30 min-w-[220px] rounded-2xl border border-app-tile-border bg-app-tile p-2 shadow-[0_18px_40px_rgba(148,163,184,0.18)]">
          <button
            type="button"
            className="focus-ring flex w-full rounded-xl px-3 py-2.5 text-left text-sm font-medium text-app-text transition hover:bg-slate-100"
            onClick={onOpenAdminPanel}
          >
            Panel administracyjny
          </button>
        </div>
      ) : null}
    </div>
  )
}

function App() {
  const browserChromeRef = useRef<HTMLElement | null>(null)
  const isEditingAddressRef = useRef(false)
  const [mode, setMode] = useState<ViewMode>('home')
  const [users, setUsers] = useState<UserProfile[]>([])
  const [favorites, setFavorites] = useState<FavoriteEntry[]>([])
  const [selectedUserId, setSelectedUserId] = useState<string | null>(null)
  const [isLoadingUsers, setIsLoadingUsers] = useState(true)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [inputValue, setInputValue] = useState('')
  const [currentUrl, setCurrentUrl] = useState(GOOGLE_HOME_URL)
  const [pageTitle, setPageTitle] = useState('Easybrowser')
  const [isLoading, setIsLoading] = useState(false)
  const [canGoBack, setCanGoBack] = useState(false)
  const [canGoForward, setCanGoForward] = useState(false)
  const [isMaximized, setIsMaximized] = useState(false)
  const [hasMicrophoneAccess, setHasMicrophoneAccess] = useState(false)
  const [hasCameraAccess, setHasCameraAccess] = useState(false)
  const [isFavorite, setIsFavorite] = useState(false)
  const [browserFaviconUrl, setBrowserFaviconUrl] = useState<string | null>(null)
  const [reputationIntervention, setReputationIntervention] =
    useState<BrowserState['reputationIntervention']>(null)
  const [dnsFailure, setDnsFailure] = useState<BrowserState['dnsFailure']>(null)
  const [copyNoticeVisible, setCopyNoticeVisible] = useState(false)
  const [isAddingUser, setIsAddingUser] = useState(false)
  const [newUserName, setNewUserName] = useState('')
  const [openUserMenuId, setOpenUserMenuId] = useState<string | null>(null)
  const [openAppMenu, setOpenAppMenu] = useState<AppMenuMode>('closed')
  const [isAdminPanelOpen, setIsAdminPanelOpen] = useState(false)
  const [adminTab, setAdminTab] = useState<AdminTab>('overview')
  const [adminPinStatus, setAdminPinStatus] = useState<AdminPinStatus | null>(null)
  const [adminGateMode, setAdminGateMode] = useState<AdminGateMode>('closed')
  const [adminPinValue, setAdminPinValue] = useState('')
  const [adminPinConfirmValue, setAdminPinConfirmValue] = useState('')
  const [adminPinErrorMessage, setAdminPinErrorMessage] = useState<string | null>(null)
  const [isSubmittingAdminPin, setIsSubmittingAdminPin] = useState(false)
  const [accessibilitySettings, setAccessibilitySettings] = useState<AccessibilitySettings>({
    visibleFocus: true
  })
  const [reputationSettings, setReputationSettings] = useState<ReputationSettings>({
    enabled: true,
    warningThreshold: 50,
    blockedThreshold: 70,
    disabledRuleIds: [],
    ruleWeights: {},
    youngDomainMaxAgeDays: 30,
    googleSafeBrowsingApiKeyConfigured: false
  })
  const [domainBlocklistSources, setDomainBlocklistSources] = useState<DomainBlocklistSource[]>([])
  const [trustedDomainSources, setTrustedDomainSources] = useState<TrustedDomainSource[]>([])
  const [customTrustedDomains, setCustomTrustedDomains] = useState<CustomTrustedDomain[]>([])
  const [securityEventLogs, setSecurityEventLogs] = useState<SecurityEventLog[]>([])
  const [isLoadingSecurityEventLogs, setIsLoadingSecurityEventLogs] = useState(false)
  const [isSecurityEventsPanelOpen, setIsSecurityEventsPanelOpen] = useState(false)
  const [filterSettingsDraft, setFilterSettingsDraft] = useState(() =>
    getFilterDraftFromSettings({
      enabled: true,
      warningThreshold: 50,
      blockedThreshold: 70,
      disabledRuleIds: [],
      ruleWeights: {},
      youngDomainMaxAgeDays: 30,
      googleSafeBrowsingApiKeyConfigured: false
    })
  )
  const [domainBlocklistSourcesDraft, setDomainBlocklistSourcesDraft] = useState<DomainBlocklistSource[]>([])
  const [newDomainBlocklistUrl, setNewDomainBlocklistUrl] = useState('')
  const [newCustomTrustedDomain, setNewCustomTrustedDomain] = useState('')
  const [googleSafeBrowsingApiKeyInput, setGoogleSafeBrowsingApiKeyInput] = useState('')
  const [shouldClearGoogleSafeBrowsingApiKey, setShouldClearGoogleSafeBrowsingApiKey] =
    useState(false)
  const [reputationTestUrl, setReputationTestUrl] = useState('')
  const [reputationTestResult, setReputationTestResult] = useState<ReputationAssessmentPreview | null>(null)
  const [reputationTestError, setReputationTestError] = useState<string | null>(null)
  const [isCheckingReputationTest, setIsCheckingReputationTest] = useState(false)
  const [isSavingFilterSettings, setIsSavingFilterSettings] = useState(false)
  const [syncingTrustedDomainSourceId, setSyncingTrustedDomainSourceId] = useState<string | null>(null)
  const [isHttpRuleExpanded, setIsHttpRuleExpanded] = useState(false)
  const [isNonLatinRuleExpanded, setIsNonLatinRuleExpanded] = useState(false)
  const [isLookalikeTrustedDomainRuleExpanded, setIsLookalikeTrustedDomainRuleExpanded] =
    useState(false)
  const [isTrustedDomainInSubdomainRuleExpanded, setIsTrustedDomainInSubdomainRuleExpanded] =
    useState(false)
  const [isIpRuleExpanded, setIsIpRuleExpanded] = useState(false)
  const [isGoogleSafeBrowsingRuleExpanded, setIsGoogleSafeBrowsingRuleExpanded] =
    useState(false)
  const [isYoungDomainRuleExpanded, setIsYoungDomainRuleExpanded] = useState(false)
  const [areBlocklistsExpanded, setAreBlocklistsExpanded] = useState(false)
  const [userPendingDeletion, setUserPendingDeletion] = useState<UserProfile | null>(null)

  const selectedUser = users.find((user) => user.id === selectedUserId) ?? null
  const hasPendingGoogleSafeBrowsingApiKey = googleSafeBrowsingApiKeyInput.trim().length > 0
  const canEnableGoogleSafeBrowsing =
    hasPendingGoogleSafeBrowsingApiKey ||
    (reputationSettings.googleSafeBrowsingApiKeyConfigured && !shouldClearGoogleSafeBrowsingApiKey)
  const currentGoogleSafeBrowsingEnabled =
    reputationSettings.googleSafeBrowsingApiKeyConfigured &&
    !reputationSettings.disabledRuleIds.includes('google-safe-browsing')
  const hasFilterSettingsChanges =
    filterSettingsDraft.httpEnabled !==
      !reputationSettings.disabledRuleIds.includes('insecure-http') ||
    filterSettingsDraft.httpScore !== (reputationSettings.ruleWeights['insecure-http'] ?? 50) ||
    filterSettingsDraft.nonLatinEnabled !==
      !reputationSettings.disabledRuleIds.includes('non-latin-script') ||
    filterSettingsDraft.nonLatinScore !==
      (reputationSettings.ruleWeights['non-latin-script'] ?? 25) ||
    filterSettingsDraft.lookalikeTrustedDomainEnabled !==
      !reputationSettings.disabledRuleIds.includes('lookalike-trusted-domain') ||
    filterSettingsDraft.lookalikeTrustedDomainScore !==
      (reputationSettings.ruleWeights['lookalike-trusted-domain'] ?? 60) ||
    filterSettingsDraft.trustedDomainInSubdomainEnabled !==
      !reputationSettings.disabledRuleIds.includes('trusted-domain-in-subdomain') ||
    filterSettingsDraft.trustedDomainInSubdomainScore !==
      (reputationSettings.ruleWeights['trusted-domain-in-subdomain'] ?? 50) ||
    filterSettingsDraft.ipEnabled !== !reputationSettings.disabledRuleIds.includes('is-ip') ||
    filterSettingsDraft.ipScore !== (reputationSettings.ruleWeights['is-ip'] ?? 40) ||
    filterSettingsDraft.googleSafeBrowsingEnabled !== currentGoogleSafeBrowsingEnabled ||
    filterSettingsDraft.googleSafeBrowsingScore !==
      (reputationSettings.ruleWeights['google-safe-browsing'] ?? 100) ||
    filterSettingsDraft.youngDomainEnabled !==
      !reputationSettings.disabledRuleIds.includes('young-domain-age') ||
    filterSettingsDraft.youngDomainScore !==
      (reputationSettings.ruleWeights['young-domain-age'] ?? 35) ||
    filterSettingsDraft.youngDomainMaxAgeDays !== reputationSettings.youngDomainMaxAgeDays ||
    filterSettingsDraft.blocklistsEnabled !==
      !reputationSettings.disabledRuleIds.includes('domain-blocklist') ||
    googleSafeBrowsingApiKeyInput.trim().length > 0 ||
    shouldClearGoogleSafeBrowsingApiKey ||
    domainBlocklistSourcesDraft.length !== domainBlocklistSources.length ||
    domainBlocklistSourcesDraft.some((draftSource) => {
      const currentSource = domainBlocklistSources.find((source) => source.id === draftSource.id)

      if (!currentSource) {
        return true
      }

      return (
        currentSource.enabled !== draftSource.enabled ||
        currentSource.scoreDelta !== draftSource.scoreDelta
      )
    })

  useEffect(() => {
    const loadUsers = async () => {
      try {
        const [
          state,
          nextAdminPinStatus,
          nextAccessibilitySettings,
          nextReputationSettings,
          nextDomainBlocklistSources,
          nextTrustedDomainSources,
          nextCustomTrustedDomains,
          nextSecurityEventLogs
        ] =
          await Promise.all([
          window.easybrowser.getUserState(),
          window.easybrowser.getAdminPinStatus(),
          window.easybrowser.getAccessibilitySettings(),
          window.easybrowser.getReputationSettings(),
          window.easybrowser.getDomainBlocklistSources(),
          window.easybrowser.getTrustedDomainSources(),
          window.easybrowser.getCustomTrustedDomains(),
          window.easybrowser.getSecurityEventLogs()
        ])
        setUsers(state.users)
        setSelectedUserId(state.activeUserId)
        setFavorites(state.favorites)
        setAdminPinStatus(nextAdminPinStatus)
        setAccessibilitySettings(nextAccessibilitySettings)
        setReputationSettings(nextReputationSettings)
        setDomainBlocklistSources(nextDomainBlocklistSources)
        setTrustedDomainSources(nextTrustedDomainSources)
        setCustomTrustedDomains(nextCustomTrustedDomains)
        setSecurityEventLogs(nextSecurityEventLogs)
      } catch (error) {
        setErrorMessage(
          error instanceof Error ? error.message : 'Nie udało się wczytać użytkowników.'
        )
      } finally {
        setIsLoadingUsers(false)
      }
    }

    const unsubscribe = window.easybrowser.onBrowserStateChange((state: BrowserState) => {
      setMode(state.mode)
      setCurrentUrl(state.url || GOOGLE_HOME_URL)
      if (state.mode !== 'browser') {
        setInputValue('')
      } else if (!isEditingAddressRef.current) {
        setInputValue(state.url || '')
      }
      setPageTitle(state.title || 'Easybrowser')
      setIsLoading(state.isLoading)
      setCanGoBack(state.canGoBack)
      setCanGoForward(state.canGoForward)
      setIsMaximized(state.isMaximized)
      setHasMicrophoneAccess(state.hasMicrophoneAccess)
      setHasCameraAccess(state.hasCameraAccess)
      setIsFavorite(state.isFavorite)
      setBrowserFaviconUrl(state.browserFaviconUrl)
      setReputationIntervention(state.reputationIntervention)
      setDnsFailure(state.dnsFailure)
      setErrorMessage(state.error)
    })

    void loadUsers()

    return unsubscribe
  }, [])

  useEffect(() => {
    if (mode !== 'browser') {
      return
    }

    const element = browserChromeRef.current

    if (!element) {
      return
    }

    const updateHeight = () => {
      void window.easybrowser.setBrowserChromeHeight(element.offsetHeight)
    }

    updateHeight()

    const observer = new ResizeObserver(() => {
      updateHeight()
    })

    observer.observe(element)
    window.addEventListener('resize', updateHeight)

    return () => {
      observer.disconnect()
      window.removeEventListener('resize', updateHeight)
    }
  }, [mode, canGoBack, canGoForward, inputValue, isMaximized])

  useEffect(() => {
    if (!openUserMenuId) {
      return
    }

    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target

      if (!(target instanceof HTMLElement)) {
        return
      }

      if (target.closest(`[data-user-menu-root="${openUserMenuId}"]`)) {
        return
      }

      setOpenUserMenuId(null)
    }

    window.addEventListener('pointerdown', handlePointerDown)

    return () => {
      window.removeEventListener('pointerdown', handlePointerDown)
    }
  }, [openUserMenuId])

  useEffect(() => {
    if (openAppMenu === 'closed') {
      return
    }

    const handlePointerDown = (event: PointerEvent) => {
      const target = event.target

      if (!(target instanceof HTMLElement)) {
        return
      }

      if (target.closest('[data-app-menu-root="main"]')) {
        return
      }

      setOpenAppMenu('closed')
    }

    window.addEventListener('pointerdown', handlePointerDown)

    return () => {
      window.removeEventListener('pointerdown', handlePointerDown)
    }
  }, [openAppMenu])

  useEffect(() => {
    document.documentElement.dataset.visibleFocus = accessibilitySettings.visibleFocus
      ? 'on'
      : 'off'
  }, [accessibilitySettings.visibleFocus])

  useEffect(() => {
    setFilterSettingsDraft(getFilterDraftFromSettings(reputationSettings))
  }, [reputationSettings])

  useEffect(() => {
    setDomainBlocklistSourcesDraft(domainBlocklistSources)
  }, [domainBlocklistSources])

  useEffect(() => {
    setGoogleSafeBrowsingApiKeyInput('')
    setShouldClearGoogleSafeBrowsingApiKey(false)
  }, [reputationSettings.googleSafeBrowsingApiKeyConfigured])

  useEffect(() => {
    if (!canEnableGoogleSafeBrowsing) {
      setFilterSettingsDraft((current) => ({
        ...current,
        googleSafeBrowsingEnabled: false
      }))
    }
  }, [canEnableGoogleSafeBrowsing])

  const applyUserState = (state: UserState) => {
    setUsers(state.users)
    setSelectedUserId(state.activeUserId)
    setFavorites(state.favorites)
    setErrorMessage(null)
  }

  const resetAdminPinForm = () => {
    setAdminPinValue('')
    setAdminPinConfirmValue('')
    setAdminPinErrorMessage(null)
  }

  const refreshAdminPinStatus = async () => {
    const nextStatus = await window.easybrowser.getAdminPinStatus()
    setAdminPinStatus(nextStatus)
    return nextStatus
  }

  const openInBrowser = async (rawValue: string) => {
    const destination = normalizeAddress(rawValue)
    isEditingAddressRef.current = false
    setInputValue(destination)
    setCurrentUrl(destination)
    setIsLoading(true)
    await window.easybrowser.navigate(destination)
  }

  const handleSearchSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    await openInBrowser(inputValue)
  }

  const handleSelectUser = async (userId: string) => {
    try {
      const state = await window.easybrowser.selectUser(userId)
      applyUserState(state)
      setIsAddingUser(false)
      setNewUserName('')
      setInputValue('')
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się wybrać użytkownika.'
      )
    }
  }

  const handleClearActiveUser = async () => {
    try {
      const state = await window.easybrowser.clearActiveUser()
      const nextAdminPinStatus = await window.easybrowser.clearAdminSession()
      applyUserState(state)
      setAdminPinStatus(nextAdminPinStatus)
      setIsAddingUser(false)
      setIsAdminPanelOpen(false)
      setAdminGateMode('closed')
      setOpenAppMenu('closed')
      setNewUserName('')
      setInputValue('')
      setCurrentUrl(GOOGLE_HOME_URL)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić użytkownika.'
      )
    }
  }

  const handleAddUser = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    try {
      const state = await window.easybrowser.createUser(newUserName)
      applyUserState(state)
      setIsAddingUser(false)
      setNewUserName('')
      setInputValue('')
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się dodać użytkownika.'
      )
    }
  }

  const handleDeleteUser = async (userId: string) => {
    try {
      const state = await window.easybrowser.deleteUser(userId)
      applyUserState(state)
      setOpenUserMenuId(null)
      setUserPendingDeletion(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się usunąć użytkownika.'
      )
    }
  }

  const goHome = async () => {
    await window.easybrowser.goHome()
    setIsAdminPanelOpen(false)
    setAdminGateMode('closed')
    setOpenAppMenu('closed')
    setInputValue('')
    setCurrentUrl(GOOGLE_HOME_URL)
    setPageTitle('Easybrowser')
    setIsLoading(false)
    setCanGoBack(false)
    setCanGoForward(false)
  }

  const navigateBack = () => {
    void window.easybrowser.goBack()
  }

  const navigateForward = () => {
    void window.easybrowser.goForward()
  }

  const reloadPage = () => {
    void window.easybrowser.reload()
  }

  const toggleMaximize = () => {
    void window.easybrowser.toggleMaximize()
  }

  const copyCurrentUrl = () => {
    void window.easybrowser.copyText(currentUrl)
    setCopyNoticeVisible(true)
    window.setTimeout(() => {
      setCopyNoticeVisible(false)
    }, 1600)
  }

  const toggleFavorite = async () => {
    try {
      const nextValue = await window.easybrowser.toggleFavorite()
      setIsFavorite(nextValue)
      const state = await window.easybrowser.getUserState()
      setFavorites(state.favorites)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić ulubionych.'
      )
    }
  }

  const removeFavorite = async (url: string) => {
    try {
      const state = await window.easybrowser.removeFavorite(url)
      applyUserState(state)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się usunąć ulubionej strony.'
      )
    }
  }

  const minimizeWindow = () => {
    void window.easybrowser.minimizeWindow()
  }

  const closeWindow = () => {
    void window.easybrowser.closeWindow()
  }

  const closeDeleteModal = () => {
    setUserPendingDeletion(null)
  }

  const finishOpeningAdminPanel = async () => {
    resetAdminPinForm()
    setAdminGateMode('closed')
    setAdminTab('overview')
    setIsAdminPanelOpen(true)
  }

  const openAdminPanel = async () => {
    setOpenAppMenu('closed')
    resetAdminPinForm()

    try {
      if (mode === 'browser') {
        await window.easybrowser.goHome()
      }

      const nextStatus = await refreshAdminPinStatus()

      if (!nextStatus.isSet) {
        setAdminGateMode('setup')
        return
      }

      if (nextStatus.isSessionUnlocked) {
        await finishOpeningAdminPanel()
        return
      }

      setAdminGateMode('verify')
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się otworzyć panelu administracyjnego.'
      )
    }
  }

  const closeAdminPanel = async () => {
    const nextStatus = await window.easybrowser.clearAdminSession()
    setAdminPinStatus(nextStatus)
    setIsAdminPanelOpen(false)
    setOpenAppMenu('closed')
    resetAdminPinForm()
    setAdminGateMode('closed')
  }

  const closeAdminGate = () => {
    resetAdminPinForm()
    setOpenAppMenu('closed')
    setAdminGateMode('closed')
  }

  const toggleVisibleFocus = async (visibleFocus: boolean) => {
    try {
      const nextSettings = await window.easybrowser.setVisibleFocus(visibleFocus)
      setAccessibilitySettings(nextSettings)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić ustawień dostępności.'
      )
    }
  }

  const applyReputationSettings = async (
    value: Partial<
      Pick<
        ReputationSettings,
        'enabled' | 'warningThreshold' | 'blockedThreshold' | 'ruleWeights' | 'youngDomainMaxAgeDays'
      >
    >
  ) => {
    try {
      const nextSettings = await window.easybrowser.updateReputationSettings(value)
      setReputationSettings(nextSettings)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić ustawień bezpieczeństwa.'
      )
    }
  }

  const updateDomainBlocklistSourceDraft = (
    id: string,
    value: Partial<Pick<DomainBlocklistSource, 'enabled' | 'scoreDelta'>>
  ) => {
    setDomainBlocklistSourcesDraft((current) =>
      current.map((source) => (source.id === id ? { ...source, ...value } : source))
    )
  }

  const handleReputationTestSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    try {
      setIsCheckingReputationTest(true)
      setReputationTestError(null)
      const normalizedUrl = normalizeReputationTestUrl(reputationTestUrl)
      const result = await window.easybrowser.assessReputationUrl(normalizedUrl)
      setReputationTestResult(result)
    } catch (error) {
      setReputationTestResult(null)
      setReputationTestError(
        error instanceof Error ? error.message : 'Nie udało się sprawdzić reputacji adresu.'
      )
    } finally {
      setIsCheckingReputationTest(false)
    }
  }

  const refreshSecurityEventLogs = async () => {
    try {
      setIsLoadingSecurityEventLogs(true)
      const nextLogs = await window.easybrowser.getSecurityEventLogs()
      setSecurityEventLogs(nextLogs)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się wczytać logów bezpieczeństwa.'
      )
    } finally {
      setIsLoadingSecurityEventLogs(false)
    }
  }

  const openSecurityEventsPanel = () => {
    setIsSecurityEventsPanelOpen(true)
    void refreshSecurityEventLogs()
  }

  const handleAddDomainBlocklistSource = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    try {
      const nextSources = await window.easybrowser.addDomainBlocklistSource(newDomainBlocklistUrl)
      setDomainBlocklistSources(nextSources)
      setNewDomainBlocklistUrl('')
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się dodać listy ostrzeżeń.'
      )
    }
  }

  const toggleDomainBlocklistSourceEnabled = async (id: string, enabled: boolean) => {
    try {
      const nextSources = await window.easybrowser.setDomainBlocklistSourceEnabled(id, enabled)
      setDomainBlocklistSources(nextSources)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić stanu listy ostrzeżeń.'
      )
    }
  }

  const handleSaveFilterSettings = async () => {
    try {
      setIsSavingFilterSettings(true)

      const nextDisabledRuleIds: ReputationSettings['disabledRuleIds'] = []

      if (!filterSettingsDraft.httpEnabled) {
        nextDisabledRuleIds.push('insecure-http')
      }

      if (!filterSettingsDraft.nonLatinEnabled) {
        nextDisabledRuleIds.push('non-latin-script')
      }

      if (!filterSettingsDraft.lookalikeTrustedDomainEnabled) {
        nextDisabledRuleIds.push('lookalike-trusted-domain')
      }

      if (!filterSettingsDraft.trustedDomainInSubdomainEnabled) {
        nextDisabledRuleIds.push('trusted-domain-in-subdomain')
      }

      if (!filterSettingsDraft.ipEnabled) {
        nextDisabledRuleIds.push('is-ip')
      }

      if (!filterSettingsDraft.googleSafeBrowsingEnabled || !canEnableGoogleSafeBrowsing) {
        nextDisabledRuleIds.push('google-safe-browsing')
      }

      if (!filterSettingsDraft.youngDomainEnabled) {
        nextDisabledRuleIds.push('young-domain-age')
      }

      if (!filterSettingsDraft.blocklistsEnabled) {
        nextDisabledRuleIds.push('domain-blocklist')
      }

      if (shouldClearGoogleSafeBrowsingApiKey) {
        await window.easybrowser.setGoogleSafeBrowsingApiKey(null)
      } else if (googleSafeBrowsingApiKeyInput.trim().length > 0) {
        await window.easybrowser.setGoogleSafeBrowsingApiKey(googleSafeBrowsingApiKeyInput)
      }

      const savedSettings = await window.easybrowser.updateReputationSettings({
        disabledRuleIds: nextDisabledRuleIds,
        ruleWeights: {
          'insecure-http': filterSettingsDraft.httpScore,
          'non-latin-script': filterSettingsDraft.nonLatinScore,
          'lookalike-trusted-domain': filterSettingsDraft.lookalikeTrustedDomainScore,
          'trusted-domain-in-subdomain': filterSettingsDraft.trustedDomainInSubdomainScore,
          'is-ip': filterSettingsDraft.ipScore,
          'google-safe-browsing': filterSettingsDraft.googleSafeBrowsingScore,
          'young-domain-age': filterSettingsDraft.youngDomainScore
        },
        youngDomainMaxAgeDays: filterSettingsDraft.youngDomainMaxAgeDays
      })

      let nextSources = domainBlocklistSources

      for (const draftSource of domainBlocklistSourcesDraft) {
        const currentSource = nextSources.find((source) => source.id === draftSource.id)

        if (!currentSource) {
          continue
        }

        if (currentSource.enabled !== draftSource.enabled) {
          nextSources = await window.easybrowser.setDomainBlocklistSourceEnabled(
            draftSource.id,
            draftSource.enabled
          )
        }

        const sourceAfterEnabledUpdate = nextSources.find((source) => source.id === draftSource.id)

        if (
          sourceAfterEnabledUpdate &&
          sourceAfterEnabledUpdate.scoreDelta !== draftSource.scoreDelta
        ) {
          nextSources = await window.easybrowser.setDomainBlocklistSourceScoreDelta(
            draftSource.id,
            draftSource.scoreDelta
          )
        }
      }

      setReputationSettings(savedSettings)
      setDomainBlocklistSources(nextSources)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zapisać ustawień filtrów.'
      )
    } finally {
      setIsSavingFilterSettings(false)
    }
  }

  const handleRemoveDomainBlocklistSource = async (id: string) => {
    try {
      const nextSources = await window.easybrowser.removeDomainBlocklistSource(id)
      setDomainBlocklistSources(nextSources)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się usunąć listy ostrzeżeń.'
      )
    }
  }

  const handleToggleTrustedDomainSource = async (id: string, enabled: boolean) => {
    try {
      const nextSources = await window.easybrowser.setTrustedDomainSourceEnabled(id, enabled)
      setTrustedDomainSources(nextSources)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zmienić źródła zaufanych domen.'
      )
    }
  }

  const handleSyncTrustedDomainSource = async (id: string) => {
    try {
      setSyncingTrustedDomainSourceId(id)
      const nextSources = await window.easybrowser.syncTrustedDomainSource(id)
      setTrustedDomainSources(nextSources)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zsynchronizować źródła zaufanych domen.'
      )
    } finally {
      setSyncingTrustedDomainSourceId(null)
    }
  }

  const handleAddCustomTrustedDomain = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    try {
      const nextDomains = await window.easybrowser.addCustomTrustedDomain(newCustomTrustedDomain)
      setCustomTrustedDomains(nextDomains)
      setNewCustomTrustedDomain('')
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się dodać domeny do allowlisty.'
      )
    }
  }

  const handleRemoveCustomTrustedDomain = async (domain: string) => {
    try {
      const nextDomains = await window.easybrowser.removeCustomTrustedDomain(domain)
      setCustomTrustedDomains(nextDomains)
      setErrorMessage(null)
    } catch (error) {
      setErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się usunąć domeny z allowlisty.'
      )
    }
  }

  const handleAdminPinSetupSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()

    if (adminPinValue !== adminPinConfirmValue) {
      setAdminPinErrorMessage('Oba pola PIN-u muszą być identyczne.')
      return
    }

    setIsSubmittingAdminPin(true)
    setAdminPinErrorMessage(null)

    try {
      const nextStatus = await window.easybrowser.setAdminPin(adminPinValue)
      setAdminPinStatus(nextStatus)
      await finishOpeningAdminPanel()
    } catch (error) {
      setAdminPinErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się ustawić PIN-u administratora.'
      )
      await refreshAdminPinStatus()
    } finally {
      setIsSubmittingAdminPin(false)
    }
  }

  const handleAdminPinVerifySubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    setIsSubmittingAdminPin(true)
    setAdminPinErrorMessage(null)

    try {
      const nextStatus = await window.easybrowser.verifyAdminPin(adminPinValue)
      setAdminPinStatus(nextStatus)
      await finishOpeningAdminPanel()
    } catch (error) {
      setAdminPinErrorMessage(
        error instanceof Error ? error.message : 'Nie udało się zweryfikować PIN-u administratora.'
      )
      await refreshAdminPinStatus()
    } finally {
      setIsSubmittingAdminPin(false)
    }
  }

  const adminGateModal = adminGateMode !== 'closed' ? (
    <div
      className="absolute inset-0 z-[220] flex items-center justify-center bg-slate-950/36 px-4 backdrop-blur-[3px]"
      onClick={() => {
        if (!isSubmittingAdminPin) {
          closeAdminGate()
        }
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="admin-pin-title"
        className="w-full max-w-md rounded-[28px] border border-app-tile-border bg-white p-6 shadow-[0_28px_80px_rgba(15,23,42,0.24)]"
        onClick={(event) => {
          event.stopPropagation()
        }}
      >
        <div className="flex items-start justify-between gap-4">
          <div>
            <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
              Administracja
            </p>
            <h2 id="admin-pin-title" className="mt-2 text-2xl font-bold text-app-text">
              {adminGateMode === 'setup'
                ? 'Ustaw PIN administratora'
                : 'Wpisz PIN administratora'}
            </h2>
            <p className="mt-2 text-sm leading-6 text-slate-500">
              {adminGateMode === 'setup'
                ? 'Ten PIN będzie potrzebny przed każdym wejściem do panelu administracyjnego.'
                : 'Aby otworzyć panel administracyjny, wpisz wcześniej ustawiony PIN.'}
            </p>
          </div>

          <button
            type="button"
            aria-label="Zamknij okno PIN-u administratora"
            className="focus-ring flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-slate-400 transition hover:bg-slate-100 hover:text-app-text"
            onClick={closeAdminGate}
            disabled={isSubmittingAdminPin}
          >
            <FiX aria-hidden="true" className="h-5 w-5" />
          </button>
        </div>

        <form
          className="mt-6"
          onSubmit={(event) => {
            if (adminGateMode === 'setup') {
              void handleAdminPinSetupSubmit(event)
              return
            }

            void handleAdminPinVerifySubmit(event)
          }}
        >
          <label className="mb-2 block text-sm font-bold text-app-text" htmlFor="admin-pin">
            PIN
          </label>
          <input
            id="admin-pin"
            type="password"
            inputMode="numeric"
            autoComplete="off"
            value={adminPinValue}
            onChange={(event) => setAdminPinValue(event.target.value)}
            placeholder="4 do 6 cyfr"
            className="focus-ring w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base tracking-[0.22em] text-app-text placeholder:tracking-normal placeholder:text-slate-400 focus:outline-none"
            autoFocus
            disabled={isSubmittingAdminPin}
          />

          {adminGateMode === 'setup' ? (
            <>
              <label
                className="mt-4 mb-2 block text-sm font-bold text-app-text"
                htmlFor="admin-pin-confirm"
              >
                Powtórz PIN
              </label>
              <input
                id="admin-pin-confirm"
                type="password"
                inputMode="numeric"
                autoComplete="off"
                value={adminPinConfirmValue}
                onChange={(event) => setAdminPinConfirmValue(event.target.value)}
                placeholder="Wpisz PIN ponownie"
                className="focus-ring w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base tracking-[0.22em] text-app-text placeholder:tracking-normal placeholder:text-slate-400 focus:outline-none"
                disabled={isSubmittingAdminPin}
              />
            </>
          ) : null}

          {adminGateMode === 'verify' && adminPinStatus ? (
            <p className="mt-3 text-sm text-slate-500">
              Pozostało prób: {adminPinStatus.remainingAttempts}
            </p>
          ) : null}

          {getAdminLockMessage(adminPinStatus?.lockedUntil ?? null) ? (
            <div className="mt-4 rounded-2xl border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-800">
              {getAdminLockMessage(adminPinStatus?.lockedUntil ?? null)}
            </div>
          ) : null}

          {adminPinErrorMessage ? (
            <div className="mt-4 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
              {adminPinErrorMessage}
            </div>
          ) : null}

          <div className="mt-6 flex flex-wrap justify-end gap-3">
            <button
              type="button"
              className="focus-ring rounded-full border border-app-tile-border px-5 py-3 text-sm font-bold text-app-text"
              onClick={closeAdminGate}
              disabled={isSubmittingAdminPin}
            >
              Anuluj
            </button>
            <button
              type="submit"
              className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text disabled:cursor-not-allowed disabled:opacity-50"
              disabled={
                isSubmittingAdminPin ||
                Boolean(getAdminLockMessage(adminPinStatus?.lockedUntil ?? null))
              }
            >
              {adminGateMode === 'setup' ? 'Ustaw PIN i otwórz panel' : 'Otwórz panel'}
            </button>
          </div>
        </form>
      </div>
    </div>
  ) : null

  if (isLoadingUsers) {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full items-center justify-center">
          <h1 className="text-2xl font-bold md:text-3xl">Ładowanie użytkowników...</h1>
        </div>
      </main>
    )
  }

  if (mode === 'browser') {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
          <header
            ref={(node) => {
              browserChromeRef.current = node
            }}
            className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]"
          >
            <div className="flex h-12 items-center justify-between border-b border-app-tile-border px-4">
              <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
                <AppBrandMenu
                  isOpen={openAppMenu === 'main'}
                  onOpen={() => {
                    setOpenAppMenu('main')
                  }}
                  onOpenAdminPanel={() => {
                    void openAdminPanel()
                  }}
                />
                <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                  <span className="app-drag-label text-xs font-medium text-slate-400">
                    Przeciągnij okno
                  </span>
                </div>
              </div>

              <WindowControls
                isMaximized={isMaximized}
                onMinimize={minimizeWindow}
                onToggleMaximize={toggleMaximize}
                onClose={closeWindow}
              />
            </div>

            <div className="mx-auto flex w-full max-w-7xl flex-col gap-2 px-4 py-2.5">
              <div className="flex flex-wrap items-center gap-2">
                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-4 py-2 text-sm font-bold text-app-text disabled:cursor-not-allowed disabled:opacity-40"
                  type="button"
                  onClick={navigateBack}
                  disabled={!canGoBack}
                >
                  Wstecz
                </button>

                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-4 py-2 text-sm font-bold text-app-text disabled:cursor-not-allowed disabled:opacity-40"
                  type="button"
                  onClick={navigateForward}
                  disabled={!canGoForward}
                >
                  Dalej
                </button>

                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-4 py-2 text-sm font-bold text-app-text"
                  type="button"
                  onClick={reloadPage}
                >
                  Odśwież
                </button>

                <button
                  className="focus-ring rounded-full border border-app-tile-border bg-slate-50 px-4 py-2 text-sm font-bold text-app-text hover:bg-slate-100"
                  type="button"
                  onClick={goHome}
                >
                  Strona główna
                </button>

                <form
                  className="min-w-[320px] flex-1 rounded-full border border-app-tile-border bg-app-tile px-4 py-1"
                  onSubmit={handleSearchSubmit}
                >
                  <label className="sr-only" htmlFor="browser-address">
                    Adres strony lub wyszukiwanie
                  </label>
                  <div className="flex items-center gap-2">
                    <BrowserAddressFavicon
                      faviconUrl={browserFaviconUrl}
                      url={currentUrl}
                      title={pageTitle}
                    />

                    <input
                      id="browser-address"
                      type="text"
                      value={inputValue}
                      onFocus={() => {
                        isEditingAddressRef.current = true
                      }}
                      onBlur={() => {
                        isEditingAddressRef.current = false
                      }}
                      onChange={(event) => setInputValue(event.target.value)}
                      className="focus-ring w-full rounded-full bg-transparent px-3 py-1 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                      placeholder="Wpisz adres strony lub wyszukaj"
                    />

                    <div className="relative flex shrink-0 items-center">
                      <button
                        aria-label={
                          isFavorite
                            ? 'Usuń stronę z ulubionych'
                            : 'Dodaj stronę do ulubionych'
                        }
                        className={`focus-ring flex h-8 w-8 items-center justify-center rounded-full transition-colors ${
                          isFavorite
                            ? 'bg-amber-100 text-amber-600 hover:bg-amber-200'
                            : 'text-slate-500 hover:bg-slate-100 hover:text-app-text'
                        }`}
                        type="button"
                        onClick={() => {
                          void toggleFavorite()
                        }}
                      >
                        <FiStar
                          aria-hidden="true"
                          className="h-4 w-4"
                          style={isFavorite ? { fill: 'currentColor' } : undefined}
                        />
                      </button>

                      <button
                        aria-label="Kopiuj adres strony"
                        className="focus-ring flex h-8 w-8 items-center justify-center rounded-full text-slate-500 transition-colors hover:bg-slate-100 hover:text-app-text"
                        type="button"
                        onClick={copyCurrentUrl}
                      >
                        <svg
                          aria-hidden="true"
                          className="h-4 w-4"
                          viewBox="0 0 24 24"
                          fill="none"
                          stroke="currentColor"
                          strokeWidth="2"
                        >
                          <rect x="9" y="9" width="10" height="10" rx="1" />
                          <rect x="5" y="5" width="10" height="10" rx="1" />
                        </svg>
                      </button>

                      {copyNoticeVisible ? (
                        <div className="pointer-events-none absolute bottom-[calc(100%+0.4rem)] right-0 z-[9999] whitespace-nowrap rounded-xl bg-slate-900 px-3 py-2 text-xs font-medium text-white shadow-lg">
                          Skopiowano do schowka
                        </div>
                      ) : null}
                    </div>
                  </div>
                </form>

                <BrowserAccessIndicator
                  hasMicrophoneAccess={hasMicrophoneAccess}
                  hasCameraAccess={hasCameraAccess}
                />
              </div>
            </div>
          </header>

          <section className="min-h-0 flex-1 overflow-hidden bg-white">
            {reputationIntervention ? (
              <div
                className={`flex h-full w-full items-center justify-center px-4 py-8 ${
                  reputationIntervention.decision === 'blocked'
                    ? 'bg-[radial-gradient(circle_at_top,#fca5a5_0%,#ef4444_38%,#991b1b_100%)]'
                    : 'bg-[radial-gradient(circle_at_top,#fde68a_0%,#fcd34d_38%,#f59e0b_100%)]'
                }`}
              >
                <div
                  className={`w-full max-w-2xl rounded-[32px] bg-white/96 p-8 text-center backdrop-blur ${
                    reputationIntervention.decision === 'blocked'
                      ? 'border border-red-200/50 shadow-[0_30px_90px_rgba(127,29,29,0.35)]'
                      : 'border border-amber-200/70 shadow-[0_30px_90px_rgba(180,83,9,0.22)]'
                  }`}
                >
                  <div
                    className={`mx-auto flex h-16 w-16 items-center justify-center rounded-full ${
                      reputationIntervention.decision === 'blocked'
                        ? 'bg-red-100 text-red-600'
                        : 'bg-amber-100 text-amber-700'
                    }`}
                  >
                    <FiAlertTriangle aria-hidden="true" className="h-8 w-8" />
                  </div>

                  <p
                    className={`mt-5 text-sm font-bold tracking-[0.16em] uppercase ${
                      reputationIntervention.decision === 'blocked'
                        ? 'text-red-500'
                        : 'text-amber-700'
                    }`}
                  >
                    {reputationIntervention.decision === 'blocked'
                      ? 'Ostrzeżenie bezpieczeństwa'
                      : 'Ostrzeżenie o połączeniu'}
                  </p>
                  <h2 className="mt-3 text-3xl leading-tight font-bold text-slate-900">
                    {reputationIntervention.title}
                  </h2>
                  <p className="mt-4 text-base leading-7 text-slate-600">
                    {reputationIntervention.message}
                  </p>
                  <div className="mt-5 rounded-[20px] border border-slate-200 bg-slate-100 px-4 py-3">
                    <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                      Kod zdarzenia
                    </p>
                    <p className="mt-1 break-all text-sm font-bold text-slate-700">
                      {reputationIntervention.eventCode}
                    </p>
                  </div>

                  <div className="mt-8 flex flex-wrap justify-center gap-3">
                    {reputationIntervention.canContinue ? (
                      <button
                        type="button"
                        className="focus-ring rounded-full bg-amber-500 px-6 py-3 text-sm font-bold text-slate-950 transition hover:bg-amber-400"
                        onClick={() => {
                          void window.easybrowser.continueReputationWarning()
                        }}
                      >
                        Kontynuuj
                      </button>
                    ) : null}
                    <button
                      type="button"
                      className={`focus-ring rounded-full px-6 py-3 text-sm font-bold transition ${
                        reputationIntervention.canContinue
                          ? 'border border-amber-300 bg-white text-slate-900 hover:bg-amber-50'
                          : 'bg-red-600 text-white hover:bg-red-700'
                      }`}
                      onClick={() => {
                        void goHome()
                      }}
                    >
                      Wróć do panelu głównego
                    </button>
                  </div>
                </div>
              </div>
            ) : dnsFailure ? (
              <div className="flex h-full w-full items-center justify-center bg-[radial-gradient(circle_at_top,#dbeafe_0%,#bfdbfe_38%,#93c5fd_100%)] px-4 py-8">
                <div className="w-full max-w-2xl rounded-[32px] border border-blue-200/60 bg-white/96 p-8 text-center shadow-[0_30px_90px_rgba(30,64,175,0.18)] backdrop-blur">
                  <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-blue-100 text-blue-700">
                    <FiAlertTriangle aria-hidden="true" className="h-8 w-8" />
                  </div>

                  <p className="mt-5 text-sm font-bold tracking-[0.16em] text-blue-600 uppercase">
                    Problem z adresem strony
                  </p>
                  <h2 className="mt-3 text-3xl leading-tight font-bold text-slate-900">
                    Strona nie istnieje
                  </h2>
                  <p className="mt-4 text-base leading-7 text-slate-600">
                    Nie udało się odnaleźć tej strony w DNS, więc przeglądarka nie mogła jej
                    otworzyć.
                  </p>
                  <div className="mt-5 rounded-[20px] border border-slate-200 bg-slate-100 px-4 py-3">
                    <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                      Kod zdarzenia
                    </p>
                    <p className="mt-1 break-all text-sm font-bold text-slate-700">
                      {dnsFailure.eventCode}
                    </p>
                  </div>

                  <button
                    type="button"
                    className="focus-ring mt-8 rounded-full bg-blue-700 px-6 py-3 text-sm font-bold text-white transition hover:bg-blue-800"
                    onClick={() => {
                      void goHome()
                    }}
                  >
                    Wróć do panelu głównego
                  </button>
                </div>
              </div>
            ) : null}
          </section>
          {adminGateModal}
        </div>
      </main>
    )
  }

  if (isAdminPanelOpen) {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
          <header className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]">
            <div className="flex h-12 items-center justify-between px-4">
              <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
                <AppBrandMenu
                  isOpen={openAppMenu === 'main'}
                  onOpen={() => {
                    setOpenAppMenu('main')
                  }}
                  onOpenAdminPanel={() => {
                    void openAdminPanel()
                  }}
                />
                <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                  <span className="app-drag-label text-xs font-medium text-slate-400">
                    Przeciągnij okno
                  </span>
                </div>
              </div>

              <WindowControls
                isMaximized={isMaximized}
                onMinimize={minimizeWindow}
                onToggleMaximize={toggleMaximize}
                onClose={closeWindow}
              />
            </div>
          </header>

          <section
            className={`min-h-0 flex-1 ${
              isSecurityEventsPanelOpen ? 'overflow-hidden' : 'overflow-y-auto'
            }`}
          >
            <div className="mx-auto w-full max-w-6xl px-4 py-6 sm:px-5 sm:py-8">
              <div className="mb-8 flex flex-wrap items-end justify-between gap-4">
                <div>
                  <p className="text-sm font-bold tracking-[0.16em] text-slate-500 uppercase">
                    Administracja
                  </p>
                  <h1 className="mt-2 text-3xl leading-tight font-bold md:text-5xl">
                    Panel administracyjny
                  </h1>
                  <p className="mt-3 max-w-2xl text-base text-slate-500 md:text-lg">
                    To miejsce na zarządzanie użytkownikami, ustawieniami i ochroną
                    przeglądarki.
                  </p>
                </div>

                <button
                  type="button"
                  className="focus-ring rounded-full border border-app-tile-border bg-app-tile px-5 py-3 text-sm font-bold text-app-text transition hover:bg-slate-50"
                  onClick={() => {
                    void closeAdminPanel()
                  }}
                >
                  Wróć
                </button>
              </div>

              <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
                <div className="rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                  <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                    Użytkownicy
                  </p>
                  <p className="mt-4 text-4xl font-bold text-app-text">{users.length}</p>
                  <p className="mt-2 text-sm text-slate-500">
                    Łączna liczba profili dostępnych w aplikacji.
                  </p>
                </div>

                <div className="rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                  <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                    Aktywny użytkownik
                  </p>
                  <p className="mt-4 text-2xl font-bold text-app-text">
                    {selectedUser?.name ?? 'Brak'}
                  </p>
                  <p className="mt-2 text-sm text-slate-500">
                    Ten profil jest aktualnie wybrany w przeglądarce.
                  </p>
                </div>

                <div className="rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                  <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                    Ulubione
                  </p>
                  <p className="mt-4 text-4xl font-bold text-app-text">{favorites.length}</p>
                  <p className="mt-2 text-sm text-slate-500">
                    Zapisane strony aktywnego użytkownika.
                  </p>
                </div>
              </div>

              <div className="mt-6 flex flex-wrap gap-3">
                <button
                  type="button"
                  className={`focus-ring rounded-full px-5 py-3 text-sm font-bold transition ${
                    adminTab === 'overview'
                      ? 'bg-app-primary text-app-primary-text'
                      : 'border border-app-tile-border bg-app-tile text-app-text hover:bg-slate-50'
                  }`}
                  onClick={() => {
                    setAdminTab('overview')
                    setIsSecurityEventsPanelOpen(false)
                  }}
                >
                  Ogólne
                </button>
                <button
                  type="button"
                  className={`focus-ring rounded-full px-5 py-3 text-sm font-bold transition ${
                    adminTab === 'security'
                      ? 'bg-app-primary text-app-primary-text'
                      : 'border border-app-tile-border bg-app-tile text-app-text hover:bg-slate-50'
                  }`}
                  onClick={() => {
                    setAdminTab('security')
                  }}
                >
                  Security
                </button>
              </div>

              {adminTab === 'overview' ? (
                <>
                  <div className="mt-6 rounded-[28px] border border-dashed border-app-tile-border bg-app-tile/70 p-6 shadow-[0_14px_34px_rgba(148,163,184,0.08)]">
                    <h2 className="text-xl font-bold text-app-text">Co dalej</h2>
                    <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500">
                      Tutaj zarządzasz ochroną przeglądarki, ustawieniami dostępności i źródłami
                      list ostrzeżeń sprawdzanych na żywo przy każdej próbie wejścia na stronę.
                    </p>
                  </div>

                  <div className="mt-6 rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                    <div className="flex flex-wrap items-start justify-between gap-4">
                      <div className="max-w-2xl">
                        <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                          Dostępność
                        </p>
                        <h2 className="mt-2 text-xl font-bold text-app-text">Visible focus</h2>
                        <p className="mt-3 text-sm leading-6 text-slate-500">
                          Włącza albo wyłącza żółte obramowanie elementów, gdy są zaznaczone
                          klawiaturą lub focusem.
                        </p>
                      </div>

                      <label className="app-no-drag flex items-center gap-3 rounded-full border border-app-tile-border bg-slate-50 px-4 py-3 text-sm font-bold text-app-text">
                        <input
                          type="checkbox"
                          className="focus-ring h-5 w-5 rounded border border-app-tile-border accent-[#1e3a8a]"
                          checked={accessibilitySettings.visibleFocus}
                          onChange={(event) => {
                            void toggleVisibleFocus(event.target.checked)
                          }}
                        />
                        <span>Włącz visible focus</span>
                      </label>
                    </div>
                  </div>
                </>
              ) : (
                <>
                  <div className="mt-6 rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                    <div className="flex flex-wrap items-start justify-between gap-4">
                      <div className="max-w-3xl">
                        <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                          Security
                        </p>
                        <h2 className="mt-2 text-xl font-bold text-app-text">
                          Silnik reputacji strony
                        </h2>
                        <p className="mt-3 text-sm leading-6 text-slate-500">
                          Tutaj ustawiasz progi reputacji, punktację reguł i aktywność źródeł,
                          które wpływają na warning albo blokadę strony.
                        </p>
                      </div>

                      <div className="flex flex-wrap items-center gap-3">
                        <button
                          type="button"
                          className="focus-ring inline-flex items-center gap-2 rounded-full border border-app-tile-border bg-slate-50 px-5 py-3 text-sm font-bold text-app-text transition hover:bg-white"
                          onClick={openSecurityEventsPanel}
                        >
                          <FiShield aria-hidden="true" className="h-4 w-4" />
                          Zdarzenia
                          {securityEventLogs.length > 0 ? (
                            <span className="rounded-full bg-app-primary px-2 py-0.5 text-xs text-app-primary-text">
                              {securityEventLogs.length}
                            </span>
                          ) : null}
                        </button>

                        <label className="app-no-drag flex items-center gap-3 rounded-full border border-app-tile-border bg-slate-50 px-4 py-3 text-sm font-bold text-app-text">
                          <input
                            type="checkbox"
                            className="focus-ring h-5 w-5 rounded border border-app-tile-border accent-[#1e3a8a]"
                            checked={reputationSettings.enabled}
                            onChange={(event) => {
                              void applyReputationSettings({ enabled: event.target.checked })
                            }}
                          />
                          <span>{reputationSettings.enabled ? 'Ochrona włączona' : 'Ochrona wyłączona'}</span>
                        </label>
                      </div>
                    </div>

                    <div className="mt-6 grid grid-cols-1 gap-3 sm:grid-cols-3">
                      <div className="rounded-[22px] border border-slate-200 bg-slate-50/80 p-4">
                        <p className="text-[11px] font-bold tracking-[0.14em] text-slate-500 uppercase">
                          Warning
                        </p>
                        <p className="mt-2 text-3xl font-bold text-app-text">
                          {reputationSettings.warningThreshold}
                        </p>
                        <p className="mt-1 text-sm text-slate-500">Punktów do ostrzeżenia</p>
                      </div>

                      <div className="rounded-[22px] border border-slate-200 bg-slate-50/80 p-4">
                        <p className="text-[11px] font-bold tracking-[0.14em] text-slate-500 uppercase">
                          Blokada
                        </p>
                        <p className="mt-2 text-3xl font-bold text-app-text">
                          {reputationSettings.blockedThreshold}
                        </p>
                        <p className="mt-1 text-sm text-slate-500">Punktów do zatrzymania strony</p>
                      </div>

                      <div className="rounded-[22px] border border-slate-200 bg-slate-50/80 p-4">
                        <p className="text-[11px] font-bold tracking-[0.14em] text-slate-500 uppercase">
                          Aktywne listy
                        </p>
                        <p className="mt-2 text-3xl font-bold text-app-text">
                          {domainBlocklistSources.filter((source) => source.enabled).length}
                        </p>
                        <p className="mt-1 text-sm text-slate-500">Źródła wpływające na reputację</p>
                      </div>
                    </div>

                    <div className="mt-6 rounded-[24px] border border-app-tile-border bg-slate-50/70 p-5">
                      <div className="flex flex-wrap items-start justify-between gap-4">
                        <div className="max-w-3xl">
                          <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                            Test reputacji
                          </p>
                          <h3 className="mt-2 text-xl font-bold text-app-text">
                            Sprawdź dowolny adres URL
                          </h3>
                          <p className="mt-3 text-sm leading-6 text-slate-500">
                            Wpisz adres, a silnik reputacji policzy wynik według aktualnych progów
                            i aktywnych filtrów.
                          </p>
                        </div>
                      </div>

                      <form className="mt-5 flex flex-col gap-3 lg:flex-row" onSubmit={handleReputationTestSubmit}>
                        <input
                          type="text"
                          inputMode="url"
                          value={reputationTestUrl}
                          onChange={(event) => {
                            setReputationTestUrl(event.target.value)
                            if (reputationTestError) {
                              setReputationTestError(null)
                            }
                          }}
                          placeholder="https://example.com"
                          className="focus-ring min-w-0 flex-1 rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                        />
                        <button
                          type="submit"
                          disabled={isCheckingReputationTest}
                          className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text disabled:cursor-wait disabled:opacity-70"
                        >
                          {isCheckingReputationTest ? 'Sprawdzanie...' : 'Sprawdź URL'}
                        </button>
                      </form>

                      {reputationTestError ? (
                        <div className="mt-4 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                          {reputationTestError}
                        </div>
                      ) : null}

                      {reputationTestResult ? (
                        <div className="mt-4 rounded-[22px] border border-app-tile-border bg-white p-4">
                          <div className="flex flex-wrap items-start justify-between gap-4">
                            <div className="min-w-0 flex-1">
                              <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                                Sprawdzony adres
                              </p>
                              <p className="mt-2 break-all text-sm font-bold text-app-text">
                                {reputationTestResult.normalizedUrl}
                              </p>
                            </div>

                            <div className="flex flex-wrap gap-3">
                              <div className="rounded-2xl border border-app-tile-border bg-slate-50 px-4 py-3">
                                <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                                  Score
                                </p>
                                <p className="mt-2 text-2xl font-bold text-app-text">
                                  {reputationTestResult.score}
                                </p>
                              </div>

                              <div className="rounded-2xl border border-app-tile-border bg-slate-50 px-4 py-3">
                                <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                                  Wynik
                                </p>
                                <p className="mt-2 text-sm font-bold text-app-text">
                                  {reputationTestResult.decision === 'blocked'
                                    ? 'Zablokowana'
                                    : reputationTestResult.decision === 'warning'
                                      ? 'Ostrzeżenie'
                                      : 'Dozwolona'}
                                </p>
                              </div>
                            </div>
                          </div>

                          <div className="mt-4">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Trafione reguły
                            </p>
                            {reputationTestResult.matchedRules.length > 0 ? (
                              <div className="mt-3 space-y-2">
                                {reputationTestResult.matchedRules.map((rule) => (
                                  <div
                                    key={`${rule.ruleId}-${rule.code}`}
                                    className="rounded-2xl border border-app-tile-border bg-slate-50 px-4 py-3"
                                  >
                                    <div className="flex flex-wrap items-center justify-between gap-3">
                                      <p className="text-sm font-bold text-app-text">{rule.code}</p>
                                      <span className="rounded-full border border-app-tile-border bg-white px-3 py-1 text-xs font-bold text-slate-600">
                                        +{rule.scoreDelta} pkt
                                      </span>
                                    </div>
                                    <p className="mt-2 text-sm leading-6 text-slate-500">
                                      {rule.message}
                                    </p>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <p className="mt-3 text-sm text-slate-500">
                                Brak trafionych reguł dla tego adresu.
                              </p>
                            )}
                          </div>
                        </div>
                      ) : null}
                    </div>
                  </div>

                  <div className="mt-6 rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                    <div className="flex flex-wrap items-start gap-4">
                      <div className="flex h-14 w-14 shrink-0 items-center justify-center rounded-2xl bg-emerald-100 text-emerald-700">
                        <FiShield aria-hidden="true" className="h-7 w-7" />
                      </div>

                      <div className="min-w-0 flex-1">
                        <p className="text-sm font-bold tracking-[0.14em] text-emerald-700 uppercase">
                          Ocena reputacji
                        </p>
                        <h2 className="mt-2 text-2xl font-bold text-app-text">
                          Jak działa scoring bezpieczeństwa
                        </h2>
                        <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-600">
                          Każda reguła dodaje punkty do oceny strony. Gdy suma przekroczy próg
                          warningu, użytkownik zobaczy ostrzeżenie. Gdy przekroczy próg blokady,
                          strona zostanie zatrzymana.
                        </p>
                      </div>
                    </div>

                    <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
                      <label className="block rounded-[24px] border border-app-tile-border bg-slate-50/80 p-4 transition hover:bg-slate-50">
                        <span className="flex items-center gap-2 text-sm font-bold text-app-text">
                          <FiAlertTriangle aria-hidden="true" className="h-4 w-4 text-amber-600" />
                          Próg warning
                        </span>
                        <p className="mt-2 text-sm leading-6 text-slate-500">
                          Po osiągnięciu tego wyniku pokazujemy ostrzeżenie, ale użytkownik może
                          jeszcze kontynuować.
                        </p>
                        <input
                          type="number"
                          min="0"
                          value={reputationSettings.warningThreshold}
                          onChange={(event) => {
                            void applyReputationSettings({
                              warningThreshold: Math.max(0, Number(event.target.value) || 0)
                            })
                          }}
                          className="focus-ring mt-4 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                        />
                      </label>

                      <label className="block rounded-[24px] border border-app-tile-border bg-slate-50/80 p-4 transition hover:bg-slate-50">
                        <span className="flex items-center gap-2 text-sm font-bold text-app-text">
                          <FiShield aria-hidden="true" className="h-4 w-4 text-red-600" />
                          Próg blokady
                        </span>
                        <p className="mt-2 text-sm leading-6 text-slate-500">
                          Po osiągnięciu tego wyniku przeglądarka zatrzyma wejście na stronę.
                        </p>
                        <input
                          type="number"
                          min="0"
                          value={reputationSettings.blockedThreshold}
                          onChange={(event) => {
                            void applyReputationSettings({
                              blockedThreshold: Math.max(0, Number(event.target.value) || 0)
                            })
                          }}
                          className="focus-ring mt-4 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                        />
                      </label>
                    </div>
                  </div>

                  <div className="mt-6 rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                    <div>
                      <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                        Reguły filtracji
                      </p>
                      <h2 className="mt-2 text-2xl font-bold text-app-text">
                        Filtry bezpieczeństwa
                      </h2>
                      <p className="mt-3 max-w-3xl text-sm leading-6 text-slate-500">
                        W tym miejscu konfigurujesz konkretne filtry używane przy sprawdzaniu
                        domen: regułę HTTP, znaki spoza alfabetu łacińskiego, adres IP, Google
                        Safe Browsing, wiek domeny oraz aktywne listy ostrzeżeń.
                      </p>
                    </div>

                    <div className="mt-6 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <p className="text-lg font-bold text-app-text">
                            HTTP
                          </p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Ta wartość określa, ile punktów dostaje strona działająca bez HTTPS.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.httpEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  httpEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>{filterSettingsDraft.httpEnabled ? 'Włączona' : 'Wyłączona'}</span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsHttpRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isHttpRuleExpanded}
                            aria-label="Rozwiń regułę HTTP"
                          >
                          {isHttpRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isHttpRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <label className="mt-5 block max-w-sm">
                            <span className="text-sm font-bold text-app-text">Punkty dla HTTP</span>
                            <input
                              type="number"
                              min="0"
                              value={filterSettingsDraft.httpScore}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  httpScore: Math.max(0, Number(event.target.value) || 0)
                                }))
                              }}
                              className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                            />
                          </label>

                          <div className="mt-5">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Efekt
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-600">
                              Jeśli strona używa wyłącznie `http`, ta reguła podnosi jej wynik
                              reputacji o ustawioną liczbę punktów.
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <p className="text-lg font-bold text-app-text">
                            Zaufane domeny w poddomenach
                          </p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Filtr wykrywa adresy, które umieszczają nazwę zaufanej domeny w
                            subdomenie, mimo że prawdziwa domena strony jest inna.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.trustedDomainInSubdomainEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  trustedDomainInSubdomainEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>
                              {filterSettingsDraft.trustedDomainInSubdomainEnabled
                                ? 'Włączona'
                                : 'Wyłączona'}
                            </span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsTrustedDomainInSubdomainRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isTrustedDomainInSubdomainRuleExpanded}
                            aria-label="Rozwiń regułę zaufanych domen w poddomenach"
                          >
                          {isTrustedDomainInSubdomainRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isTrustedDomainInSubdomainRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <label className="mt-5 block max-w-sm">
                            <span className="text-sm font-bold text-app-text">
                              Punkty dla zaufanych domen w poddomenach
                            </span>
                            <input
                              type="number"
                              min="0"
                              value={filterSettingsDraft.trustedDomainInSubdomainScore}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  trustedDomainInSubdomainScore: Math.max(
                                    0,
                                    Number(event.target.value) || 0
                                  )
                                }))
                              }}
                              className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                            />
                          </label>

                          <div className="mt-5">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Efekt
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-600">
                              Przykład ryzyka: zaufana domena widoczna w początku adresu może być
                              tylko przynętą, jeśli prawdziwa domena znajduje się dalej.
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <p className="text-lg font-bold text-app-text">
                            Podobne do zaufanych domen
                          </p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Filtr wykrywa adresy, które wyglądają podobnie do domen z allowlisty,
                            ale nie są dokładnie tą samą domeną.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.lookalikeTrustedDomainEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  lookalikeTrustedDomainEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>
                              {filterSettingsDraft.lookalikeTrustedDomainEnabled
                                ? 'Włączona'
                                : 'Wyłączona'}
                            </span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsLookalikeTrustedDomainRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isLookalikeTrustedDomainRuleExpanded}
                            aria-label="Rozwiń regułę podobieństwa do zaufanych domen"
                          >
                          {isLookalikeTrustedDomainRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isLookalikeTrustedDomainRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <label className="mt-5 block max-w-sm">
                            <span className="text-sm font-bold text-app-text">
                              Punkty dla domen podobnych do zaufanych
                            </span>
                            <input
                              type="number"
                              min="0"
                              value={filterSettingsDraft.lookalikeTrustedDomainScore}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  lookalikeTrustedDomainScore: Math.max(
                                    0,
                                    Number(event.target.value) || 0
                                  )
                                }))
                              }}
                              className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                            />
                          </label>

                          <div className="mt-5">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Efekt
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-600">
                              Jeśli adres jest bardzo podobny do domeny z allowlisty, ale nie jest
                              tą samą domeną, do wyniku reputacji zostanie dodane ustawione score.
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <p className="text-lg font-bold text-app-text">
                            Znaki spoza lacinskich
                          </p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Ten filtr wykrywa domeny zawierające litery spoza alfabetu łacińskiego.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.nonLatinEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  nonLatinEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>{filterSettingsDraft.nonLatinEnabled ? 'Włączona' : 'Wyłączona'}</span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsNonLatinRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isNonLatinRuleExpanded}
                            aria-label="Rozwiń regułę znaków spoza łacińskich"
                          >
                          {isNonLatinRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isNonLatinRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <label className="mt-5 block max-w-sm">
                            <span className="text-sm font-bold text-app-text">
                              Punkty dla znaków spoza łacińskich
                            </span>
                            <input
                              type="number"
                              min="0"
                              value={filterSettingsDraft.nonLatinScore}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  nonLatinScore: Math.max(0, Number(event.target.value) || 0)
                                }))
                              }}
                              className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                            />
                          </label>

                          <div className="mt-5">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Efekt
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-600">
                              Jeśli domena zawiera litery spoza alfabetu łacińskiego, do wyniku
                              reputacji zostanie dodane domyślnie 25 punktów.
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <div className="flex flex-wrap items-center gap-3">
                            <p className="text-lg font-bold text-app-text">Google Safe Browsing</p>
                            {!canEnableGoogleSafeBrowsing ? (
                              <span className="inline-flex items-center rounded-full border border-amber-200 bg-amber-50 px-3 py-1 text-xs font-bold text-amber-800">
                                Brak klucza API
                              </span>
                            ) : null}
                          </div>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Filtr sprawdza URL w Google Safe Browsing i może mocno podnieść score
                            dla phishingu, malware lub niechcianego oprogramowania.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.googleSafeBrowsingEnabled}
                              disabled={!canEnableGoogleSafeBrowsing}
                              onChange={(event) => {
                                if (!canEnableGoogleSafeBrowsing) {
                                  return
                                }

                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  googleSafeBrowsingEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>{filterSettingsDraft.googleSafeBrowsingEnabled ? 'Włączona' : 'Wyłączona'}</span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsGoogleSafeBrowsingRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isGoogleSafeBrowsingRuleExpanded}
                            aria-label="Rozwiń regułę Google Safe Browsing"
                          >
                          {isGoogleSafeBrowsingRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isGoogleSafeBrowsingRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
                            <label className="block">
                              <span className="text-sm font-bold text-app-text">
                                Nowy Google Safe Browsing API key
                              </span>
                              <input
                                type="password"
                                value={googleSafeBrowsingApiKeyInput}
                                onChange={(event) => {
                                  setGoogleSafeBrowsingApiKeyInput(event.target.value)
                                  if (shouldClearGoogleSafeBrowsingApiKey) {
                                    setShouldClearGoogleSafeBrowsingApiKey(false)
                                  }
                                }}
                                placeholder={
                                  reputationSettings.googleSafeBrowsingApiKeyConfigured
                                    ? '••••••••••••••••••••••••••••••••'
                                    : 'Wklej klucz API Google Safe Browsing'
                                }
                                className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                              />
                            </label>

                            <label className="block">
                              <span className="text-sm font-bold text-app-text">
                                Punkty dla trafienia Google
                              </span>
                              <input
                                type="number"
                                min="0"
                                value={filterSettingsDraft.googleSafeBrowsingScore}
                                onChange={(event) => {
                                  setFilterSettingsDraft((current) => ({
                                    ...current,
                                    googleSafeBrowsingScore: Math.max(
                                      0,
                                      Number(event.target.value) || 0
                                    )
                                  }))
                                }}
                                className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                              />
                            </label>
                          </div>

                          <div className="mt-4 flex flex-wrap gap-3">
                            <button
                              type="button"
                              className="focus-ring rounded-full border border-app-tile-border bg-white px-4 py-2.5 text-sm font-bold text-app-text"
                              onClick={() => {
                                setShouldClearGoogleSafeBrowsingApiKey((current) => !current)
                                if (!shouldClearGoogleSafeBrowsingApiKey) {
                                  setGoogleSafeBrowsingApiKeyInput('')
                                }
                              }}
                            >
                              {shouldClearGoogleSafeBrowsingApiKey
                                ? 'Anuluj usuwanie klucza'
                                : 'Usuń klucz API'}
                            </button>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <p className="text-lg font-bold text-app-text">Adres IP</p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Ten filtr wykrywa wejście bezpośrednio na numer IP zamiast na domenę.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.ipEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  ipEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>{filterSettingsDraft.ipEnabled ? 'Włączona' : 'Wyłączona'}</span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsIpRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isIpRuleExpanded}
                            aria-label="Rozwiń regułę adresu IP"
                          >
                          {isIpRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isIpRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <label className="mt-5 block max-w-sm">
                            <span className="text-sm font-bold text-app-text">
                              Punkty dla adresu IP
                            </span>
                            <input
                              type="number"
                              min="0"
                              value={filterSettingsDraft.ipScore}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  ipScore: Math.max(0, Number(event.target.value) || 0)
                                }))
                              }}
                              className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                            />
                          </label>

                          <div className="mt-5">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Efekt
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-600">
                              Jeśli adres prowadzi bezpośrednio na numer IP, do wyniku reputacji
                              zostanie dodane ustawione score.
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div>
                          <p className="text-lg font-bold text-app-text">Wiek domeny</p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Filtr sprawdza po RDAP, czy domena jest bardzo młoda i przez to bardziej
                            podejrzana.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.youngDomainEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  youngDomainEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>{filterSettingsDraft.youngDomainEnabled ? 'Włączona' : 'Wyłączona'}</span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setIsYoungDomainRuleExpanded((current) => !current)
                            }}
                            aria-expanded={isYoungDomainRuleExpanded}
                            aria-label="Rozwiń regułę wieku domeny"
                          >
                          {isYoungDomainRuleExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {isYoungDomainRuleExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <div className="mt-5 grid grid-cols-1 gap-4 lg:grid-cols-2">
                            <label className="block">
                              <span className="text-sm font-bold text-app-text">
                                Maksymalny wiek domeny w dniach
                              </span>
                              <input
                                type="number"
                                min="1"
                                value={filterSettingsDraft.youngDomainMaxAgeDays}
                                onChange={(event) => {
                                  setFilterSettingsDraft((current) => ({
                                    ...current,
                                    youngDomainMaxAgeDays: Math.max(
                                      1,
                                      Number(event.target.value) || 1
                                    )
                                  }))
                                }}
                                className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                              />
                            </label>

                            <label className="block">
                              <span className="text-sm font-bold text-app-text">
                                Punkty dla młodej domeny
                              </span>
                              <input
                                type="number"
                                min="0"
                                value={filterSettingsDraft.youngDomainScore}
                                onChange={(event) => {
                                  setFilterSettingsDraft((current) => ({
                                    ...current,
                                    youngDomainScore: Math.max(0, Number(event.target.value) || 0)
                                  }))
                                }}
                                className="focus-ring mt-3 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                              />
                            </label>
                          </div>

                          <div className="mt-5">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Efekt
                            </p>
                            <p className="mt-2 text-sm leading-6 text-slate-600">
                              Jeśli RDAP pokaże, że domena ma nie więcej niż{' '}
                              {filterSettingsDraft.youngDomainMaxAgeDays} dni, do wyniku reputacji
                              zostanie dodane ustawione score.
                            </p>
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-4 rounded-[24px] border border-app-tile-border bg-slate-50/70">
                      <div className="flex items-start justify-between gap-4 rounded-[24px] px-5 py-5">
                        <div className="max-w-3xl">
                          <p className="text-lg font-bold text-app-text">
                            Listy ostrzeżeń
                          </p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Każda aktywna lista pobierana jest na żywo, a jej punktacja wpływa na
                            końcowy score reputacji domeny.
                          </p>
                        </div>
                        <div className="flex shrink-0 items-center gap-3">
                          <label className="app-no-drag flex items-center gap-2 rounded-full border border-app-tile-border bg-white px-3 py-2 text-sm font-bold text-app-text">
                            <input
                              type="checkbox"
                              className="focus-ring h-4 w-4 rounded border border-app-tile-border accent-[#1e3a8a]"
                              checked={filterSettingsDraft.blocklistsEnabled}
                              onChange={(event) => {
                                setFilterSettingsDraft((current) => ({
                                  ...current,
                                  blocklistsEnabled: event.target.checked
                                }))
                              }}
                            />
                            <span>{filterSettingsDraft.blocklistsEnabled ? 'Włączona' : 'Wyłączona'}</span>
                          </label>
                          <button
                            type="button"
                            className="focus-ring mt-1 flex h-10 w-10 items-center justify-center rounded-full border border-app-tile-border bg-white text-slate-500"
                            onClick={() => {
                              setAreBlocklistsExpanded((current) => !current)
                            }}
                            aria-expanded={areBlocklistsExpanded}
                            aria-label="Rozwiń regułę list ostrzeżeń"
                          >
                          {areBlocklistsExpanded ? (
                            <FiChevronUp aria-hidden="true" className="h-5 w-5" />
                          ) : (
                            <FiChevronDown aria-hidden="true" className="h-5 w-5" />
                          )}
                          </button>
                        </div>
                      </div>

                      {areBlocklistsExpanded ? (
                        <div className="border-t border-app-tile-border px-5 pb-5">
                          <form className="mt-5 flex flex-col gap-3 lg:flex-row" onSubmit={handleAddDomainBlocklistSource}>
                            <input
                              type="url"
                              inputMode="url"
                              value={newDomainBlocklistUrl}
                              onChange={(event) => setNewDomainBlocklistUrl(event.target.value)}
                              placeholder="https://example.com/lista.txt"
                              className="focus-ring min-w-0 flex-1 rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                            />
                            <button
                              type="submit"
                              className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text"
                            >
                              Dodaj listę
                            </button>
                          </form>

                          <div className="mt-5 space-y-3">
                            {domainBlocklistSourcesDraft.map((source) => (
                              <div
                                key={source.id}
                                className="flex flex-col gap-4 rounded-[24px] border border-app-tile-border bg-white p-5 transition hover:bg-slate-50/90 lg:flex-row lg:items-center lg:justify-between"
                              >
                                <div className="min-w-0 flex-1">
                                  <div className="flex flex-wrap items-center gap-2">
                                    <p className="break-all text-sm font-bold text-app-text">{source.url}</p>
                                    {source.isDefault ? (
                                      <span className="rounded-full bg-slate-200 px-3 py-1 text-[11px] font-bold tracking-[0.12em] text-slate-600 uppercase">
                                        Domyślna
                                      </span>
                                    ) : null}
                                  </div>
                                  <p className="mt-2 text-sm text-slate-500">
                                    {source.enabled
                                      ? 'Ta lista jest aktywna i bierze udział w sprawdzaniu reputacji domen.'
                                      : 'Ta lista jest wyłączona i nie bierze udziału w sprawdzaniu reputacji domen.'}
                                  </p>
                                </div>

                                <div className="flex flex-col gap-3 lg:min-w-[340px] lg:items-end">
                                  <div className="flex flex-wrap items-center gap-3 lg:justify-end">
                                    <label className="app-no-drag flex items-center gap-3 rounded-full border border-app-tile-border bg-white px-4 py-3 text-sm font-bold text-app-text">
                                      <input
                                        type="checkbox"
                                        className="focus-ring h-5 w-5 rounded border border-app-tile-border accent-[#1e3a8a]"
                                        checked={source.enabled}
                                        onChange={(event) => {
                                          updateDomainBlocklistSourceDraft(source.id, {
                                            enabled: event.target.checked
                                          })
                                        }}
                                      />
                                      <span>{source.enabled ? 'Włączona' : 'Wyłączona'}</span>
                                    </label>

                                    <label className="block min-w-[190px]">
                                      <span className="text-xs font-bold tracking-[0.12em] text-slate-500 uppercase">
                                        Punkty listy
                                      </span>
                                      <input
                                        type="number"
                                        min="0"
                                        value={source.scoreDelta}
                                        onChange={(event) => {
                                          updateDomainBlocklistSourceDraft(source.id, {
                                            scoreDelta: Math.max(0, Number(event.target.value) || 0)
                                          })
                                        }}
                                        className="focus-ring mt-2 w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text focus:outline-none"
                                      />
                                    </label>
                                    {!source.isDefault ? (
                                      <button
                                        type="button"
                                        className="focus-ring flex h-11 w-11 items-center justify-center rounded-full border border-red-200 bg-red-50 text-red-600 transition hover:bg-red-100"
                                        aria-label={`Usuń listę ${source.url}`}
                                        onClick={() => {
                                          void handleRemoveDomainBlocklistSource(source.id)
                                        }}
                                      >
                                        <FiTrash2 aria-hidden="true" className="h-4 w-4" />
                                      </button>
                                    ) : null}
                                  </div>
                                </div>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null}
                    </div>

                    <div className="mt-5 flex flex-wrap items-center justify-between gap-3 rounded-[24px] border border-dashed border-app-tile-border bg-slate-50/70 px-5 py-4">
                      <p className="text-sm text-slate-500">
                        {hasFilterSettingsChanges
                          ? 'Masz niezapisane zmiany w filtrach.'
                          : 'Wszystkie ustawienia filtrów są zapisane.'}
                      </p>
                      <button
                        type="button"
                        disabled={!hasFilterSettingsChanges || isSavingFilterSettings}
                        className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text disabled:cursor-not-allowed disabled:opacity-60"
                        onClick={() => {
                          void handleSaveFilterSettings()
                        }}
                      >
                        {isSavingFilterSettings ? 'Zapisywanie...' : 'Zapisz'}
                      </button>
                    </div>
                  </div>

                  <div className="mt-6 rounded-[28px] border border-app-tile-border bg-app-tile p-6 shadow-[0_14px_34px_rgba(148,163,184,0.12)]">
                    <div className="flex flex-wrap items-start justify-between gap-4">
                      <div className="max-w-3xl">
                        <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                          Trusted Domains
                        </p>
                        <h2 className="mt-2 text-2xl font-bold text-app-text">
                          Zaufane źródła whitelisty
                        </h2>
                        <p className="mt-3 text-sm leading-6 text-slate-500">
                          Te źródła budują lokalną bazę zaufanych domen w SQLite. Whitelista nie
                          omija blocklist ani Google Safe Browsing, ale może obniżać czułość części
                          heurystyk.
                        </p>
                      </div>
                    </div>

                    <div className="mt-5 rounded-[24px] border border-app-tile-border bg-slate-50/70 p-5">
                      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
                        <div className="max-w-2xl">
                          <p className="text-lg font-bold text-app-text">
                            Własne domeny allowlisty
                          </p>
                          <p className="mt-2 text-sm leading-6 text-slate-500">
                            Dodane tutaj domeny będą traktowane jako zaufane i ominą reguły
                            reputacji strony. Wpisuj tylko domeny, którym naprawdę ufasz.
                          </p>
                        </div>
                        <form
                          className="flex w-full flex-col gap-3 sm:flex-row lg:max-w-xl"
                          onSubmit={(event) => {
                            void handleAddCustomTrustedDomain(event)
                          }}
                        >
                          <label className="min-w-0 flex-1">
                            <span className="sr-only">Domena do dodania do allowlisty</span>
                            <input
                              type="text"
                              value={newCustomTrustedDomain}
                              onChange={(event) => {
                                setNewCustomTrustedDomain(event.target.value)
                              }}
                              placeholder="example.com"
                              className="focus-ring w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                            />
                          </label>
                          <button
                            type="submit"
                            className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text disabled:cursor-not-allowed disabled:opacity-60"
                            disabled={newCustomTrustedDomain.trim().length === 0}
                          >
                            Dodaj domenę
                          </button>
                        </form>
                      </div>

                      <div className="mt-5">
                        {customTrustedDomains.length > 0 ? (
                          <div className="overflow-hidden rounded-2xl border border-app-tile-border bg-white">
                            {customTrustedDomains.map((entry) => (
                              <div
                                key={entry.domain}
                                className="flex flex-col gap-3 border-b border-app-tile-border px-4 py-4 last:border-b-0 sm:flex-row sm:items-center sm:justify-between"
                              >
                                <div className="min-w-0">
                                  <p className="break-all text-sm font-bold text-app-text">
                                    {entry.domain}
                                  </p>
                                  <p className="mt-1 text-xs text-slate-500">
                                    Dodano:{' '}
                                    {new Date(entry.createdAt).toLocaleString('pl-PL')}
                                  </p>
                                </div>
                                <button
                                  type="button"
                                  className="focus-ring inline-flex items-center justify-center gap-2 self-start rounded-full border border-red-200 bg-red-50 px-4 py-2 text-sm font-bold text-red-600 transition hover:bg-red-100 sm:self-center"
                                  aria-label={`Usuń domenę ${entry.domain} z allowlisty`}
                                  onClick={() => {
                                    void handleRemoveCustomTrustedDomain(entry.domain)
                                  }}
                                >
                                  <FiX aria-hidden="true" className="h-4 w-4" />
                                  Usuń
                                </button>
                              </div>
                            ))}
                          </div>
                        ) : (
                          <p className="rounded-2xl border border-dashed border-app-tile-border bg-white px-4 py-3 text-sm text-slate-500">
                            Nie dodano jeszcze własnych zaufanych domen.
                          </p>
                        )}
                      </div>
                    </div>

                    <div className="mt-5 space-y-3">
                      {trustedDomainSources.filter((source) => source.kind === 'tranco').map((source) => (
                        <div
                          key={source.id}
                          className="rounded-[24px] border border-app-tile-border bg-slate-50/70 p-5"
                        >
                          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
                            <div className="min-w-0 flex-1">
                              <div className="flex flex-wrap items-center gap-2">
                                <p className="text-lg font-bold text-app-text">{source.name}</p>
                                {source.isDefault ? (
                                  <span className="rounded-full bg-slate-200 px-3 py-1 text-[11px] font-bold tracking-[0.12em] text-slate-600 uppercase">
                                    Domyślna
                                  </span>
                                ) : null}
                              </div>
                              <p className="mt-2 break-all text-sm text-slate-500">{source.url}</p>
                              <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-500">
                                <span className="rounded-full border border-app-tile-border bg-white px-3 py-1">
                                  Limit: {source.maxDomains.toLocaleString('pl-PL')}
                                </span>
                                <span className="rounded-full border border-app-tile-border bg-white px-3 py-1">
                                  Domeny: {source.lastDomainCount.toLocaleString('pl-PL')}
                                </span>
                                <span className="rounded-full border border-app-tile-border bg-white px-3 py-1">
                                  Ostatnia synchronizacja:{' '}
                                  {source.lastSyncedAt
                                    ? new Date(source.lastSyncedAt).toLocaleString('pl-PL')
                                    : 'brak'}
                                </span>
                              </div>
                              {source.lastSyncError ? (
                                <div className="mt-3 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                                  {source.lastSyncError}
                                </div>
                              ) : null}
                            </div>

                            <div className="flex flex-wrap items-center gap-3 lg:justify-end">
                              <label className="app-no-drag flex items-center gap-3 rounded-full border border-app-tile-border bg-white px-4 py-3 text-sm font-bold text-app-text">
                                <input
                                  type="checkbox"
                                  className="focus-ring h-5 w-5 rounded border border-app-tile-border accent-[#1e3a8a]"
                                  checked={source.enabled}
                                  onChange={(event) => {
                                    void handleToggleTrustedDomainSource(
                                      source.id,
                                      event.target.checked
                                    )
                                  }}
                                />
                                <span>{source.enabled ? 'Włączona' : 'Wyłączona'}</span>
                              </label>

                              <button
                                type="button"
                                className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text disabled:cursor-wait disabled:opacity-70"
                                disabled={syncingTrustedDomainSourceId === source.id}
                                onClick={() => {
                                  void handleSyncTrustedDomainSource(source.id)
                                }}
                              >
                                {syncingTrustedDomainSourceId === source.id
                                  ? 'Synchronizacja...'
                                  : 'Synchronizuj'}
                              </button>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </>
              )}
            </div>
          </section>
          {adminTab === 'security' && isSecurityEventsPanelOpen ? (
            <div className="fixed top-12 right-0 bottom-0 left-0 z-40 flex justify-end bg-slate-950/20 backdrop-blur-[1px]">
              <button
                type="button"
                className="absolute inset-0 cursor-default"
                aria-label="Zamknij logi bezpieczeństwa"
                onClick={() => {
                  setIsSecurityEventsPanelOpen(false)
                }}
              />

              <aside className="relative z-10 flex h-full w-full max-w-xl flex-col border-l border-app-tile-border bg-app-tile shadow-[-24px_0_70px_rgba(15,23,42,0.18)]">
                <div className="border-b border-app-tile-border px-5 py-5">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <p className="text-sm font-bold tracking-[0.14em] text-slate-500 uppercase">
                        Logi bezpieczeństwa
                      </p>
                      <h2 className="mt-2 text-2xl font-bold text-app-text">
                        Zdarzenia z ostatnich 30 dni
                      </h2>
                      <p className="mt-2 text-sm leading-6 text-slate-500">
                        Strony zatrzymane albo oznaczone ostrzeżeniem przez filtry bezpieczeństwa.
                      </p>
                    </div>

                    <button
                      type="button"
                      className="focus-ring flex h-11 w-11 shrink-0 items-center justify-center rounded-full border border-app-tile-border bg-slate-50 text-slate-600 transition hover:bg-white"
                      aria-label="Zamknij logi bezpieczeństwa"
                      onClick={() => {
                        setIsSecurityEventsPanelOpen(false)
                      }}
                    >
                      <FiX aria-hidden="true" className="h-5 w-5" />
                    </button>
                  </div>

                  <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
                    <span className="rounded-full border border-app-tile-border bg-slate-50 px-3 py-1 text-xs font-bold text-slate-600">
                      {securityEventLogs.length} wpisów
                    </span>
                    <button
                      type="button"
                      className="focus-ring inline-flex items-center gap-2 rounded-full border border-app-tile-border bg-slate-50 px-4 py-2.5 text-sm font-bold text-app-text transition hover:bg-white disabled:cursor-wait disabled:opacity-70"
                      disabled={isLoadingSecurityEventLogs}
                      onClick={() => {
                        void refreshSecurityEventLogs()
                      }}
                    >
                      <FiRefreshCw
                        aria-hidden="true"
                        className={`h-4 w-4 ${isLoadingSecurityEventLogs ? 'animate-spin' : ''}`}
                      />
                      {isLoadingSecurityEventLogs ? 'Odświeżanie...' : 'Odśwież'}
                    </button>
                  </div>
                </div>

                <div className="min-h-0 flex-1 overflow-y-auto px-5 py-5">
                  {securityEventLogs.length > 0 ? (
                    <div className="space-y-3">
                      {securityEventLogs.map((entry) => (
                        <div
                          key={entry.id}
                          className="rounded-[24px] border border-app-tile-border bg-slate-50/70 p-4"
                        >
                          <div className="flex flex-wrap items-center gap-2">
                            <span
                              className={`rounded-full border px-3 py-1 text-xs font-bold ${getSecurityEventDecisionClass(
                                entry.decision
                              )}`}
                            >
                              {getSecurityEventDecisionLabel(entry.decision)}
                            </span>
                            <span className="rounded-full border border-app-tile-border bg-white px-3 py-1 text-xs font-bold text-slate-600">
                              Score: {entry.score}
                            </span>
                          </div>

                          <p className="mt-3 break-all text-base font-bold text-app-text">
                            {entry.hostname ?? entry.url}
                          </p>
                          <p className="mt-1 break-all text-sm text-slate-500">{entry.url}</p>

                          <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2">
                            <div className="rounded-2xl border border-app-tile-border bg-white px-3 py-2">
                              <p className="text-[11px] font-bold tracking-[0.12em] text-slate-500 uppercase">
                                Czas
                              </p>
                              <p className="mt-1 text-xs font-bold text-app-text">
                                {new Date(entry.createdAt).toLocaleString('pl-PL')}
                              </p>
                            </div>
                            <div className="rounded-2xl border border-app-tile-border bg-white px-3 py-2">
                              <p className="text-[11px] font-bold tracking-[0.12em] text-slate-500 uppercase">
                                Kod
                              </p>
                              <p className="mt-1 break-all text-xs font-bold text-app-text">
                                {entry.eventCode}
                              </p>
                            </div>
                          </div>

                          <div className="mt-3">
                            <p className="text-xs font-bold tracking-[0.14em] text-slate-500 uppercase">
                              Wyłapane reguły
                            </p>
                            {entry.matchedRules.length > 0 ? (
                              <div className="mt-2 flex flex-wrap gap-2">
                                {entry.matchedRules.map((rule) => (
                                  <span
                                    key={`${entry.id}-${rule.ruleId}-${rule.code}`}
                                    className="rounded-full border border-app-tile-border bg-white px-3 py-1 text-xs font-bold text-slate-600"
                                  >
                                    {rule.ruleId} +{rule.scoreDelta}
                                  </span>
                                ))}
                              </div>
                            ) : (
                              <p className="mt-2 text-sm text-slate-500">
                                Brak zapisanych szczegółów reguł.
                              </p>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="rounded-2xl border border-dashed border-app-tile-border bg-slate-50/70 px-4 py-3 text-sm text-slate-500">
                      Brak zapisanych zdarzeń bezpieczeństwa z ostatnich 30 dni.
                    </p>
                  )}
                </div>
              </aside>
            </div>
          ) : null}
          {adminGateModal}
        </div>
      </main>
    )
  }

  if (selectedUser) {
    return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
        <div className="app-shell flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
          <header className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]">
            <div className="flex h-12 items-center justify-between px-4">
              <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
                <AppBrandMenu
                  isOpen={openAppMenu === 'main'}
                  onOpen={() => {
                    setOpenAppMenu('main')
                  }}
                  onOpenAdminPanel={() => {
                    void openAdminPanel()
                  }}
                />
                <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                  <span className="app-drag-label text-xs font-medium text-slate-400">
                    Przeciągnij okno
                  </span>
                </div>
              </div>

              <WindowControls
                isMaximized={isMaximized}
                onMinimize={minimizeWindow}
                onToggleMaximize={toggleMaximize}
                onClose={closeWindow}
              />
            </div>
          </header>

          <section className="mx-auto flex min-h-0 flex-1 w-full max-w-5xl items-center justify-center overflow-hidden px-4 py-6 sm:px-5 sm:py-8">
            <div className="mx-auto w-full max-w-2xl md:max-w-3xl">
              <div className="mb-10 text-center">
                <p className="mb-3 text-sm font-bold tracking-[0.16em] text-slate-500 uppercase">
                  Użytkownik
                </p>
                <h1 className="text-3xl leading-tight font-bold md:text-5xl">
                  Witaj, {selectedUser.name}
                </h1>
                <p className="mt-3 text-base text-slate-500 md:text-lg">
                  Możesz już wyszukać coś w internecie.
                </p>
              </div>

              <form
                className="overflow-hidden rounded-full border border-app-tile-border bg-app-tile px-4 py-2.5 shadow-[0_14px_40px_rgba(148,163,184,0.18)] sm:px-5 sm:py-3"
                onSubmit={handleSearchSubmit}
              >
                <div className="flex items-center gap-2 sm:gap-3">
                  <div
                    aria-label="Google"
                    className="font-google shrink-0 text-xl leading-none tracking-tight sm:text-2xl md:text-3xl"
                  >
                    <span className="text-[#4285F4]">G</span>
                    <span className="text-[#EA4335]">o</span>
                    <span className="text-[#FBBC05]">o</span>
                    <span className="text-[#4285F4]">g</span>
                    <span className="text-[#34A853]">l</span>
                    <span className="text-[#EA4335]">e</span>
                  </div>

                  <div className="h-7 w-px bg-slate-200" />

                  <input
                    id="search"
                    type="text"
                    value={inputValue}
                    onChange={(event) => setInputValue(event.target.value)}
                    placeholder="Wpisz, czego szukasz"
                  className="focus-ring min-w-0 w-full rounded-full bg-transparent px-3 py-2 text-base text-app-text placeholder:text-slate-400 focus:outline-none sm:px-4 sm:py-3 sm:text-lg md:text-xl"
                  />
                </div>
              </form>

              {favorites.length > 0 ? (
                <section className="mt-8">
                  <div className="mb-4 text-center">
                    <h2 className="text-xl font-bold text-app-text md:text-2xl">
                      Ulubione strony
                    </h2>
                    <p className="mt-2 text-sm text-slate-500 md:text-base">
                      Kliknij, aby szybko otworzyć zapisane miejsce
                    </p>
                  </div>

                  <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
                    {favorites.map((favorite) => (
                      <div
                        key={favorite.url}
                        className="group relative min-h-[132px] rounded-[24px] border border-app-tile-border bg-app-tile shadow-[0_14px_34px_rgba(148,163,184,0.12)] transition hover:-translate-y-0.5 hover:bg-slate-50 hover:shadow-[0_18px_40px_rgba(148,163,184,0.16)]"
                      >
                        <button
                          type="button"
                          className="focus-ring flex min-h-[132px] w-full flex-col justify-between rounded-[24px] p-5 pr-14 text-left"
                          onClick={() => {
                            void openInBrowser(favorite.url)
                          }}
                        >
                          <FavoriteTileIcon
                            title={favorite.title}
                            url={favorite.url}
                            faviconUrl={favorite.faviconUrl}
                          />

                          <div className="mt-4">
                            <h3 className="text-lg leading-tight font-bold text-app-text">
                              {favorite.title}
                            </h3>
                            <p className="mt-2 line-clamp-2 break-all text-sm text-slate-500">
                              {favorite.url}
                            </p>
                          </div>
                        </button>

                        <button
                          type="button"
                          aria-label={`Usuń z ulubionych: ${favorite.title}`}
                          className="focus-ring absolute top-4 right-4 flex h-9 w-9 items-center justify-center rounded-full text-slate-400 opacity-100 transition hover:bg-red-50 hover:text-red-600 sm:opacity-0 sm:group-hover:opacity-100 sm:focus:opacity-100"
                          onClick={() => {
                            void removeFavorite(favorite.url)
                          }}
                        >
                          <FiTrash2 aria-hidden="true" className="h-4 w-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                </section>
              ) : null}

              <div className="mt-8 text-center">
                <button
                  type="button"
                  className="focus-ring rounded-full px-4 py-2 text-sm font-bold text-app-primary transition hover:bg-slate-100"
                  onClick={() => {
                    void handleClearActiveUser()
                  }}
                >
                  Zmień użytkownika
                </button>
              </div>
            </div>
          </section>
          {adminGateModal}
        </div>
      </main>
    )
  }

  return (
      <main className="flex h-screen overflow-hidden bg-app text-app-text">
      <div className="app-shell relative flex h-full w-full flex-col overflow-hidden border-0 shadow-none">
        <header className="border-b border-app-tile-border bg-app-tile shadow-[0_10px_30px_rgba(148,163,184,0.12)]">
          <div className="flex h-12 items-center justify-between px-4">
            <div className="app-drag-region min-w-0 flex flex-1 items-center gap-3 pr-4 select-none">
              <AppBrandMenu
                isOpen={openAppMenu === 'main'}
                onOpen={() => {
                  setOpenAppMenu('main')
                }}
                onOpenAdminPanel={() => {
                  void openAdminPanel()
                }}
              />
              <div className="app-drag-surface flex h-8 flex-1 items-center justify-center rounded-full border border-dashed border-slate-200 bg-slate-50/70 px-3">
                <span className="app-drag-label text-xs font-medium text-slate-400">
                  Przeciągnij okno
                </span>
              </div>
            </div>

            <WindowControls
              isMaximized={isMaximized}
              onMinimize={minimizeWindow}
              onToggleMaximize={toggleMaximize}
              onClose={closeWindow}
            />
          </div>
        </header>

        <section className="mx-auto flex min-h-0 flex-1 w-full max-w-5xl items-center justify-center overflow-hidden px-4 py-6 sm:px-5 sm:py-8">
          <div className="w-full max-w-3xl">
            <div className="mb-10 text-center">
              <h1 className="text-3xl leading-tight font-bold md:text-5xl">
                Kto korzysta z internetu?
              </h1>
              <p className="mt-3 text-base text-slate-500 md:text-lg">
                Wybierz użytkownika
              </p>
            </div>

            {errorMessage ? (
              <div className="mb-6 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700">
                {errorMessage}
              </div>
            ) : null}

            {users.length > 0 ? (
              <div className="flex flex-wrap justify-center gap-4">
                {users.map((user) => (
                  <button
                    key={user.id}
                    type="button"
                    className="focus-ring relative w-full max-w-[244px] rounded-[24px] border border-app-tile-border bg-app-tile p-5 text-left shadow-[0_14px_34px_rgba(148,163,184,0.12)] transition hover:-translate-y-0.5 hover:shadow-[0_18px_40px_rgba(148,163,184,0.16)] sm:w-[244px]"
                    onClick={() => {
                      void handleSelectUser(user.id)
                    }}
                  >
                    <div className="absolute top-3 right-3" data-user-menu-root={user.id}>
                      <button
                        type="button"
                        aria-label={`Opcje użytkownika ${user.name}`}
                        className="focus-ring flex h-8 w-8 items-center justify-center rounded-full text-slate-500 transition-colors hover:bg-slate-100 hover:text-app-text"
                        onClick={(event) => {
                          event.stopPropagation()
                          setOpenUserMenuId((currentId) =>
                            currentId === user.id ? null : user.id
                          )
                        }}
                      >
                        <FiMoreVertical aria-hidden="true" className="h-4 w-4" />
                      </button>

                      {openUserMenuId === user.id ? (
                        <div className="absolute top-[calc(100%+0.35rem)] right-0 z-20 min-w-[172px] rounded-2xl border border-app-tile-border bg-app-tile p-2 shadow-[0_18px_40px_rgba(148,163,184,0.18)]">
                          <button
                            type="button"
                            className="focus-ring flex w-full items-center gap-2 rounded-xl px-3 py-2 text-left text-sm font-medium text-red-600 transition hover:bg-red-50"
                            onClick={(event) => {
                              event.stopPropagation()
                              setOpenUserMenuId(null)
                              setUserPendingDeletion(user)
                            }}
                          >
                            <FiTrash2 aria-hidden="true" className="h-4 w-4 shrink-0" />
                            Usuń użytkownika
                          </button>
                        </div>
                      ) : null}
                    </div>

                    <div className="flex h-14 w-14 items-center justify-center rounded-2xl bg-slate-100 text-lg font-bold text-app-text">
                      {user.initials}
                    </div>
                    <h2 className="mt-4 text-xl font-bold text-app-text">{user.name}</h2>
                    <p className="mt-1 text-sm text-slate-500">
                      Kliknij, aby wybrać użytkownika
                    </p>
                  </button>
                ))}
              </div>
            ) : (
              <div className="rounded-[24px] border border-dashed border-app-tile-border bg-app-tile/70 px-6 py-10 text-center text-slate-500">
                Nie ma jeszcze żadnego użytkownika
              </div>
            )}

            {isAddingUser ? (
              <form
                className="mt-8 rounded-[24px] border border-app-tile-border bg-app-tile p-5 shadow-[0_14px_34px_rgba(148,163,184,0.12)]"
                onSubmit={(event) => {
                  void handleAddUser(event)
                }}
              >
                <label
                  className="mb-4 block text-sm font-bold text-app-text"
                  htmlFor="new-user-name"
                >
                  Nazwa użytkownika
                </label>
                <input
                  id="new-user-name"
                  type="text"
                  value={newUserName}
                  onChange={(event) => setNewUserName(event.target.value)}
                  placeholder="Wpisz imię użytkownika"
                  className="focus-ring w-full rounded-2xl border border-app-tile-border bg-white px-4 py-3 text-base text-app-text placeholder:text-slate-400 focus:outline-none"
                  autoFocus
                />

                <div className="mt-6 flex flex-wrap items-center gap-3">
                  <button
                    type="submit"
                    className="focus-ring rounded-full bg-app-primary px-5 py-3 text-sm font-bold text-app-primary-text"
                  >
                    Dodaj użytkownika
                  </button>
                  <button
                    type="button"
                    className="focus-ring rounded-full border border-app-tile-border px-5 py-3 text-sm font-bold text-app-text"
                    onClick={() => {
                      setIsAddingUser(false)
                      setNewUserName('')
                    }}
                  >
                    Anuluj
                  </button>
                </div>
              </form>
            ) : (
              <div className="mt-8 text-center">
                <button
                  type="button"
                  className="focus-ring rounded-full border border-app-primary/18 bg-app-tile px-5 py-3 text-sm font-bold text-app-primary shadow-[0_10px_24px_rgba(148,163,184,0.12)] transition hover:-translate-y-0.5 hover:bg-slate-50 hover:shadow-[0_14px_28px_rgba(148,163,184,0.16)]"
                  onClick={() => {
                    setIsAddingUser(true)
                    setErrorMessage(null)
                  }}
                >
                  Nie ma Cię tu? Dodaj nowego użytkownika
                </button>
              </div>
            )}
          </div>
        </section>

        {userPendingDeletion ? (
          <div
            className="absolute inset-0 z-[200] flex items-center justify-center bg-slate-950/30 px-4 backdrop-blur-[2px]"
            onClick={closeDeleteModal}
          >
            <div
              role="dialog"
              aria-modal="true"
              aria-labelledby="delete-user-title"
              className="w-full max-w-md rounded-[28px] border border-red-200 bg-white p-6 shadow-[0_28px_80px_rgba(15,23,42,0.24)]"
              onClick={(event) => {
                event.stopPropagation()
              }}
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex items-start gap-4">
                  <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl bg-red-50 text-red-600">
                    <FiAlertTriangle aria-hidden="true" className="h-6 w-6" />
                  </div>

                  <div>
                    <h2 id="delete-user-title" className="text-xl font-bold text-app-text">
                      Czy na pewno chcesz usunąć użytkownika?
                    </h2>
                    <p className="mt-2 text-sm leading-6 text-slate-500">
                      Użytkownik <span className="font-bold text-app-text">{userPendingDeletion.name}</span>{' '}
                      zostanie usunięty razem z jego danymi przeglądania.
                    </p>
                  </div>
                </div>

                <button
                  type="button"
                  aria-label="Zamknij okno potwierdzenia"
                  className="focus-ring flex h-10 w-10 shrink-0 items-center justify-center rounded-full text-slate-400 transition hover:bg-slate-100 hover:text-app-text"
                  onClick={closeDeleteModal}
                >
                  <FiX aria-hidden="true" className="h-5 w-5" />
                </button>
              </div>

              <div className="mt-6 flex flex-wrap justify-end gap-3">
                <button
                  type="button"
                  className="focus-ring rounded-full border border-app-tile-border px-5 py-3 text-sm font-bold text-app-text"
                  onClick={closeDeleteModal}
                >
                  Anuluj
                </button>
                <button
                  type="button"
                  className="focus-ring rounded-full bg-red-600 px-5 py-3 text-sm font-bold text-white transition hover:bg-red-700"
                  onClick={() => {
                    void handleDeleteUser(userPendingDeletion.id)
                  }}
                >
                  Usuń użytkownika
                </button>
              </div>
            </div>
          </div>
        ) : null}

        {adminGateModal}
      </div>
    </main>
  )
}

export default App
