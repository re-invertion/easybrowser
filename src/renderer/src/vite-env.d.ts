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
