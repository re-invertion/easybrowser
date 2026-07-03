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
  }

  interface Window {
    easybrowser: {
      version: string
      navigate: (value: string) => Promise<void>
      goHome: () => Promise<void>
      goBack: () => Promise<void>
      goForward: () => Promise<void>
      reload: () => Promise<void>
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
