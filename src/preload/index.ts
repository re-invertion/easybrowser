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
}

contextBridge.exposeInMainWorld('easybrowser', {
  version: '1.0.0',
  navigate: (value: string) => ipcRenderer.invoke('browser:navigate', value),
  goHome: () => ipcRenderer.invoke('browser:home'),
  goBack: () => ipcRenderer.invoke('browser:back'),
  goForward: () => ipcRenderer.invoke('browser:forward'),
  reload: () => ipcRenderer.invoke('browser:reload'),
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
