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

type UserProfile = {
  id: string
  initials: string
  name: string
  description: string
  createdAt: string
}

type UserState = {
  users: UserProfile[]
  activeUserId: string | null
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
