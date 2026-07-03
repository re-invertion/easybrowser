/// <reference types="vite/client" />

declare global {
  interface Window {
    easybrowser: {
      version: string
    }
  }
}

export {}
