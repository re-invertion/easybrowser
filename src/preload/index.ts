import { contextBridge } from 'electron'

contextBridge.exposeInMainWorld('easybrowser', {
  version: '1.0.0'
})
