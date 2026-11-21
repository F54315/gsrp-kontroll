'use strict'
const { contextBridge, ipcRenderer } = require('electron')
contextBridge.exposeInMainWorld('kontroll', {
  start: (code) => ipcRenderer.invoke('start', code),
  scan: () => ipcRenderer.invoke('scan'),
  cancel: () => ipcRenderer.invoke('cancel'),
  quit: () => ipcRenderer.invoke('quit'),
  onProgress: (cb) => ipcRenderer.on('progress', (_e, p) => cb(p)),
})
