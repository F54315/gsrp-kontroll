'use strict'
// GSRP Kontroll. Ett synligt fönster som spelaren startar själv. Inget körs i bakgrunden, inget läggs i autostart, och allt går att avbryta.
// Flöde: spelaren skriver en engångskod -> appen hämtar reglerna -> skannar lokalt -> skickar bara träffarna (signerade) till servern.
const { app, BrowserWindow, ipcMain, shell } = require('electron')
const crypto = require('crypto')
const path = require('path')
const { scan } = require('./scanner.cjs')

const API = process.env.KONTROLL_API || 'https://roblox-erlc.vercel.app'
const VERSION = require('./package.json').version
let win = null
let session = null // { code, key, rules, playerName }
let control = { aborted: false }
let busy = false

async function call(body) {
  const res = await fetch(`${API}/api/civil?r=kontroll`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body), signal: AbortSignal.timeout(60000) })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) throw new Error(json.error || `Servern svarade ${res.status}`)
  return json
}

function createWindow() {
  win = new BrowserWindow({
    width: 940, height: 700, minWidth: 760, minHeight: 600, title: 'GSRP Kontroll', backgroundColor: '#0d121c', autoHideMenuBar: true,
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  })
  win.removeMenu()
  win.loadFile(path.join(__dirname, 'index.html'))
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https:\/\//.test(url)) shell.openExternal(url)
    return { action: 'deny' }
  })
  win.webContents.on('will-navigate', (e) => e.preventDefault())
}

ipcMain.handle('start', async (_e, code) => {
  try {
    const res = await call({ action: 'start', code })
    session = { code, key: res.sessionKey, rules: res.rules, playerName: res.playerName }
    return { ok: true, playerName: res.playerName, expiresAt: res.expiresAt }
  } catch (err) {
    return { ok: false, error: err.message }
  }
})

ipcMain.handle('scan', async () => {
  if (!session || busy) return { ok: false, error: 'Starta med en kod först.' }
  busy = true
  control = { aborted: false }
  try {
    const result = await scan({ rules: session.rules, control, onProgress: (p) => win && !win.isDestroyed() && win.webContents.send('progress', p) })
    if (result.aborted) return { ok: true, aborted: true }
    // Skickas automatiskt när skanningen är klar. Det som skickas visas för spelaren direkt efteråt.
    const payload = JSON.stringify({ findings: result.findings, stats: { ...result.stats, ruleVersion: 1 }, appVersion: VERSION })
    const signature = crypto.createHmac('sha256', session.key).update(payload).digest('hex')
    try {
      const sent = await call({ action: 'submit', code: session.code, payload, signature })
      return { ok: true, sent: true, verdict: sent.verdict, findings: result.findings, stats: result.stats }
    } catch (err) {
      return { ok: true, sent: false, error: err.message, findings: result.findings, stats: result.stats }
    }
  } finally {
    busy = false
  }
})

ipcMain.handle('cancel', () => {
  control.aborted = true
  return true
})

ipcMain.handle('quit', () => app.quit())

app.whenReady().then(createWindow)
app.on('window-all-closed', () => app.quit())
