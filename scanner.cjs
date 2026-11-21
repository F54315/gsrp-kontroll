'use strict'
// Skannern. Går igenom filer, körande program och autostart och jämför mot reglerna (kontroll/rules.cjs + serverns egna).
// Allt jämförs lokalt. Det som lämnar datorn är bara träffarna (filnamn, mapp utan Windows-användarnamn, storlek, datum, SHA-256),
// aldrig en lista över alla filer och aldrig filernas innehåll.
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const { execFile } = require('child_process')
const { EXECUTABLE_EXT } = require('./rules.cjs')

const MAX_HASH_BYTES = 150 * 1024 * 1024
const MAX_CONTENT_BYTES = 1_500_000
const MAX_FINDINGS = 300
const TIER_RANK = { osaker: 1, sannolik: 2, bekraftad: 3 }
const ARCHIVE_EXT = ['zip', 'rar', '7z']
const CONTENT_EXT = ['js', 'mjs', 'py', 'bat', 'cmd', 'ps1', 'vbs', 'lua', 'sh']
// Mappar som aldrig går igenom (systemmappar, papperskorg och verktygsmappar med enorma mängder oskyldiga filer)
const SKIP_DIRS = new Set(['$recycle.bin', 'system volume information', 'node_modules', '.git', 'site-packages', 'winsxs', 'proc', 'sys', 'dev', 'windowsapps'])
const SKIP_ROOT_CHILD = new Set(['windows'])

const ext = (name) => {
  const i = name.lastIndexOf('.')
  return i < 0 ? '' : name.slice(i + 1).toLowerCase()
}

// Tar bort Windows-användarnamnet ur en sökväg, så att personens namn inte skickas med
function cleanPath(p) {
  return String(p)
    .replace(/^([A-Za-z]:[\\/]Users[\\/])[^\\/]+/i, '$1<användare>')
    .replace(/^(\/home\/|\/Users\/)[^/]+/, '$1<användare>')
}

function compile(rules) {
  const re = (s) => {
    try {
      return new RegExp(s, 'i')
    } catch {
      return null
    }
  }
  const names = []
  for (const r of rules.name ?? []) {
    const rx = re(r.pattern)
    if (rx) names.push({ ...r, rx })
  }
  const strings = []
  for (const r of rules.string ?? []) {
    const rxs = (r.patterns ?? []).map(re)
    if (rxs.length && rxs.every(Boolean)) strings.push({ ...r, rxs })
  }
  const hashes = new Map((rules.hash ?? []).map((r) => [String(r.pattern).toLowerCase(), r]))
  const allowHashes = new Set((rules.allow ?? []).filter((r) => r.kind === 'hash').map((r) => String(r.pattern).toLowerCase()))
  const allowNames = (rules.allow ?? []).filter((r) => r.kind === 'name').map((r) => re(r.pattern)).filter(Boolean)
  return { names, strings, hashes, allowHashes, allowNames }
}

// Namn som matchar ger "sannolik" bara på körbara filer, arkiv, mappar, processer och autostart. På vanliga filer (bilder, text) blir det "osäker".
function nameTier(rule, kind, e) {
  if (rule.tier !== 'sannolik') return rule.tier
  if (kind === 'mapp' || kind === 'process' || kind === 'autostart') return 'sannolik'
  return EXECUTABLE_EXT.includes(e) || ARCHIVE_EXT.includes(e) || CONTENT_EXT.includes(e) ? 'sannolik' : 'osaker'
}

function sha256File(file) {
  return new Promise((resolve) => {
    const h = crypto.createHash('sha256')
    const s = fs.createReadStream(file)
    s.on('data', (d) => h.update(d))
    s.on('end', () => resolve(h.digest('hex')))
    s.on('error', () => resolve(null))
  })
}

const run = (cmd, args, timeout = 15000) =>
  new Promise((resolve) => execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 8_000_000, encoding: 'utf8' }, (err, out) => resolve(err ? '' : String(out))))

function listRoots() {
  if (process.platform !== 'win32') return ['/']
  const roots = []
  for (let c = 67; c <= 90; c++) {
    const r = `${String.fromCharCode(c)}:\\`
    try {
      if (fs.existsSync(r)) roots.push(r)
    } catch {
      /* hoppa över */
    }
  }
  return roots
}

async function signatureOf(file) {
  if (process.platform !== 'win32') return 'okand'
  const out = (await new Promise((resolve) =>
    execFile('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', '(Get-AuthenticodeSignature -LiteralPath $env:KP_FILE).Status'], { timeout: 10000, windowsHide: true, env: { ...process.env, KP_FILE: file }, encoding: 'utf8' }, (err, o) => resolve(err ? '' : String(o))),
  )).trim()
  return out === 'Valid' ? 'signerad' : out === 'NotSigned' ? 'osignerad' : out ? 'ogiltig' : 'okand'
}

// Huvudfunktionen. control = { aborted: boolean }. onProgress får { files, dirs, current, findings, phase }.
async function scan({ rules, control = { aborted: false }, onProgress = () => {}, roots }) {
  const c = compile(rules)
  const started = Date.now()
  const findings = []
  const seen = new Set()
  const stats = { files: 0, dirs: 0, skipped: 0, hashed: 0, drives: 0, processes: 0, autostart: 0 }
  let current = ''
  let lastEmit = 0
  const emit = (phase, force) => {
    const now = Date.now()
    if (!force && now - lastEmit < 150) return
    lastEmit = now
    onProgress({ phase, files: stats.files, dirs: stats.dirs, current: cleanPath(current), findings: findings.length })
  }

  const add = (f) => {
    if (findings.length >= MAX_FINDINGS) return
    const key = `${f.ruleId}|${f.kind}|${f.dir}|${f.name}`
    if (seen.has(key)) return
    seen.add(key)
    findings.push(f)
  }

  const allowedByName = (name) => c.allowNames.some((rx) => rx.test(name))
  const matchName = (name) => c.names.find((r) => r.rx.test(name))

  async function inspectFile(dir, name, e) {
    const full = path.join(dir, name)
    const isExec = EXECUTABLE_EXT.includes(e)
    const nameRule = !allowedByName(name) ? matchName(name) : null
    const wantHash = c.hashes.size > 0 || c.allowHashes.size > 0
    let st = null
    let sha = null
    if (nameRule || (isExec && wantHash) || (CONTENT_EXT.includes(e) && c.strings.length)) {
      try {
        st = await fs.promises.stat(full)
      } catch {
        return
      }
    }
    if (isExec && wantHash && st && st.size <= MAX_HASH_BYTES && !/[\\/]program files( \(x86\))?[\\/]/i.test(dir)) {
      sha = await sha256File(full)
      stats.hashed++
      if (sha && c.allowHashes.has(sha)) return
      const hit = sha ? c.hashes.get(sha) : null
      if (hit) {
        add({ tier: 'bekraftad', category: hit.category, label: hit.label, ruleId: hit.id, kind: 'fil', name, dir: cleanPath(dir), size: st.size, modified: st.mtime.toISOString(), sha256: sha })
        return
      }
    }
    if (nameRule && st) {
      if (!sha && isExec && st.size <= MAX_HASH_BYTES) sha = await sha256File(full)
      if (sha && c.allowHashes.has(sha)) return
      add({ tier: nameTier(nameRule, 'fil', e), category: nameRule.category, label: nameRule.label, ruleId: nameRule.id, kind: 'fil', name, dir: cleanPath(dir), size: st.size, modified: st.mtime.toISOString(), sha256: sha ?? undefined })
      return
    }
    if (CONTENT_EXT.includes(e) && c.strings.length && st && st.size > 0 && st.size <= MAX_CONTENT_BYTES) {
      let text = ''
      try {
        text = await fs.promises.readFile(full, 'latin1')
      } catch {
        return
      }
      const hit = c.strings.find((r) => r.rxs.every((rx) => rx.test(text)))
      if (hit) {
        const h = await sha256File(full)
        if (h && c.allowHashes.has(h)) return
        add({ tier: hit.tier, category: hit.category, label: hit.label, ruleId: hit.id, kind: 'innehall', name, dir: cleanPath(dir), size: st.size, modified: st.mtime.toISOString(), sha256: h ?? undefined })
      }
    }
  }

  async function walk(root) {
    const stack = [root]
    while (stack.length) {
      if (control.aborted) return
      const dir = stack.pop()
      current = dir
      stats.dirs++
      let handle
      try {
        handle = await fs.promises.opendir(dir)
      } catch {
        stats.skipped++
        continue
      }
      try {
        for await (const entry of handle) {
          if (control.aborted) return
          const lower = entry.name.toLowerCase()
          if (entry.isSymbolicLink()) continue
          if (entry.isDirectory()) {
            if (SKIP_DIRS.has(lower)) continue
            if (dir === root && SKIP_ROOT_CHILD.has(lower)) continue
            if (!allowedByName(entry.name)) {
              const r = matchName(entry.name)
              if (r) add({ tier: nameTier(r, 'mapp'), category: r.category, label: r.label, ruleId: r.id, kind: 'mapp', name: entry.name, dir: cleanPath(dir) })
            }
            stack.push(path.join(dir, entry.name))
          } else if (entry.isFile()) {
            stats.files++
            await inspectFile(dir, entry.name, ext(entry.name))
            if (stats.files % 400 === 0) {
              emit('filer')
              await new Promise((r) => setImmediate(r))
            }
          }
        }
      } catch {
        stats.skipped++
      }
    }
  }

  // 1. Körande program
  emit('program', true)
  const procOut = process.platform === 'win32' ? await run('tasklist', ['/fo', 'csv', '/nh']) : await run('ps', ['-eo', 'comm='])
  const procNames = new Set()
  for (const line of procOut.split(/\r?\n/)) {
    const n = (process.platform === 'win32' ? (line.match(/^"([^"]+)"/)?.[1] ?? '') : line.trim()).trim()
    if (n) procNames.add(n)
  }
  stats.processes = procNames.size
  for (const n of procNames) {
    const r = allowedByName(n) ? null : matchName(n)
    if (r) add({ tier: 'sannolik', category: r.category, label: r.label, ruleId: r.id, kind: 'process', name: n, dir: '(körs just nu)' })
  }

  // 2. Autostart (Windows)
  if (process.platform === 'win32') {
    emit('autostart', true)
    for (const key of ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run']) {
      const out = await run('reg', ['query', key])
      for (const line of out.split(/\r?\n/)) {
        const m = line.match(/^\s+(.+?)\s+REG_\w+\s+(.*)$/)
        if (!m) continue
        stats.autostart++
        const r = matchName(`${m[1]} ${m[2]}`)
        if (r && !allowedByName(m[2])) add({ tier: nameTier(r, 'autostart'), category: r.category, label: r.label, ruleId: r.id, kind: 'autostart', name: m[1], dir: cleanPath(m[2]).slice(0, 200) })
      }
    }
  }

  // 3. Filer på alla diskar
  const rootList = roots ?? listRoots()
  stats.drives = rootList.length
  for (const r of rootList) {
    if (control.aborted) break
    await walk(r)
  }

  // 4. Digital signatur för träffarna (bara Windows, bara ett fåtal)
  if (process.platform === 'win32') {
    emit('signaturer', true)
    for (const f of findings.filter((x) => x.kind === 'fil' && x.dir).slice(0, 15)) {
      if (control.aborted) break
      f.signed = await signatureOf(path.join(f.dir.replace('<användare>', os.userInfo().username), f.name))
    }
  }

  findings.sort((a, b) => TIER_RANK[b.tier] - TIER_RANK[a.tier])
  emit('klar', true)
  stats.ms = Date.now() - started
  return { findings, stats, aborted: Boolean(control.aborted) }
}

module.exports = { scan, cleanPath, compile, TIER_RANK }
