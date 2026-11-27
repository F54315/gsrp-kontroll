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

const MAX_HASH_BYTES = 300 * 1024 * 1024
const MAX_HASH_BYTES_PROGRAMDIR = 100 * 1024 * 1024 // i Program Files/ProgramData: bara .exe, och mindre filer, så att skanningen inte tar för lång tid
const MAX_ZIP_BYTES = 4 * 1024 * 1024 * 1024 // zip läses bara i slutet (innehållsförteckningen), så stora filer går bra
const MAX_CONTENT_BYTES = 1_500_000
const MAX_FINDINGS = 300
const TIER_RANK = { osaker: 1, sannolik: 2, bekraftad: 3 }
const ARCHIVE_EXT = ['zip', 'rar', '7z']
// Skript och källkod som kollas efter textmönster (webhooks, token-/cookie-läsning, exekutor-funktioner)
const CONTENT_EXT = ['js', 'mjs', 'cjs', 'ts', 'py', 'pyw', 'bat', 'cmd', 'ps1', 'vbs', 'vbe', 'wsf', 'lua', 'luau', 'sh', 'cs', 'vb', 'go', 'rb', 'php', 'java', 'rs', 'ahk', 'au3']
// Kompilerade program och Electron-paket (app.asar innehåller läsbar JavaScript) kollas också, med gränser så skanningen inte tar för lång tid
const BINARY_CONTENT_EXT = ['exe', 'scr', 'asar']
const MAX_BINARY_CONTENT_BYTES = { exe: 30 * 1024 * 1024, scr: 30 * 1024 * 1024, asar: 80 * 1024 * 1024 }
const BINARY_CONTENT_BUDGET = 6 * 1024 * 1024 * 1024 // högst så här mycket program/paket läses totalt
// Mappar som aldrig går igenom (systemmappar, papperskorg och verktygsmappar med enorma mängder oskyldiga filer)
const SKIP_DIRS = new Set(['$recycle.bin', 'system volume information', 'node_modules', '.git', 'site-packages', 'winsxs', 'proc', 'sys', 'dev', 'windowsapps'])
// Windows-mappen skannas (Temp, Tasks m.m. brukar användas för att gömma saker) men de stora systemmapparna hoppas över.
const SKIP_IN_WINDOWS = new Set(['system32', 'syswow64', 'sysarm32', 'servicing', 'assembly', 'installer', 'microsoft.net', 'systemapps', 'softwaredistribution', 'fonts', 'inf', 'driverstore', 'immersivecontrolpanel', 'systemresources', 'diagnostics'])
const PROGRAM_DIR_RE = /[\\/](program files( \(x86\))?|programdata)[\\/]/i

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

// Läser filnamnen i en zip-fil (bara innehållsförteckningen i slutet, inget packas upp). Ger [] om filen inte går att läsa.
async function zipEntryNames(file, size) {
  let fh
  try {
    fh = await fs.promises.open(file, 'r')
    const tailLen = Math.min(size, 65557)
    const tail = Buffer.alloc(tailLen)
    await fh.read(tail, 0, tailLen, size - tailLen)
    let eocd = -1
    for (let i = tailLen - 22; i >= 0; i--) {
      if (tail.readUInt32LE(i) === 0x06054b50) {
        eocd = i
        break
      }
    }
    if (eocd < 0) return []
    const cdSize = tail.readUInt32LE(eocd + 12)
    const cdOffset = tail.readUInt32LE(eocd + 16)
    if (cdSize === 0xffffffff || cdOffset === 0xffffffff || cdSize > 8_000_000 || cdOffset + cdSize > size) return []
    const cd = Buffer.alloc(cdSize)
    await fh.read(cd, 0, cdSize, cdOffset)
    const names = []
    let pos = 0
    while (pos + 46 <= cdSize && names.length < 20000 && cd.readUInt32LE(pos) === 0x02014b50) {
      const n = cd.readUInt16LE(pos + 28)
      const m = cd.readUInt16LE(pos + 30)
      const k = cd.readUInt16LE(pos + 32)
      if (pos + 46 + n > cdSize) break
      names.push(cd.toString('utf8', pos + 46, pos + 46 + n))
      pos += 46 + n + m + k
    }
    return names
  } catch {
    return []
  } finally {
    await fh?.close().catch(() => {})
  }
}

// Delar en CSV-rad ("a","b,c","d") i fält
function csvFields(line) {
  const out = []
  const re = /"((?:[^"]|"")*)"|([^,]+)/g
  let m
  while ((m = re.exec(line))) out.push(m[1] !== undefined ? m[1].replace(/""/g, '"') : m[2])
  return out
}

// Hittar programfilen i ett kommando (t.ex. "C:\Program Files\X\x.exe" --flagga) så att den kan fingeravtryckas
function exeInCommand(cmd) {
  const expanded = String(cmd).replace(/%([^%]+)%/g, (_m, v) => process.env[v] ?? process.env[v.toUpperCase()] ?? `%${v}%`)
  const m = expanded.match(/"([^"]+\.(?:exe|scr|com|bat|cmd|ps1|vbs|jar))"/i) || expanded.match(/([A-Za-z]:\\[^"*?<>|]+?\.(?:exe|scr|com|bat|cmd|ps1|vbs|jar))(?:\s|$)/i)
  return m ? m[1] : null
}

// Windows filtid (100 ns sedan 1601) till ISO-datum
function fileTimeToIso(ft) {
  try {
    const ms = Number(ft / 10000n - 11644473600000n)
    const d = new Date(ms)
    return ms > 0 && d.getFullYear() < 2100 ? d.toISOString() : undefined
  } catch {
    return undefined
  }
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
async function scan({ rules, control = { aborted: false }, onProgress = () => {}, roots, prefetchDir }) {
  const c = compile(rules)
  const started = Date.now()
  const findings = []
  const seen = new Set()
  const stats = { files: 0, dirs: 0, skipped: 0, hashed: 0, drives: 0, processes: 0, autostart: 0, archives: 0, recycled: 0, prefetch: 0, tasks: 0, services: 0 }
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

  // Fingeravtryck på en programfil mot hash-reglerna. Ger en "bekräftad"-träff eller null. Används för program som körs och för autostart,
  // så att ett omdöpt program ändå hittas.
  let binaryBytesRead = 0
  const hashedCache = new Map()
  async function hashHit(file) {
    const key = file.toLowerCase()
    if (hashedCache.has(key)) return hashedCache.get(key)
    let result = null
    try {
      const st = await fs.promises.stat(file)
      if (st.isFile() && st.size <= MAX_HASH_BYTES && !/[\\/]windows[\\/](system32|syswow64|winsxs)[\\/]/i.test(file)) {
        const sha = await sha256File(file)
        stats.hashed++
        if (sha && !c.allowHashes.has(sha)) {
          const hit = c.hashes.get(sha)
          result = { sha, hit, size: st.size, modified: st.mtime.toISOString() }
        }
      }
    } catch {
      /* finns inte längre */
    }
    hashedCache.set(key, result)
    return result
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
    if (nameRule || (isExec && wantHash) || ((CONTENT_EXT.includes(e) || BINARY_CONTENT_EXT.includes(e)) && c.strings.length) || (e === 'zip' && c.names.length)) {
      try {
        st = await fs.promises.stat(full)
      } catch {
        return
      }
    }
    const inProgramDir = PROGRAM_DIR_RE.test(dir + path.sep)
    const hashLimit = inProgramDir ? MAX_HASH_BYTES_PROGRAMDIR : MAX_HASH_BYTES
    if (isExec && wantHash && st && st.size <= hashLimit && (!inProgramDir || e === 'exe')) {
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
      if (!sha && isExec && st.size <= hashLimit) sha = await sha256File(full)
      if (sha && c.allowHashes.has(sha)) return
      add({ tier: nameTier(nameRule, 'fil', e), category: nameRule.category, label: nameRule.label, ruleId: nameRule.id, kind: 'fil', name, dir: cleanPath(dir), size: st.size, modified: st.mtime.toISOString(), sha256: sha ?? undefined })
      return
    }
    if (e === 'zip' && st && st.size > 22 && st.size <= MAX_ZIP_BYTES && c.names.length) {
      stats.archives++
      let n = 0
      for (const entry of await zipEntryNames(full, st.size)) {
        const parts = entry.split(/[\\/]/).filter(Boolean)
        if (!parts.length || n >= 5) break
        // Filnamnet, eller (om det är en mapp i zip-filen) mappnamnen
        const candidates = entry.endsWith('/') ? parts : [parts[parts.length - 1], ...parts.slice(0, -1)]
        const hitName = candidates.find((nm) => !allowedByName(nm) && matchName(nm))
        if (!hitName) continue
        const r = matchName(hitName)
        n++
        add({ tier: nameTier(r, 'fil', ext(hitName)), category: r.category, label: r.label, ruleId: r.id, kind: 'fil', name: `${name} › ${hitName}`.slice(0, 200), dir: cleanPath(dir), size: st.size, modified: st.mtime.toISOString() })
      }
    }
    const isBinaryContent = BINARY_CONTENT_EXT.includes(e)
    const contentLimit = isBinaryContent ? (e === 'asar' || !(inProgramDir || /[\\/]windows[\\/]/i.test(dir + path.sep)) ? MAX_BINARY_CONTENT_BYTES[e] : 0) : MAX_CONTENT_BYTES
    if ((CONTENT_EXT.includes(e) || isBinaryContent) && c.strings.length && st && st.size > 0 && st.size <= contentLimit && (!isBinaryContent || binaryBytesRead + st.size <= BINARY_CONTENT_BUDGET)) {
      let buf
      try {
        buf = await fs.promises.readFile(full)
      } catch {
        return
      }
      if (isBinaryContent) binaryBytesRead += st.size
      // Text i vanliga filer är oftast 8-bit; .NET-program lagrar texten som UTF-16, så program läses även så
      let hit = c.strings.find((r) => r.rxs.every((rx) => rx.test(buf.toString('latin1'))))
      if (!hit && (e === 'exe' || e === 'scr')) {
        const wide = buf.toString('utf16le')
        hit = c.strings.find((r) => r.rxs.every((rx) => rx.test(wide)))
      }
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
            if (dir.toLowerCase() === path.join(root, 'windows').toLowerCase() && SKIP_IN_WINDOWS.has(lower)) continue
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

  const win = process.platform === 'win32'
  const ps = (script) => run('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], 30000)

  // 1. Körande program (namn, sökväg och fingeravtryck på programfilen, så att omdöpta program också hittas)
  emit('program', true)
  const procs = new Map() // namn -> Set(sökvägar)
  const addProc = (n, exe) => {
    if (!n) return
    if (!procs.has(n)) procs.set(n, new Set())
    if (exe) procs.get(n).add(exe)
  }
  if (win) {
    const out = await ps('Get-CimInstance Win32_Process | Select-Object Name,ExecutablePath | ConvertTo-Csv -NoTypeInformation')
    for (const line of out.split(/\r?\n/).slice(1)) {
      const f = csvFields(line)
      if (f[0]) addProc(f[0].trim(), (f[1] ?? '').trim())
    }
    if (!procs.size) {
      for (const line of (await run('tasklist', ['/fo', 'csv', '/nh'])).split(/\r?\n/)) addProc((line.match(/^"([^"]+)"/)?.[1] ?? '').trim())
    }
  } else {
    for (const line of (await run('ps', ['-eo', 'comm='])).split(/\r?\n/)) addProc(line.trim())
  }
  stats.processes = procs.size
  for (const [n, exes] of procs) {
    const exeList = [...exes]
    const r = allowedByName(n) ? null : (matchName(n) ?? exeList.map((x) => (allowedByName(x) ? null : matchName(x))).find(Boolean))
    if (r) add({ tier: 'sannolik', category: r.category, label: r.label, ruleId: r.id, kind: 'process', name: n, dir: exeList[0] ? cleanPath(exeList[0]) : '(körs just nu)' })
    if (c.hashes.size) {
      for (const x of exeList.slice(0, 3)) {
        if (control.aborted) break
        const h = await hashHit(x)
        if (h?.hit) add({ tier: 'bekraftad', category: h.hit.category, label: h.hit.label, ruleId: h.hit.id, kind: 'process', name: n, dir: cleanPath(x), size: h.size, modified: h.modified, sha256: h.sha })
      }
    }
  }

  // 2. Autostart (Windows): registret, startmappar, schemalagda uppgifter och tjänster
  async function checkAutostart(label, cmd, source) {
    stats.autostart++
    const r = !allowedByName(cmd) ? matchName(`${label} ${cmd}`) : null
    if (r) add({ tier: nameTier(r, 'autostart'), category: r.category, label: r.label, ruleId: r.id, kind: 'autostart', name: String(label).slice(0, 120), dir: cleanPath(`${source}: ${cmd}`).slice(0, 200) })
    if (c.hashes.size && !/^[A-Za-z]:\\Windows\\/i.test(cmd)) {
      const exe = exeInCommand(cmd)
      const h = exe ? await hashHit(exe) : null
      if (h?.hit) add({ tier: 'bekraftad', category: h.hit.category, label: h.hit.label, ruleId: h.hit.id, kind: 'autostart', name: String(label).slice(0, 120), dir: cleanPath(`${source}: ${exe}`).slice(0, 200), size: h.size, modified: h.modified, sha256: h.sha })
    }
  }
  if (win) {
    emit('autostart', true)
    const regKeys = [
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
      'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
      'HKLM\\Software\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Run',
    ]
    for (const key of regKeys) {
      for (const line of (await run('reg', ['query', key])).split(/\r?\n/)) {
        const m = line.match(/^\s+(.+?)\s+REG_\w+\s+(.*)$/)
        if (m) await checkAutostart(m[1], m[2], 'register')
      }
    }
    const startDirs = [path.join(process.env.APPDATA ?? '', 'Microsoft\\Windows\\Start Menu\\Programs\\Startup'), path.join(process.env.ProgramData ?? '', 'Microsoft\\Windows\\Start Menu\\Programs\\StartUp')]
    for (const d of startDirs) {
      let names = []
      try {
        names = await fs.promises.readdir(d)
      } catch {
        /* finns inte */
      }
      for (const n of names) if (n.toLowerCase() !== 'desktop.ini') await checkAutostart(n, path.join(d, n), 'startmapp')
    }
    const seenTasks = new Set()
    for (const line of (await run('schtasks', ['/query', '/fo', 'csv', '/v', '/nh'], 40000)).split(/\r?\n/)) {
      const f = csvFields(line)
      const taskName = f[1]
      if (!taskName || seenTasks.has(taskName)) continue
      seenTasks.add(taskName)
      if (/^\\Microsoft\\/i.test(taskName)) continue
      stats.tasks++
      await checkAutostart(taskName.replace(/^\\/, ''), f[8] ?? '', 'schemalagd uppgift')
    }
    const svcOut = await ps('Get-CimInstance Win32_Service | Select-Object Name,PathName | ConvertTo-Csv -NoTypeInformation')
    for (const line of svcOut.split(/\r?\n/).slice(1)) {
      const f = csvFields(line)
      if (!f[0] || !f[1] || /[\\/]windows[\\/]/i.test(f[1])) continue
      stats.services++
      await checkAutostart(f[0], f[1], 'tjänst')
    }
  }

  // 2b. Program som körts tidigare (Windows Prefetch). Finns kvar även om programmet raderats efteråt.
  const pfDir = prefetchDir ?? (win ? path.join(process.env.SystemRoot ?? 'C:\\Windows', 'Prefetch') : null)
  if (pfDir) {
    emit('historik', true)
    let pf = []
    try {
      pf = await fs.promises.readdir(pfDir)
    } catch {
      /* kräver administratörsrättigheter på vissa datorer */
    }
    for (const file of pf) {
      if (!/\.pf$/i.test(file)) continue
      stats.prefetch++
      const exe = file.replace(/-[0-9A-F]{8}\.pf$/i, '')
      const r = !allowedByName(exe) ? matchName(exe) : null
      if (!r) continue
      let modified
      try {
        modified = (await fs.promises.stat(path.join(pfDir, file))).mtime.toISOString()
      } catch {
        /* hoppa över */
      }
      add({ tier: 'sannolik', category: r.category, label: r.label, ruleId: r.id, kind: 'process', name: exe, dir: '(har körts tidigare på datorn)', modified })
    }
  }

  // 2c. Papperskorgen: raderade filer går att se via $I-filerna (ursprungligt namn och mapp). Kollas på alla diskar.
  async function scanRecycle(root) {
    const bin = path.join(root, '$Recycle.Bin')
    let sids = []
    try {
      sids = await fs.promises.readdir(bin)
    } catch {
      return
    }
    for (const sid of sids) {
      if (control.aborted) return
      let items = []
      try {
        items = await fs.promises.readdir(path.join(bin, sid))
      } catch {
        continue
      }
      for (const item of items.filter((i) => /^\$I/i.test(i)).slice(0, 5000)) {
        try {
          const buf = await fs.promises.readFile(path.join(bin, sid, item))
          if (buf.length < 28 || buf.length > 4096) continue
          const version = Number(buf.readBigInt64LE(0))
          const size = Number(buf.readBigInt64LE(8))
          const deleted = fileTimeToIso(buf.readBigInt64LE(16))
          const raw = version === 2 ? buf.toString('utf16le', 28, 28 + buf.readInt32LE(24) * 2) : buf.toString('utf16le', 24)
          const full = raw.replace(/\0+$/, '')
          const parts = full.split(/[\\/]/).filter(Boolean)
          const name = parts[parts.length - 1]
          if (!name) continue
          stats.recycled++
          const candidates = [name, ...parts.slice(0, -1)]
          const hitName = candidates.find((nm) => !allowedByName(nm) && matchName(nm))
          const dir = '(papperskorgen) ' + cleanPath(parts.slice(0, -1).join('\\'))
          if (hitName) {
            const r = matchName(hitName)
            add({ tier: nameTier(r, hitName === name ? 'fil' : 'mapp', ext(name)), category: r.category, label: r.label, ruleId: r.id, kind: 'fil', name, dir, size, modified: deleted })
            continue
          }
          // Raderad programfil med känt fingeravtryck (filen heter $R + samma suffix)
          if (c.hashes.size && EXECUTABLE_EXT.includes(ext(name))) {
            const h = await hashHit(path.join(bin, sid, '$R' + item.slice(2)))
            if (h?.hit) add({ tier: 'bekraftad', category: h.hit.category, label: h.hit.label, ruleId: h.hit.id, kind: 'fil', name, dir, size, modified: deleted, sha256: h.sha })
          }
        } catch {
          /* hoppa över */
        }
      }
    }
  }

  // 3. Filer på alla diskar
  const rootList = roots ?? listRoots()
  stats.drives = rootList.length
  emit('papperskorg', true)
  for (const r of rootList) await scanRecycle(r)
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
