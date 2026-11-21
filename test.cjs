'use strict'
// Enkelt test av skannern mot en låtsasmapp (kör: npm test). Kräver tsx för att läsa reglerna: npx tsx kontroll/test.cjs är inte nödvändigt,
// här används en liten uppsättning regler direkt.
const assert = require('assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const crypto = require('crypto')
const { scan, cleanPath } = require('./scanner.cjs')

;(async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'kontroll-'))
  fs.mkdirSync(path.join(dir, 'Downloads', 'MittFusk'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'Downloads', 'MittFusk', 'start.exe'), 'abc')
  fs.writeFileSync(path.join(dir, 'Downloads', 'bra.exe'), 'xyz')
  fs.writeFileSync(path.join(dir, 'Downloads', 'ok.txt'), 'hej')
  fs.writeFileSync(path.join(dir, 'Downloads', 'grab.py'), 'u="https://discord.com/api/webhooks/1/a"\nopen("Local Storage/leveldb")')
  const hash = crypto.createHash('sha256').update('abc').digest('hex')
  const rules = {
    name: [{ id: 'n1', kind: 'name', pattern: 'mittfusk', category: 'roblox-fusk', tier: 'sannolik', label: 'Test' }],
    string: [{ id: 's1', kind: 'string', category: 'token-grabber', tier: 'sannolik', label: 'Grabber', patterns: ['discord(app)?\\.com/api/webhooks/', 'leveldb'] }],
    hash: [{ id: 'h1', kind: 'hash', pattern: hash, category: 'roblox-fusk', tier: 'bekraftad', label: 'Hash' }],
    allow: [],
  }
  const r = await scan({ rules, roots: [dir] })
  const names = r.findings.map((f) => `${f.tier}:${f.name}`)
  assert(names.includes('bekraftad:start.exe'), 'hash ska ge bekräftad: ' + names)
  assert(names.includes('sannolik:MittFusk'), 'mapp ska ge sannolik')
  assert(names.includes('sannolik:grab.py'), 'skript ska ge sannolik')
  assert(!names.some((n) => n.includes('bra.exe') || n.includes('ok.txt')), 'oskyldiga filer ska inte träffa')
  const r2 = await scan({ rules: { ...rules, allow: [{ kind: 'hash', pattern: hash }] }, roots: [dir] })
  assert(!r2.findings.some((f) => f.name === 'start.exe'), 'tillåtelselistan ska ta bort träffen')
  assert.strictEqual(cleanPath('C:\\Users\\Anna\\Downloads'), 'C:\\Users\\<användare>\\Downloads')
  const abort = { aborted: true }
  const r3 = await scan({ rules, roots: [dir], control: abort })
  assert(r3.aborted && r3.findings.length === 0, 'avbrutet ska inte ge träffar')
  fs.rmSync(dir, { recursive: true, force: true })
  console.log('OK: skannern klarar alla tester')
})().catch((e) => { console.error(e); process.exit(1) })
