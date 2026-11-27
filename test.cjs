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

  // Nya kontroller: zip-innehåll, prefetch (tidigare körda program) och papperskorgen
  const crc = (buf) => { let c = ~0; for (const b of buf) { c ^= b; for (let k = 0; k < 8; k++) c = (c >>> 1) ^ (0xedb88320 & -(c & 1)) } return ~c >>> 0 }
  function makeZip(file, entries) {
    const locals = []; const centrals = []; let offset = 0
    for (const [name, data] of entries) {
      const n = Buffer.from(name); const d = Buffer.from(data); const h = Buffer.alloc(30)
      h.writeUInt32LE(0x04034b50, 0); h.writeUInt16LE(20, 4); h.writeUInt32LE(crc(d), 14); h.writeUInt32LE(d.length, 18); h.writeUInt32LE(d.length, 22); h.writeUInt16LE(n.length, 26)
      const cd = Buffer.alloc(46)
      cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt32LE(crc(d), 16); cd.writeUInt32LE(d.length, 20); cd.writeUInt32LE(d.length, 24); cd.writeUInt16LE(n.length, 28); cd.writeUInt32LE(offset, 42)
      locals.push(h, n, d); centrals.push(cd, n); offset += 30 + n.length + d.length
    }
    const cdBuf = Buffer.concat(centrals); const end = Buffer.alloc(22)
    end.writeUInt32LE(0x06054b50, 0); end.writeUInt16LE(entries.length, 8); end.writeUInt16LE(entries.length, 10); end.writeUInt32LE(cdBuf.length, 12); end.writeUInt32LE(offset, 16)
    fs.writeFileSync(file, Buffer.concat([...locals, cdBuf, end]))
  }
  const dir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'kontroll2-'))
  makeZip(path.join(dir2, 'semester.zip'), [['bilder/a.jpg', 'x'], ['verktyg/MittFusk.exe', 'y']])
  fs.mkdirSync(path.join(dir2, 'prefetch'))
  fs.writeFileSync(path.join(dir2, 'prefetch', 'MITTFUSK.EXE-1A2B3C4D.pf'), '')
  fs.writeFileSync(path.join(dir2, 'prefetch', 'NOTEPAD.EXE-11223344.pf'), '')
  const bin = path.join(dir2, '$Recycle.Bin', 'S-1-5-21-1')
  fs.mkdirSync(bin, { recursive: true })
  const delPath = Buffer.from('C:\\Users\\Anna\\Downloads\\mittfusk_v2.exe\0', 'utf16le')
  const ib = Buffer.alloc(28 + delPath.length)
  ib.writeBigInt64LE(2n, 0); ib.writeBigInt64LE(1234n, 8); ib.writeBigInt64LE(133500000000000000n, 16); ib.writeInt32LE(delPath.length / 2, 24); delPath.copy(ib, 28)
  fs.writeFileSync(path.join(bin, '$IABC123.exe'), ib)
  fs.writeFileSync(path.join(bin, '$RABC123.exe'), 'abc')
  const r4 = await scan({ rules, roots: [dir2], prefetchDir: path.join(dir2, 'prefetch') })
  const n4 = r4.findings.map((f) => `${f.kind}:${f.name}`)
  assert(n4.some((n) => n.startsWith('fil:semester.zip › MittFusk.exe')), 'zip-innehåll ska ge träff: ' + n4)
  assert(n4.includes('process:MITTFUSK.EXE'), 'prefetch ska ge träff: ' + n4)
  assert(n4.includes('fil:mittfusk_v2.exe'), 'papperskorgen ska ge träff: ' + n4)
  assert(r4.findings.find((f) => f.name === 'mittfusk_v2.exe').dir.includes('<användare>'), 'användarnamn ska tas bort även från papperskorgen')
  assert(!n4.some((n) => n.includes('NOTEPAD')), 'oskyldig prefetch ska inte träffa')
  const r5 = await scan({ rules: { ...rules, name: [] }, roots: [dir2], prefetchDir: path.join(dir2, 'prefetch') })
  assert(r5.findings.some((f) => f.sha256 === hash && f.tier === 'bekraftad'), 'raderad fil med känt fingeravtryck ska ge bekräftad: ' + JSON.stringify(r5.findings))
  fs.rmSync(dir2, { recursive: true, force: true })
  // Kompilerade program (8-bit och UTF-16) och Electron-paket ska innehållskollas
  const dir3 = fs.mkdtempSync(path.join(os.tmpdir(), 'kontroll3-'))
  const bad = 'discord.com/api/webhooks/1/abc leveldb'
  fs.writeFileSync(path.join(dir3, 'stealer1.exe'), Buffer.concat([Buffer.alloc(50, 0), Buffer.from(bad, 'latin1')]))
  fs.writeFileSync(path.join(dir3, 'stealer2.exe'), Buffer.from(bad, 'utf16le'))
  fs.writeFileSync(path.join(dir3, 'app.asar'), 'xx ' + bad)
  fs.writeFileSync(path.join(dir3, 'Grabber.cs'), bad)
  fs.writeFileSync(path.join(dir3, 'snaelt.exe'), Buffer.alloc(1000, 1))
  const r6 = await scan({ rules: { ...rules, name: [], hash: [] }, roots: [dir3] })
  const n6 = r6.findings.filter((f) => f.kind === 'innehall').map((f) => f.name).sort()
  assert.deepStrictEqual(n6, ['Grabber.cs', 'app.asar', 'stealer1.exe', 'stealer2.exe'], 'innehållskoll: ' + n6)
  fs.rmSync(dir3, { recursive: true, force: true })
  fs.rmSync(dir, { recursive: true, force: true })
  console.log('OK: skannern klarar alla tester')
})().catch((e) => { console.error(e); process.exit(1) })
