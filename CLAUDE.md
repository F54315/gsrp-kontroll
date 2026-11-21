# gsrp-kontroll (GSRP Kontroll)

Eget projekt: frivillig säkerhetskontroll (Windows, Electron) som spelaren startar själv med en engångskod från admin. Appen är fristående (egen mapp, eget git, eget bygge) men **skickar resultatet till CAD:en** (`roblox-erlc`, Admin → Kontroller) via `POST {KONTROLL_API}/api/civil?r=kontroll` (`start` hämtar reglerna, `submit` skickar signerade träffar). Standardadress `https://roblox-erlc.vercel.app`, kan ändras med `KONTROLL_API`.

## Delar
- `main.cjs` (fönster, anrop till CAD:en, signering HMAC), `preload.cjs`, `index.html` (hela gränssnittet), `scanner.cjs` (skanningen, lokalt), `rules.cjs` (filändelser).
- Reglerna kommer från servern vid start (`server/cheatRules.ts` i roblox-erlc + adminernas egna). Ändra regler där, inte här.
- Servern, adminfliken, migrering och juridik/principer: se `docs/KONTROLL.md` i roblox-erlc.

## Principer (ändra inte utan att Florian säger det)
- Frivilligt och synligt: samtycke, "egen dator", ålder, kan avbrytas, inget i bakgrunden/autostart, ingen dold variant.
- Bara träffar lämnar datorn (inga fillistor, inget innehåll, Windows-användarnamn tas bort). Ingen automatisk ban.

## Starta och testa
- `npm install`, `npm test` (skannern mot en låtsasmapp), `npm start` (Electron), `npm run build:win` (portabel .exe).
- Ej testad på riktig Windows än. Kontrollera att appens protokoll (start/submit) och servern i roblox-erlc (`server/cheatCheck.ts`) hålls i synk.

## Att göra
- Skapa publikt repo (kräver Florians ok) och en release med .exe, och sätt `KONTROLL_APP_URL` på Vercel till nedladdningslänken.
- När detta repo är pushat: ta bort `kontroll/` och workflowet `kontroll-app.yml` i roblox-erlc, så det inte finns två kopior.
