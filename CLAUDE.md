# gsrp-kontroll (appen heter GSRP PCcheck)

Eget projekt: frivillig säkerhetskontroll (Windows, Electron) som spelaren startar själv med en engångskod från admin. Appen är fristående (egen mapp, eget git, eget bygge) men **skickar resultatet till CAD:en** (`roblox-erlc`, Admin → Kontroller) via `POST {KONTROLL_API}/api/civil?r=kontroll` (`start` hämtar reglerna, `submit` skickar signerade träffar). Standardadress `https://roblox-erlc.vercel.app`, kan ändras med `KONTROLL_API` (bara vid `npm start`, inte i den färdiga appen).

## Delar
- `main.cjs` (fönster, anrop till CAD:en, signering HMAC), `preload.cjs`, `index.html` (hela gränssnittet), `scanner.cjs` (skanningen, lokalt), `rules.cjs` (filändelser).
- Reglerna kommer från servern vid start (`server/cheatRules.ts` i roblox-erlc + adminernas egna). Ändra regler där, inte här.
- Servern, adminfliken, migrering och juridik/principer: se `docs/KONTROLL.md` i roblox-erlc.

## Skanningen (svårt att smita undan, men inom principerna)
- Körande program: namn, sökväg och SHA-256 på programfilen (omdöpta program hittas). Autostart: register (Run/RunOnce/WOW6432Node), startmappar, schemalagda uppgifter, tjänster.
- Historik: Windows Prefetch (program som körts, även raderade) och papperskorgen (`$I`-filer: ursprungligt namn/mapp, hash på `$R`). Zip-filer: filnamn i innehållsförteckningen. Windows-mappen skannas utom stora systemmappar.
- Innehållskoll (textmönster från serverns `string`-regler): skript och källkod (js, ts, py, ps1, bat, cs, go, php, ahk m.fl.), samt `.exe/.scr` (≤ 30 MB, 8-bit och UTF-16, inte i Program Files/Windows) och `app.asar` (≤ 80 MB). Högst 6 GB program/paket läses per skanning.
- Bara befintliga träfftyper (`fil`, `mapp`, `process`, `autostart`, `innehall`) används, så servern behöver inte ändras.
- I den färdiga appen ignoreras `KONTROLL_API` (bara `npm start` får byta adress), så spelaren inte kan peka om kontrollen.
- Kvarstående luckor som bara servern i roblox-erlc kan täppa till: signeringsnyckeln ligger hos klienten, koden bör gå ut snabbt, och en admin bör vara med när kontrollen körs. Skannern hoppar fortfarande över `node_modules`, `.git`, `site-packages`, rar/7z-innehåll, programfiler över 30 MB (innehåll) och filer över 300 MB (hash). Nya mönster läggs till som regler i roblox-erlc, inte här.

## Principer (ändra inte utan att Florian säger det)
- Frivilligt och synligt: samtycke, "egen dator", ålder, kan avbrytas, inget i bakgrunden/autostart, ingen dold variant.
- Bara träffar lämnar datorn (inga fillistor, inget innehåll, Windows-användarnamn tas bort). Ingen automatisk ban.

## Starta och testa
- `npm install`, `npm test` (skannern mot en låtsasmapp), `npm start` (Electron), `npm run build:win` (portabel .exe).
- Ej testad på riktig Windows än. Kontrollera att appens protokoll (start/submit) och servern i roblox-erlc (`server/cheatCheck.ts`) hålls i synk.

## Att göra
- Skapa publikt repo (kräver Florians ok) och en release med .exe, och sätt `KONTROLL_APP_URL` på Vercel till nedladdningslänken.
- När detta repo är pushat: ta bort `kontroll/` och workflowet `kontroll-app.yml` i roblox-erlc, så det inte finns två kopior.
