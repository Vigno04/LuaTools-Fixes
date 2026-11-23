# LuaTools Fixes

Community & Wine/FEX compatibility fixes repository for **LuaTools Android** (e.g., integrity-check bypasses, Online-Fix zips, and emulator-specific patches).

## How to Add a Fix
1. Place the fix archive at `fixes/<appId>.zip` (contents are extracted directly into the game's install directory, with `.luatools_backup` created for any overwritten files and automatic Wine `DllOverrides` for known proxy DLLs).
2. Add an entry to `fixes.json`:
```json
[
  {
    "appId": "1868140",
    "name": "DAVE THE DIVER",
    "title": "Wine/FEX FileIntegrityCheck Bypass",
    "description": "Bypasses FileIntegrityCheck.CheckFileIntegrity() mismatch under Wine/FEX",
    "zipUrl": "https://raw.githubusercontent.com/Vigno04/LuaTools-Fixes/main/fixes/1868140.zip"
  }
]
```
