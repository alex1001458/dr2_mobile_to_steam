# Danganronpa 2 Mobile → Steam Save Converter

## **DISCLAIMER: THIS PROGRAM WAS DEVELOPED USING AI**

Experimental community tool for converting **Danganronpa 2 mobile** `savedata.tc` files into **Danganronpa 2 Steam** `savedata.vfs` candidates.

This tool was built by comparing mobile and Steam save formats. It does **not** include game files, save files, copyrighted assets, or keys. It only transforms save files that the user provides.

## Current verified result

A completed mobile save was successfully converted into a Steam-loadable save using a mobile stream wrapped with a Steam save prefix of `740` bytes. The converted save preserved:

- Load/Continue behavior
- Chapter Select unlocks
- Monocoins/stats/items
- Magical Girl Monomi
- Island Mode
- Danganronpa IF / Novel unlock state when present

The exact best stream can differ per save, so the tool generates several candidates and a `try_first` folder instead of pretending one stream number works for everyone.

## Requirements

- Python 3.10 or newer
- No third-party Python packages required

## Before you start

Back up everything.

For Steam, back up these files if present:

```text
savedata.vfs
savedata.bak
savedata.tmp
```

Also disable Steam Cloud for Danganronpa 2 while testing, otherwise Steam may overwrite your test file.

## Files you need

### 1. Mobile save

Usually named:

```text
savedata.tc
```

Common Android location:

```text
Android/data/jp.co.spike_chunsoft.DR2/files/savedata.tc
```

### 2. Fresh Steam save template

Create a new save in the Steam version, then copy the Steam `savedata.vfs` somewhere safe. Rename the copy to:

```text
fresh_savedata.vfs
```

Using a fresh Steam save is recommended because it gives the converter a clean Steam save wrapper.

## Easiest Windows workflow

Put these files in the same folder:

```text
dr2_mobile_to_steam.py
savedata.tc
fresh_savedata.vfs
DR2_Save_Converter_Wizard.bat
```

Double-click:

```text
DR2_Save_Converter_Wizard.bat
```

Press Enter for the defaults if your files are named exactly `savedata.tc` and `fresh_savedata.vfs`.

The tool will create a folder like:

```text
dr2_converted_candidates_YYYYMMDD_HHMMSS
```

Open:

```text
READ_ME_FIRST_RESULTS.txt
```

## Command-line workflow

```powershell
python dr2_mobile_to_steam.py auto savedata.tc fresh_savedata.vfs
```

Optional output folder:

```powershell
python dr2_mobile_to_steam.py auto savedata.tc fresh_savedata.vfs --out-dir converted
```

Known-good default prefix is `740`:

```powershell
python dr2_mobile_to_steam.py auto savedata.tc fresh_savedata.vfs --prefix 740
```

## How to test candidates

Inside the generated output folder, start with:

```text
try_first/
```

For each candidate:

1. Pick one `.vfs` file.
2. Copy it into the Steam save folder.
3. Rename it exactly to:

```text
savedata.vfs
```

4. Launch Danganronpa 2 on Steam.
5. Try Load/Continue.
6. Check chapters, stats, items, postgame modes, and Island Mode/Novel if relevant.

Do not test multiple candidates at once. One candidate must be named `savedata.vfs`.

## If the first candidate loads but is missing postgame modes

Try later candidates with titles like:

- `EPILOGUE`
- `EPILOGUE END`
- `Dangan Island`

In one verified conversion, the best score candidate loaded the epilogue correctly, but a later Dangan Island stream contained the final postgame state.

## Once a candidate works

After loading a working candidate in Steam:

1. Enter a state where the game allows saving.
2. Save normally inside the Steam version.
3. Quit the game.
4. Back up the newly written Steam `savedata.vfs`.

That newly written file is the cleanest final Steam-native save.

## Advanced commands

The script still includes reverse-engineering commands from the lab versions:

```powershell
python dr2_mobile_to_steam.py tc-list savedata.tc --json tc_manifest.json
python dr2_mobile_to_steam.py tc-map savedata.tc --steam-template fresh_savedata.vfs --streams all --only-titled --json tc_map.json
python dr2_mobile_to_steam.py postgame-candidates savedata.tc fresh_savedata.vfs --out-dir postgame_tests --streams 50-54 --prefixes 740,716
python dr2_mobile_to_steam.py prefix-sweep savedata.tc fresh_savedata.vfs --stream-index 47 --out-dir sweep --prefixes 700-780:4,716,740
```

Most users should use `auto` or the `.bat` wizard.

## Known limitations

- This is not an official converter.
- It may generate multiple candidates because the mobile container can contain internal snapshots, autosaves, thumbnails, and postgame-state streams.
- Multi-slot restoration is experimental. The reliable path is usually to find the latest working single-slot candidate, load it in Steam, then save natively.
- Voice/language settings may not transfer exactly between mobile and Steam.

## Safety

The tool never overwrites your input files. Testing still requires replacing Steam's active `savedata.vfs`, so backups are mandatory.
