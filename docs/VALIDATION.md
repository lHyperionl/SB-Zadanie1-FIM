# Výsledky overenia

Dokument má dve časti: pôvodné overenie a následné
overenie plného nasadenia z 23. a 24. 11. 2026.

# Časť 1: Pôvodné overenie implementácie

Implementácia bola overovaná na Linuxe vo WSL, distribúcia Ubuntu 26.04,
Python 3.12.14, watchdog 7.0.0. Nie iba simuláciou POSIX oprávnení vo Windows.

## Automatizované kontroly

- Celá sada: **38 úspešných testov**, `python -m pytest -q`, vrátane root
  testov prepínania UID (8,67 s pri záverečnom behu).
- Bezpečnostné scenáre: zmeny pri rovnakom mtime a veľkosti, symlinky,
  FIFO, neprístupný súbor, nestabilný zápis, obmedzenie veľkosti a počtu položiek.
- Polnoc: konce mesiacov a roka, priestupný deň, dátumy zmeny letného času,
  päťsekundový prechod a útok počas plánovanej aktualizácie.
- Reálny lokálny SMTP prijímač, overenie poradia STARTTLS pred autentifikáciou,
  trvalý front, opakovanie doručenia a deduplikácia.
- Detekcia cez reálne Linux udalosti do dvoch sekúnd pri vypnutom krátkom
  periodickom intervale; náhradná kontrola pri nedostupnom pozorovateľovi.
- Root test chráneného prostredia pod dočasným `/opt/fim-smoke-*`: nainštalované
  moduly, izolovaný Python, root kontrola ciest, oddelené UID, inicializácia,
  neprivilegované publikovanie a kontrola, detekcia útoku. Test nevytvára účty.
- `bash -n` pre oba inštalačné skripty.
- Úspešne zostavený wheel `tuke_fim-1.0.0-py3-none-any.whl`.
- `systemd-analyze verify` pre jednotky. Pri tomto syntaktickom teste sú iba
  cesty k ešte nenainštalovaným programom nahradené existujúcimi executable.

## End-to-end s Mailpit

Použitý bol skutočný Mailpit **v1.33.0**, stiahnutý z oficiálneho vydania
a overený SHA-256 z inštalačného skriptu. Samostatný test spustil Mailpit aj
FIM na dočasných dátach a lokálnych portoch, zmenil CSS a overil e-mail cez
HTTP API Mailpit. Referenčná databáza ostala byte-for-byte nezmenená.

Namerané pri jednom behu: **1 doručený e-mail, 1,045 s od zmeny po doručenie**.
Toto je výsledok malej ukážky, nie výkonová záruka pre ľubovoľný web.

## Čo pôvodné výsledky nepokrývali

Po následnom audite pribudli regresné testy `tests/test_adversarial_tree.py`:
neplatné POSIX názvy vrátane zápisu alertu do SQLite a zotavenia, obmedzenie
enumerácie ešte pred materializáciou zoznamu, globálny rozpočet položiek
a bezpečný limit hĺbky. Pôvodný údaj o 38 testoch vyššie popisuje prvé overenie.

Kompletný inštalátor s apt, Nginx a zapnutím trvalých systemd služieb nebol
pri pôvodnom overení spustený. Toto dopĺňa časť 2. Root smoke test overuje
chránené rozloženie a prácu účtov, nenahrádza beh celého servera so systemd
sandboxom.

Testy letného času používajú správne časové pásmo a relevantné dátumy;
neposúvajú systémové hodiny a nesimulujú každý možný skok systémového času.
Nejde o dôkaz odolnosti voči root ani o záruku zachytenia každej krátkej zmeny.

# Časť 2: Overenie plného nasadenia (23. a 24. 11. 2026)

Prostredie: WSL 2, **Ubuntu 24.04.1 LTS** so zapnutým systemd 255,
Python 3.12.3, watchdog 7.0.0, pytest 9.2.0, aiosmtpd 1.4.6.
Nejde o vyhradenú VM, ale o existujúcu WSL distribúciu bez predchádzajúcej
inštalácie FIM.

## Automatizované testy

- Pridané 2 testy v `tests/test_integrity.py`, ktoré výslovne pokrývajú
  scenáre 4 a 5 z `docs/ATTACKS.md`:
  - `test_new_symlink_is_unexpected_type_and_never_read`: nový symlink sa
    nahlási ako `unexpected_type` a cieľ odkazu sa nečíta,
  - `test_file_permission_change_is_metadata_only`: zmena práv súboru sa
    nahlási iba ako `metadata_changed`, hash obsahu sa nezmení.
- Pridaný 1 test v `tests/test_linux_permissions.py`,
  `test_publisher_sandbox_allows_rename_from_staging_to_web`. Kontroluje
  nastavenie `fim-publish.service`; na pôvodnom nastavení zlyhá, na
  opravenom prejde. Samotný sandbox systemd nespúšťa.
- Sada bez root (24. 11.): **38 passed, 3 skipped** (11,9 s),
  `PYTHONPATH=src python -m pytest -q -rs`. Preskočené sú 3 testy, ktoré
  vyžadujú root. Celkový počet testov je teraz 41.
- Root testy (24. 11., po opravách): **5 passed** (2,88 s),
  `sudo env PYTHONPATH=src python -m pytest -q tests/test_linux_permissions.py tests/test_installed_smoke.py`.
  Zahŕňajú 3 testy preskočené v behu bez root, test syntaxe systemd jednotiek
  a test zapisovateľnej cesty generátora.
- Spolu teda po opravách prešlo **všetkých 41 testov**.

## Plná inštalácia

- `sudo bash deploy/install.sh` a `sudo bash deploy/install-mailpit.sh`
  skončili úspešne. Inštalátor bol spustený z kópie projektu v domovskom
  priečinku WSL (`~/fim`), nie z `/mnt/c`.
- Služby `fim-monitor`, `fim-publish.timer`, `nginx` a `fim-mailpit` sú
  aktívne. Časovač má najbližšie spustenie o 00:00:00 CET.
- Stránka na `http://localhost:8080` zobrazuje dátum 23. 11. 2026 a meniny
  (Klement).
- `fim test-alert` doručil e-mail do Mailpit (`http://localhost:8025`).
- Po úplnom vypnutí a opätovnom spustení WSL sa všetky služby spustili samé.

## Ručné scenáre podľa docs/ATTACKS.md

| Scenár | Výsledok |
|---|---|
| 1. Skript vložený do `index.html` | `daily_content_changed`, e-mail doručený; pri opakovaných skenoch nevznikol ďalší e-mail; `fim-publish` odmietol prepis (`Refusing to overwrite noncanonical index.html`); po obnove `incident_resolved` |
| 2. Pridaný a odstránený súbor | `added` (`probe.php`) a `removed` (`style.css`), oba e-maily doručené, po obnove `incident_resolved` |
| 3. Rovnaká veľkosť a zachovaný čas | `content_changed`; veľkosť aj mtime pred a po útoku zhodné na nanosekundy |
| 4. Symlink a FIFO | dvakrát `unexpected_type` (`symlink`, `special`), `sha256` je `null`, monitor pokračoval v skenovaní |
| 5. Zmena oprávnení | `metadata_changed` (mode 0664 → 0666, rovnaký hash), `fim-publish` odmietol prepis (`unexpected ownership/permissions`) |
| 6. Zmena konfigurácie, baseline a programu | všetky tri pokusy skončili `Permission denied` |
| 7. Výpadok SMTP | po zastavení Mailpit `alert_delivery_failed`, po jeho spustení bol čakajúci alert doručený |
| 7. Pád monitora (`SIGKILL`) | systemd službu reštartoval s novým PID |
| 7. Prepis po zmeškanej polnoci | 24. 11. o 09:38 **najprv zlyhal** (`Invalid cross-device link`) a monitor správne nahlásil `daily_content_changed`. Po oprave o 09:49:57 `page_published`, stránka 24. 11. 2026 (Emília), `incident_resolved`, `findings: 0` |
| 7. Automatický prepis po štarte (po oprave) | 24. 11.: pri zastavenom monitore vložená platná stránka z 23. 11. a Ubuntu vypnuté (`wsl --terminate`). Po zapnutí o 10:22:42 `page_published` bez zásahu, monitor sa spustil až potom, `findings: 0`, žiadny alert. Simulácia, nie skutočne zmeškaná polnoc |
| 7. Polnoc (00:00) | zatiaľ nepozorovaná, WSL bolo v noci z 23. na 24. 11. vypnuté |

## Chyba nasadenia zistená pri overení

- **Prejav:** generátor nedokázal vymeniť stránku za stránku nového dňa,
  požiadavka na polnočnú zmenu preto na nainštalovanom systéme nefungovala.
- **Príčina:** `fim-publish.service` mal v `ReadWritePaths` dve cesty.
  Systemd z nich vytvorí dve pripojenia a premenovanie súboru zo
  `fim-staging` do `fim-demo` skončí chybou `EXDEV`, hoci ide o ten istý
  súborový systém. Chyba nezávisí od vypnutia WSL.
- **Prečo sa neprejavila skôr:** v deň inštalácie bola stránka aktuálna
  (`page_already_current`) a automatické testy bežia mimo sandboxu systemd.
- **Oprava:** `ReadWritePaths=/var/www`. Súborové práva sa nezmenili,
  `fim-publisher` môže zapisovať do tých istých priečinkov ako predtým.
- **Testy:** posielali alerty na port 1025, teda do spusteného Mailpitu.
  Teraz používajú port 1; pri behu z 24. 11. žiadny e-mail nepribudol.

## Opravy dokumentácie zistené pri overení

- Scenár 3 v `docs/ATTACKS.md` pôvodne spúšťal útok pod `fim-publisher`.
  Ten nevlastní `style.css`, takže `os.utime` s pôvodným časom skončil
  `PermissionError` a mtime sa zmenil. Scenár teraz beží pod root.
- Doplnený scenár 5 (zmena oprávnení); pôvodné scenáre 5 a 6 sú teraz 6 a 7.

## Čo ani toto overenie nepokrýva

- Inštalácia prebehla vo WSL, nie v čerstvej vyhradenej VM ani na verejne
  dostupnom serveri.
- Alerty boli overené iba cez lokálny Mailpit, nie cez skutočnú e-mailovú
  schránku so STARTTLS a heslom.
- Automatický prepis presne o 00:00 ešte nebol pozorovaný (pozri tabuľku vyššie).
