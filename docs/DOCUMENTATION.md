# File Integrity Monitoring – dokumentácia riešenia

Dokument popisuje riešenie zadania 1 z predmetu Softvérová bezpečnosť:
ako spĺňa požiadavky zadania, ako funguje, ako ho predviesť a aké sú jeho
bezpečnostné vlastnosti a obmedzenia.

Pri predvedení sú uvedené:

- **Predvedenie:** súbor, stránka alebo príkaz,
- **Očakávaný výsledok:** čo sa má zobraziť, ak riešenie funguje správne,
- **Vysvetlenie:** čo predvedenie dokazuje a prečo je riešenie navrhnuté takto.

Súvisiace dokumenty: [README.md](../README.md) (inštalácia a prevádzka),
[ATTACKS.md](ATTACKS.md) (všetky bezpečnostné scenáre), [VALIDATION.md](VALIDATION.md)
(namerané výsledky overenia).

---

## Obsah

1. [Zadanie a splnenie požiadaviek](#1-zadanie-a-splnenie-požiadaviek)
2. [Ako riešenie funguje](#2-ako-riešenie-funguje)
3. [Prostredie a príprava predvedenia](#3-prostredie-a-príprava-predvedenia)
4. [Predvedenie požiadaviek zadania](#4-predvedenie-požiadaviek-zadania)
5. [Predvedenie útokov](#5-predvedenie-útokov)
6. [Automatické testy](#6-automatické-testy)
7. [Bezpečnostné rozhodnutia](#7-bezpečnostné-rozhodnutia)
8. [Obmedzenia riešenia](#8-obmedzenia-riešenia)
9. [Súvislosť s prednáškou](#9-súvislosť-s-prednáškou)
10. [Otázky a odpovede](#10-otázky-a-odpovede)
11. [Mapa súborov](#11-mapa-súborov)
12. [Slovník pojmov](#12-slovník-pojmov)
13. [Prehľad príkazov](#13-prehľad-príkazov)

---

## 1. Zadanie a splnenie požiadaviek

**Zadanie:** zostaviť programové riešenie pre monitorovanie integrity súborov
(FIM), nasadiť ho na webový server a monitorovať ním súbory webovej stránky.
Na `index.html` má byť dnešný dátum a meniny, ktoré sa menia o polnoci.

| # | Požiadavka zadania | Ako ju riešenie spĺňa | Kde v kóde |
|---|---|---|---|
| 1 | Pri spustení načíta parametre z konfiguračného súboru | TOML súbor `/etc/fim/config.toml`, cesta sa zadáva parametrom `--config` | [config.py](../src/fim/config.py#L89) |
| 2 | Zapisuje informácie do logovacieho súboru | `/var/log/fim/fim.jsonl`, jeden JSON záznam na riadok, rotácia 5 × 5 MiB | [events.py](../src/fim/events.py#L22) |
| 3 | Pri incidente upozorní kompetentnú osobu | e-mail cez SMTP, trvalá fronta správ s opakovaním doručenia | [alerts.py](../src/fim/alerts.py#L16), [runtime.py](../src/fim/runtime.py#L52) |
| 4 | Informácie o baseline sú uložené v databáze | SQLite `/var/lib/fim/reference/baseline.sqlite` | [baseline.py](../src/fim/baseline.py#L76) |
| 5 | Nasadenie na webovom serveri, monitorovanie súborov webu | Nginx na porte 8080, web `/var/www/fim-demo`, služby systemd | [deploy/](../deploy/) |
| 6 | `index.html` s dátumom a meninami, zmena o polnoci | časovač systemd o 00:00 (Europe/Bratislava), oficiálny kalendár menín | [page.py](../src/fim/page.py#L83), [fim-publish.timer](../deploy/fim-publish.timer) |

**Technológie:** Python 3.12, SQLite, Linux (referenčne Ubuntu 24.04), systemd,
Nginx, knižnica `watchdog` (udalosti zmien súborov), Mailpit (testovací
prijímač e-mailov).

**Zhrnutie:** riešenie stráži súbory webovej stránky zobrazovanej cez Nginx.
Správny stav súborov je uložený v SQLite databáze, činnosť sa zapisuje do
logu a pri zmene dostane správca e-mail. Stránka `index.html` sa každú polnoc
prepíše na nový dátum a meniny a FIM túto legitímnu zmenu rozlišuje od útoku.

---

## 2. Ako riešenie funguje

### 2.1 Princíp FIM

File Integrity Monitoring overuje integritu súborov porovnaním ich
aktuálneho stavu so známym korektným stavom (baseline). Súbory sa
neporovnávajú celé, ale pomocou hashu (digitálneho odtlačku). Zmena čo i len
jedného bajtu vedie k úplne inému hashu.

Postup má tri kroky:

1. **Baseline:** zaznamenanie správneho stavu súborov a ich hashov.
2. **Monitorovanie:** priebežné porovnávanie aktuálneho stavu s baseline.
3. **Reakcia:** pri rozdiele sa zaznamená incident a upozorní správca.

FIM je **detekčné** opatrenie: zmenám nezabraňuje, ale odhaľuje ich.
Zabránenie zmenám zabezpečujú preventívne opatrenia, v tomto riešení
napríklad prístupové práva (pozri [kapitolu 7](#7-bezpečnostné-rozhodnutia)).

### 2.2 Architektúra

```
                    ┌─────────────────────┐
  o polnoci ──────► │  fim publish        │ ──► prepíše index.html
  (časovač)         │  účet fim-publisher │     (nový dátum + meniny)
                    └─────────────────────┘
                                                 ┌──────────────────┐
                                                 │ /var/www/fim-demo│ ◄── Nginx ho
                                                 │  index.html      │     zobrazuje na
                                                 │  style.css       │     http://localhost:8080
                                                 └────────┬─────────┘
                                                          │ iba číta
                    ┌─────────────────────┐               │
 config.toml ─────► │  fim watch          │ ◄─────────────┘
                    │  účet fim-monitor   │ ◄── baseline.sqlite (iba číta)
                    └──┬──────────┬───────┘
                       │          │
                       ▼          ▼
                  fim.jsonl    runtime.sqlite ──► e-mail správcovi
                  (log)        (incidenty + fronta e-mailov)
```

Riešenie tvoria dve časti, ktoré bežia pod dvoma rôznymi systémovými účtami:

- **`fim watch` (monitor, účet `fim-monitor`)** beží nepretržite ako služba
  systemd. Web aj baseline môže iba čítať. Zapisuje iba do logu a do
  prevádzkovej databázy incidentov.
- **`fim publish` (generátor, účet `fim-publisher`)** spúšťa časovač o polnoci.
  Prepíše `index.html` a skončí.

Oddelenie účtov zabezpečuje, že útočník, ktorý ovládne účet s právom meniť
web, nezíska kontrolu nad monitorom ani nad baseline.

### 2.3 Priebeh jednej kontroly

Monitor spustí kontrolu, keď nastane jedna z týchto udalostí
([daemon.py](../src/fim/daemon.py#L114)):

| Spúšťač | Účel |
|---|---|
| Linux ohlási zmenu súboru (`watchdog`, oneskorenie 0,2 s) | okamžitá reakcia, zvyčajne do 1 s |
| Uplynulo 30 s od poslednej kontroly | poistka pre prípad straty udalosti |
| Zmena dňa a uplynutie 5 s po polnoci | overenie novej dennej stránky |

Kontrola ([monitor.py](../src/fim/monitor.py#L33)):

1. Prejde všetky položky webu ([safefs.py](../src/fim/safefs.py#L100)).
2. Pre každý súbor vypočíta **SHA-256** a zistí **práva, vlastníka, skupinu
   a veľkosť**.
3. Spojí zoznam položiek z baseline so zoznamom na disku a porovná ich:

| V baseline | Na disku | Výsledok |
|---|---|---|
| nie | áno | `added`, alebo `unexpected_type`, ak nejde o súbor ani priečinok (symlink, FIFO) |
| áno | nie | `removed` |
| áno | áno, iný typ | `type_changed` |
| áno | áno, iné práva alebo vlastník | `metadata_changed` |
| áno | áno, iný hash | `content_changed` (pri `index.html` `daily_content_changed`) |

4. Každý nález je **incident**: zapíše sa do logu, do prevádzkovej databázy
   a do fronty e-mailov ([runtime.py](../src/fim/runtime.py#L52)).
5. Samostatné vlákno odosiela e-maily z fronty ([alerts.py](../src/fim/alerts.py#L39)).

### 2.4 Denne sa meniaci súbor `index.html`

Toto je hlavný problém zadania a kľúčová myšlienka riešenia.

**Problém:** FIM predpokladá, že sa súbory nemenia, no zadanie vyžaduje,
aby sa `index.html` menil každú polnoc. Ide o nevýhodu FIM uvedenú
v prednáške („problém s dynamicky sa meniacimi súbormi“). Pri uložení hashu
stránky by FIM každú polnoc hlásil falošný incident.

**Riešenie:** pre `index.html` sa v baseline neukladá iba hash, ale
**recept**: šablóna stránky a úplný kalendár menín (tabuľka `page_recipe`).
Pri kontrole monitor postupuje takto:

```
1. Aký je dnes dátum?                          → 24. 11.
2. Ako MÁ stránka vyzerať? (vyrenderuj recept) → "...24. 11. 2026...Emília..."
3. Hash toho, čo MÁ byť                         → 7a1f...
4. Hash toho, čo JE na disku                    → zhoda = v poriadku, rozdiel = incident
```

Kód: [page.py](../src/fim/page.py#L59) (`hashes`) a [monitor.py](../src/fim/monitor.py#L52).

Stránka sa generuje deterministicky: rovnaký deň vždy dá bajt po bajte
rovnakú stránku, a teda rovnaký hash. Zmena dátumu o polnoci preto nie je
incident, akákoľvek iná úprava stránky áno.

**Tolerancia 5 sekúnd:** o 00:00:00 monitor už očakáva nový deň, ale
generátor ešte nemusel stránku prepísať. Prvých 5 s po polnoci je preto
platná aj **presne** včerajšia správna verzia, nie ľubovoľná úprava.
Po 5 s je včerajšia stránka incident.

### 2.5 Generátor stránky a polnoc

Časovač [fim-publish.timer](../deploy/fim-publish.timer):

```ini
OnCalendar=*-*-* 00:00:00 Europe/Bratislava   # každý deň o polnoci
Persistent=true                                # zmeškané spustenie dobehne po zapnutí servera
```

Generátor ([page.py](../src/fim/page.py#L83)):

1. Doplní do šablóny [index.template.html](../data/index.template.html)
   dátum a meniny z [namedays.sk.json](../data/namedays.sk.json)
   (366 dní vrátane 29. 2.; zdroj: Oficiálne kalendárium MK SR 2025,
   pozri [SOURCE.md](../data/SOURCE.md)).
2. **Pred prepisom overí existujúcu stránku:** musí to byť presne vygenerovaná
   stránka z niektorého predošlého dňa a mať očakávané práva. Inak prepis
   **odmietne** ([page.py](../src/fim/page.py#L101)). Polnočný prepis tak
   nemôže zakryť útok.
3. Novú stránku zapíše do dočasného súboru a nahradí ňou pôvodnú jedným
   premenovaním (`os.replace`). Stránka nikdy nie je čiastočne zapísaná.

---

## 3. Prostredie a príprava predvedenia

### 3.1 Prostredie

- **Referenčné prostredie:** Ubuntu 24.04 LTS, Python 3.12, systemd.
- **Overené prostredie:** WSL 2 s Ubuntu 24.04.1 a zapnutým systemd
  (podrobnosti v [VALIDATION.md](VALIDATION.md)).
- **Inštalácia:** `sudo bash deploy/install.sh` a voliteľne
  `sudo bash deploy/install-mailpit.sh`, postup je v [README.md](../README.md).

Po inštalácii:

| Adresa | Obsah |
|---|---|
| http://localhost:8080 | webová stránka (Nginx) |
| http://localhost:8025 | Mailpit, prijaté alerty (iba lokálne) |

### 3.2 Kontrola stavu pred predvedením

V termináli v priečinku projektu:

```bash
systemctl is-active fim-monitor fim-publish.timer nginx fim-mailpit
sudo tail -n 1 /var/log/fim/fim.jsonl
```

**Očakávaný výsledok:** štyrikrát `active`. Posledný záznam logu je
`"event": "scan_completed", "findings": 0`, teda web zodpovedá baseline.

### 3.3 Čisté kópie súborov na obnovu po útokoch

Útoky v kapitole 5 menia web a po každom sa web obnoví z čistej kópie.
Kópia `index.html` musí byť z aktuálneho dňa, preto sa vytvára v deň
predvedenia a iba vtedy, keď je web čistý (krok 3.2):

```bash
sudo install -m 0600 /var/www/fim-demo/index.html /var/lib/fim/clean-index.html
sudo install -m 0600 /var/www/fim-demo/style.css /var/lib/fim/clean-style.css
```

V Mailpite (http://localhost:8025) je vhodné pred predvedením zmazať staré
správy tlačidlom **Delete all**.

Pri WSL musí terminál s Ubuntu zostať otvorený, inak Windows po chvíli WSL
vypne aj so službami.

### 3.4 Odporúčaný priebeh predvedenia

Približne 12 až 15 minút:

| Čas | Časť | Kapitola |
|---|---|---|
| 1 min | Princíp FIM a zadanie | [2.1](#21-princíp-fim), [1](#1-zadanie-a-splnenie-požiadaviek) |
| 2 min | Architektúra | [2.2](#22-architektúra) |
| 4 min | Požiadavky 1 až 6 | [4](#4-predvedenie-požiadaviek-zadania) |
| 4 min | Útoky 1, 3 a 5 | [5](#5-predvedenie-útokov) |
| 1 min | Automatické testy | [6](#6-automatické-testy) |
| 1 min | Obmedzenia | [8](#8-obmedzenia-riešenia) |

**Minimálne predvedenie:** stránka s dátumom a meninami, útok 1 s e-mailom
v Mailpite a vysvetlenie, ako FIM rozlišuje polnočnú zmenu od útoku
([2.4](#24-denne-sa-meniaci-súbor-indexhtml)).

---

## 4. Predvedenie požiadaviek zadania

### Požiadavka 1: Konfiguračný súbor

**Predvedenie:** [deploy/config.toml](../deploy/config.toml) v repozitári,
alebo nainštalovaná verzia:

```bash
sudo cat /etc/fim/config.toml
```

**Očakávaný výsledok:**

| Sekcia | Význam |
|---|---|
| `[paths]` | sledovaný web (`web_root`), umiestnenie baseline, logov a ďalších priečinkov |
| `[security]` | `require_root_owned = true`: konfigurácia, baseline a program musia patriť rootovi |
| `[monitor]` | `scan_interval = 30` (úplná kontrola každých 30 s), limity veľkosti a počtu položiek |
| `[page]` | časové pásmo, tolerancia po polnoci, vlastník a práva stránky |
| `[smtp]` | mailový server, odosielateľ a príjemcovia alertov (`recipients`) |

**Vysvetlenie:** program sa vždy spúšťa s parametrom `--config`.
Konfiguráciu pri načítaní aj validuje: baseline ani log nesmú byť vo
vnútri sledovaného webu, nešifrované SMTP je povolené iba na lokálny server
a cesty musia byť absolútne. Kompetentná osoba je určená položkou
`recipients`. Kód: [config.py](../src/fim/config.py#L89), funkcia `load`.

### Požiadavka 2: Logovací súbor

**Predvedenie:**

```bash
sudo tail -n 5 /var/log/fim/fim.jsonl
```

**Očakávaný výsledok:** záznamy `scan_completed` približne každých 30 s:

```json
{"blocked_paths": [], "event": "scan_completed", "findings": 0, "level": "INFO", "timestamp": "2026-11-23T19:52:24.632302+00:00"}
```

**Typy záznamov:**

| Udalosť | Význam |
|---|---|
| `scan_completed` | dokončená kontrola, `findings` = počet nálezov |
| `incident_detected` | nový incident, obsahuje `expected` a `actual` |
| `incident_resolved` | incident zanikol, stav opäť zodpovedá baseline |
| `alert_delivered` | e-mail doručený |
| `alert_delivery_failed` | e-mail sa nepodarilo doručiť, opakuje sa |

**Vysvetlenie:** formát JSON Lines umožňuje strojové spracovanie, napríklad
v systéme SIEM. Súbor sa rotuje po 5 MiB a uchováva sa päť starších verzií.
Časové značky sú v UTC. Kód: [events.py](../src/fim/events.py#L34).

### Požiadavka 3: Upozornenie kompetentnej osoby

**Predvedenie:**

```bash
sudo -u fim-monitor /opt/fim/venv/bin/python -I -m fim test-alert --config /etc/fim/config.toml
```

**Očakávaný výsledok:** v Mailpite (http://localhost:8025) e-mail
**„FIM test alert“**.

**Vysvetlenie:** alert je e-mail. V ukážke ho prijíma Mailpit, lokálny
testovací server, ktorý e-maily iba zobrazí. V produkcii sa v `[smtp]`
nastaví skutočný server s režimom STARTTLS a heslo sa uloží do samostatného
súboru `/etc/fim/smtp.env`, nie do konfigurácie. E-maily prechádzajú trvalou
frontou v databáze: pri nedostupnom serveri sa alert nestratí a doručenie sa
opakuje po 10, 30 a 60 s, potom každých 5 minút. Rovnaký pretrvávajúci
incident sa posiela iba raz. Kód: [alerts.py](../src/fim/alerts.py#L16),
opakovanie [runtime.py](../src/fim/runtime.py#L97).

### Požiadavka 4: Baseline v databáze

**Predvedenie:** výpis baseline pod účtom monitora, databáza je otvorená
iba na čítanie:

```bash
sudo -u fim-monitor python3 -I - <<'PY'
import sqlite3, json, datetime
db = sqlite3.connect("file:/var/lib/fim/reference/baseline.sqlite?mode=ro", uri=True)
print("Vytvorená:", db.execute("SELECT created_at FROM metadata").fetchone()[0])
for path, data in db.execute("SELECT path, data FROM entries ORDER BY path"):
    print(path, data)
template, calendar = db.execute("SELECT template, calendar FROM page_recipe").fetchone()
calendar = json.loads(calendar)
today = datetime.date.today()
tomorrow = today + datetime.timedelta(days=1)
print("Recept: šablóna", len(template), "znakov, kalendár", len(calendar), "dní")
print("Dnes:", calendar[today.strftime("%m-%d")], "| Zajtra:", calendar[tomorrow.strftime("%m-%d")])
PY
```

Porovnanie hashu z baseline so skutočným súborom:

```bash
sha256sum /var/www/fim-demo/style.css
```

**Očakávaný výsledok:**

| Tabuľka | Obsah |
|---|---|
| `entries` | pre každý súbor a priečinok: `kind`, `mode`, `uid`, `gid`, `size`, `sha256` |
| `page_recipe` | šablóna stránky a kalendár menín (366 dní) |
| `metadata` | čas vytvorenia baseline |

Hash z `sha256sum` sa zhoduje s hodnotou `sha256` pri `style.css`.

**Vysvetlenie:** pre `index.html` je v `entries` hash z dňa vytvorenia
baseline. Monitor ho pre túto stránku nepoužíva, očakávaný hash počíta
z receptu (kapitola 2.4). Baseline patrí rootovi (`0640`, skupina `fim-read`),
monitor aj generátor ju môžu iba čítať. Pri každom načítaní program
kontroluje vlastníctvo súboru a integritu databázy (`PRAGMA quick_check`).
Kód: tabuľky [baseline.py](../src/fim/baseline.py#L108), čítanie
[baseline.py](../src/fim/baseline.py#L46).

### Požiadavka 5: Nasadenie na webovom serveri

**Predvedenie:**

```bash
systemctl status fim-monitor --no-pager
ls -l /var/www/fim-demo
```

**Očakávaný výsledok:**

- `Active: active (running)` a `Status: "Monitoring website integrity"`,
- `index.html` patrí `fim-publisher`, `style.css` patrí `root`, oba skupine `fim-web`.

**Vysvetlenie:** inštalačný skript [install.sh](../deploy/install.sh)
nainštaluje Nginx, vytvorí systémové účty a priečinky s presnými právami,
vytvorí baseline a zaregistruje služby v systemd. Systemd spúšťa monitor
pri štarte systému a po páde ho znova spustí. Nginx
([nginx.conf](../deploy/nginx.conf)) zobrazuje stránku z priečinka, ktorý
FIM stráži. Služba monitora ([fim-monitor.service](../deploy/fim-monitor.service))
má obmedzené práva: zapisovať smie iba do logu a prevádzkovej databázy.

### Požiadavka 6: Stránka s dátumom a meninami

**Predvedenie:**

1. http://localhost:8080,
2. naplánovanie časovača:
   ```bash
   systemctl list-timers fim-publish.timer --no-pager
   ```
3. posledné spustenie generátora:
   ```bash
   sudo journalctl -u fim-publish -n 5 --no-pager
   ```

**Očakávaný výsledok:** stránka „Dnes je DD. MM. RRRR“ a „Dnes má meniny: …“;
najbližšie spustenie časovača o 00:00:00; v žurnáli generátora `page_published`
z poslednej polnoci.

**Vysvetlenie:** stránku prepisuje časovač systemd každú polnoc v časovom
pásme Europe/Bratislava. Meniny pochádzajú z oficiálneho kalendária
Ministerstva kultúry SR uloženého lokálne, nie zo služby na internete. Ak bol
server o polnoci vypnutý, prepis sa vykoná po zapnutí. Spôsob, akým FIM
túto zmenu odlišuje od útoku, popisuje kapitola
[2.4](#24-denne-sa-meniaci-súbor-indexhtml).

---

## 5. Predvedenie útokov

Útoky simulujú útočníka, ktorý ovládol účet `fim-publisher` s právom meniť
web. Výnimkou je útok 3, ktorý vyžaduje silnejšieho útočníka (root). Úplný
zoznam scenárov je v [ATTACKS.md](ATTACKS.md), namerané výsledky
v [VALIDATION.md](VALIDATION.md).

Pred útokmi musia existovať čisté kópie (kapitola [3.3](#33-čisté-kópie-súborov-na-obnovu-po-útokoch)).

### Útok 1: škodlivý skript v stránke

**Predvedenie:**

```bash
sudo -u fim-publisher sh -c 'printf "\n<script>alert(1)</script>\n" >> /var/www/fim-demo/index.html'
```

**Očakávaný výsledok:**

1. Mailpit: **„FIM incident: daily_content_changed“** do 1 až 2 s.
2. http://localhost:8080: zobrazí sa okno „1“, vložený skript sa vykonal.
3. Log obsahuje `expected` (hash, ktorý mal byť) a `actual` (skutočný hash):
   ```bash
   sudo grep incident_detected /var/log/fim/fim.jsonl | tail -n 1
   ```
4. Generátor napadnutú stránku neprepíše:
   ```bash
   sudo systemctl start fim-publish.service
   sudo journalctl -u fim-publish -n 5 --no-pager
   ```
   Spustenie skončí chybou, v žurnáli je `Refusing to overwrite noncanonical index.html`.

**Obnova:**

```bash
sudo install -m 0664 -o fim-publisher -g fim-web /var/lib/fim/clean-index.html /var/www/fim-demo/index.html
sudo tail -n 3 /var/log/fim/fim.jsonl
```

V logu sa objaví `incident_resolved` a `findings: 0`.

**Vysvetlenie:** útok sa podaril a skript sa v prehliadači vykonal. FIM ho
odhalil do jednej až dvoch sekúnd a upozornil správcu. Generátor stránku
neprepísal, aby zostal zachovaný dôkaz. Po obnove z čistej kópie monitor
incident sám uzavrel. Opakované skeny rovnakého stavu nový e-mail
nevytvárajú.

### Útok 3: zmena so zachovanou veľkosťou a časom

**Predvedenie** (ako root, lebo ľubovoľný čas súboru smie nastaviť iba
vlastník súboru alebo root):

```bash
ls -l --full-time /var/www/fim-demo/style.css
sudo python3 - <<'PY'
from pathlib import Path
import os
p = Path('/var/www/fim-demo/style.css')
s = p.stat()
original = p.read_bytes()
assert b'#24352c' in original
p.write_bytes(original.replace(b'#24352c', b'#ffffff', 1))
os.utime(p, ns=(s.st_atime_ns, s.st_mtime_ns))
assert p.stat().st_size == s.st_size
PY
ls -l --full-time /var/www/fim-demo/style.css
```

**Očakávaný výsledok:** oba výpisy `ls` majú rovnakú veľkosť aj čas až na
nanosekundy. Mailpit napriek tomu prijme **„FIM incident: content_changed“**.

**Obnova:**

```bash
sudo install -m 0664 -o root -g fim-web /var/lib/fim/clean-style.css /var/www/fim-demo/style.css
```

**Vysvetlenie:** farba bola nahradená rovnako dlhou hodnotou a čas zmeny
bol vrátený na pôvodný. Nástroj, ktorý sleduje iba veľkosť a dátum zmeny,
by zmenu neodhalil. Hash obsahu podvrhnúť nemožno bez nájdenia kolízie
SHA-256. Preto riešenie dátum zmeny do baseline vôbec neukladá.

### Útok 5: zmena oprávnení

**Predvedenie:**

```bash
sudo -u fim-publisher chmod 0666 /var/www/fim-demo/index.html
```

**Očakávaný výsledok:** e-mail **„FIM incident: metadata_changed“**. V logu
(`sudo grep incident_detected /var/log/fim/fim.jsonl | tail -n 1`) má `mode`
hodnotu 436 (0664) v `expected` a 438 (0666) v `actual`, `sha256` je
rovnaký.

**Obnova:**

```bash
sudo -u fim-publisher chmod 0664 /var/www/fim-demo/index.html
```

**Vysvetlenie:** obsah sa nezmenil, ale stránka sa stala zapisovateľnou pre
všetkých používateľov servera. FIM sleduje okrem obsahu aj práva a
vlastníka. Hodnota `mode` je v logu v desiatkovej sústave.

### Ďalšie scenáre

| Scenár ([ATTACKS.md](ATTACKS.md)) | Príkaz | Výsledok |
|---|---|---|
| 2. Pridaný súbor | `sudo -u fim-publisher sh -c 'printf "<?php echo 1; ?>\n" > /var/www/fim-demo/probe.php'` | `added` |
| 2. Zmazaný súbor | `sudo -u fim-publisher unlink /var/www/fim-demo/style.css` | `removed` |
| 4. Symlink | `sudo -u fim-publisher ln -s /etc/passwd /var/www/fim-demo/link-test` | `unexpected_type`, cieľ odkazu sa nečíta |
| 4. FIFO | `sudo -u fim-publisher mkfifo /var/www/fim-demo/fifo-test` | `unexpected_type`, monitor sa nezablokuje |
| 6. Zmena FIM samotného | `sudo -u fim-publisher touch /etc/fim/config.toml` | `Permission denied` |
| 7. Pád monitora | `sudo systemctl kill --signal=SIGKILL fim-monitor` | systemd službu do 5 s znova spustí |
| 7. Výpadok e-mailu | `sudo systemctl stop fim-mailpit`, útok, `sudo systemctl start fim-mailpit` | `alert_delivery_failed`, e-mail doručený dodatočne |

Obnova po scenároch 2 a 4: odstránenie pridaných objektov príkazom `unlink`
a obnova `style.css` z čistej kópie.

### Riešenie problémov pri predvedení

| Situácia | Postup |
|---|---|
| Neprišiel e-mail | `sudo tail -n 5 /var/log/fim/fim.jsonl`. Ak je v logu `incident_detected`, detekcia fungovala a problém je v doručení (`systemctl is-active fim-mailpit`). |
| Web zostal zmenený | obnova z čistých kópií (kapitola [13](#13-prehľad-príkazov)) a kontrola `findings: 0` v logu |
| Po obnove `index.html` stále trvá incident | čistá kópia je z predošlého dňa; `sudo systemctl start fim-publish.service` ju aktualizuje na dnešný deň |

---

## 6. Automatické testy

Projekt obsahuje **40 automatických testov** (pytest). Všetky prechádzajú,
výsledky sú v [VALIDATION.md](VALIDATION.md).

**Príprava** (jednorazovo, v priečinku projektu):

```bash
python3 -m venv ~/fim-venv
~/fim-venv/bin/pip install --require-hashes -r requirements.txt
~/fim-venv/bin/pip install "pytest>=8,<10" "aiosmtpd>=1.4.6,<2"
```

**Spustenie:**

```bash
PYTHONPATH=src ~/fim-venv/bin/python -m pytest -q
sudo env PYTHONPATH=src ~/fim-venv/bin/python -m pytest -q tests/test_linux_permissions.py tests/test_installed_smoke.py
```

**Očakávaný výsledok:** `37 passed, 3 skipped` a `4 passed`. Tri testy
preskočené v prvom behu vyžadujú root a prebehnú v druhom.

| Súbor | Čo testuje |
|---|---|
| [test_integrity.py](../tests/test_integrity.py) | detekcia: obsah, pridané a zmazané súbory, práva, symlinky, FIFO, limity veľkosti, poškodená baseline, validácia konfigurácie |
| [test_daily.py](../tests/test_daily.py) | polnoc: koniec roka, priestupný deň, zmena letného času, 5 s tolerancia, útok tesne po polnoci, 10-dňový výpadok |
| [test_alerts.py](../tests/test_alerts.py) | e-maily: trvalá fronta, opakovanie, deduplikácia, skutočné odoslanie, STARTTLS pred autentifikáciou |
| [test_daemon_cli.py](../tests/test_daemon_cli.py) | detekcia do 2 s cez udalosti, náhradné skeny, návratové kódy príkazov |
| [test_linux_permissions.py](../tests/test_linux_permissions.py), [test_installed_smoke.py](../tests/test_installed_smoke.py) | oddelenie účtov a chránená inštalácia (vyžadujú root), syntax jednotiek systemd |

Testy bežia v dočasných priečinkoch a nainštalovaného systému sa nedotýkajú.
Pokrývajú aj prípady, ktoré sa ručne predvádzajú ťažko: prechod polnocou pri
zmene letného času alebo súbor, ktorý sa mení počas čítania. Ručné scenáre
overujú reálne nasadenie, automatické testy logiku programu.

---

## 7. Bezpečnostné rozhodnutia

| Rozhodnutie | Dôvod |
|---|---|
| **Dva oddelené účty** (`fim-monitor`, `fim-publisher`) | ovládnutie účtu, ktorý zapisuje web, nedáva kontrolu nad monitorom |
| **Monitor má web aj baseline iba na čítanie** | ani ovládnutý monitor nemôže meniť web ani referenčný stav; systemd mu navyše zakazuje zápis mimo logu a prevádzkovej databázy (`ProtectSystem=strict`, `ReadWritePaths`) |
| **Dve databázy:** referenčná (`baseline.sqlite`, vlastník root) a prevádzková (`runtime.sqlite`) | referenčný stav je oddelený od zapisovateľných údajov |
| **Žiadna automatická obnova** | obnova by odstránila dôkazy, útočník by mohol súbor meniť opakovane a príčina by ostala neodstránená |
| **Generátor neprepíše podozrivú stránku** | polnočná aktualizácia nesmie zakryť útok |
| **`baseline-update` iba výslovne** (`--accept-current`) | program nikdy sám neprevezme neznámy stav ako správny |
| **Symlinky sa nenasledujú** (`O_NOFOLLOW`, `follow_symlinks=False`) | monitor nemožno presmerovať na súbor mimo webu |
| **Špeciálne súbory sa nečítajú, otváranie s `O_NONBLOCK`** | FIFO nemôže zablokovať monitor |
| **Kontrola zmeny počas čítania** | súbor zmenený počas merania sa nahlási, nevyhodnotí sa chybne |
| **Limity:** 64 MiB na súbor, 10 000 položiek | prekročenie je chyba s alertom, nie úspešná kontrola |
| **Kontrola vlastníctva pri štarte** (`trusted_path`) | ak konfigurácia, baseline alebo kód nepatria rootovi, program odmietne bežať |
| **Deduplikácia incidentov** | pretrvávajúci problém vytvorí jeden e-mail, nie e-mail pri každom skene |

Kód: [safefs.py](../src/fim/safefs.py#L122) (symlinky),
[config.py](../src/fim/config.py#L17) (`trusted_path`),
[fim-monitor.service](../deploy/fim-monitor.service) (obmedzenia systemd).

---

## 8. Obmedzenia riešenia

| Obmedzenie | Vysvetlenie |
|---|---|
| **Útočník s právami root** | môže monitor zastaviť alebo prepísať baseline. Platí to pre každý FIM bežiaci na tom istom serveri. Riešením je nezávislé meranie z iného stroja a odosielanie logov mimo server. |
| **Sledovaný je iba priečinok webu** | konfigurácia Nginx a systémové súbory sa nesledujú. Zadanie vyžaduje súbory webu; rozšírenie by vyžadovalo podporu viacerých priečinkov. |
| **Veľmi krátka zmena môže uniknúť** | zmena vrátená v priebehu zlomku sekundy nemusí byť zachytená. |
| **Kontrolujú sa súbory na disku** | nie odpovede HTTP, ktoré dostane návštevník, ani stav pamäte servera. |
| **Úmyselné zastavenie služby** | systemd reštartuje pád, ale na zastavenie služby administrátorom alebo útočníkom s root nikto neupozorní. |
| **Rozsah overenia** | overené vo WSL s lokálnym Mailpitom, nie na verejnom serveri so skutočnou e-mailovou schránkou. |

FIM je detekčné opatrenie. Odhalí zmenu súborov, nezabráni jej a neochráni
pred útočníkom s plnými právami. Preto sa kombinuje s preventívnymi
opatreniami, napríklad s prístupovými právami, ktoré zabránili zmene
konfigurácie a baseline v scenári 6.

---

## 9. Súvislosť s prednáškou

| Prednáška | Realizácia v riešení |
|---|---|
| **Definícia FIM** (slajd 3): overenie aktuálneho stavu voči známemu korektnému stavu | porovnanie s baseline v SQLite |
| **Kedy monitorovať** (slajd 4): neustále, v pravidelných intervaloch, po udalosti, pri incidente | udalosti systému (neustále), sken každých 30 s (pravidelne), kontrola po polnoci (po udalosti), príkaz `fim check` (pri incidente) |
| **Scanner a monitor** (slajd 5) | `fim watch` je **monitor** (priebežne, takmer okamžite, generuje upozornenie); `fim check` je **scanner** (jednorazová kontrola s návratovým kódom 0/1/2) |
| **Čo monitorovať** (slajd 6): servery, webové služby | súbory webovej stránky |
| **Sledované vlastnosti** (slajd 7): počet, umiestnenie, atribúty, obsah | počet a umiestnenie (`added`, `removed`), názov (cesta), veľkosť, práva a vlastník (`metadata_changed`), obsah (SHA-256). Dátum modifikácie sa zámerne nepoužíva, dá sa podvrhnúť (útok 3). |
| **Postup** (slajd 8): aktíva, baseline, odtlačky, monitorovanie, logovanie, výstrahy, reportovanie | `web_root` v konfigurácii, `fim init`, SHA-256, `fim watch`, `fim.jsonl`, e-mail, história incidentov v `runtime.sqlite` |
| **Výhody** (slajd 9): odhalenie súborov na nesprávnom mieste, návrat do baseline | `added` odhalí napríklad zabudnutú zálohu databázy; obnova z čistých kópií a automatické uzavretie incidentu |
| **Nevýhody** (slajd 10): časová náročnosť, dynamické súbory, veľký počet výstrah | limity veľkosti; recept pre `index.html`; deduplikácia incidentov |
| **Vznik baseline** (slajd 12): pri prvom alebo poslednom skenovaní | `fim init` (prvé), `fim baseline-update --accept-current` (schválená zmena) |
| **Odtlačky** (slajd 13): parita, CRC, MD5, SHA-1, SHA-2, SHA-3 | **SHA-256** (rodina SHA-2) |
| **Normy** (slajdy 14 až 16): PCI DSS, NERC CIP, NIST SI-7 a ďalšie | normy vyžadujú detekciu neoprávnených zmien a upozornenie, čo riešenie realizuje |

---

## 10. Otázky a odpovede

**Prečo SHA-256, a nie MD5 alebo CRC?**
CRC nie je kryptografická funkcia, iný obsah s rovnakým CRC sa dá ľahko
vytvoriť. MD5 a SHA-1 majú známe kolízie, preto sa na bezpečnostné účely
neodporúčajú. SHA-256 je súčasný štandard a je dostatočne rýchly.

**Prečo sa do baseline neukladá dátum zmeny (mtime)?**
Dá sa podvrhnúť (útok 3). Hash obsahu podvrhnúť nemožno. Práva, vlastník
a veľkosť sa ukladajú.

**Čo ak útočník zmení baseline?**
Baseline patrí rootovi s právami `0640`, monitor aj generátor ju môžu iba
čítať. Pokus o zápis skončí `Permission denied` (scenár 6). Program pri
každom načítaní overuje, že baseline patrí rootovi a nik iný do nej nemôže
zapisovať.

**Čo ak útočník získa práva root?**
Môže monitor vypnúť aj baseline prepísať. Pred takým útočníkom nechráni
žiadny FIM bežiaci na tom istom serveri; pomohol by nezávislý monitor na
inom stroji.

**Prečo FIM zmenu automaticky nevráti?**
Obnova by zmazala dôkazy, útočník by súbor mohol meniť opakovane a príčina
by ostala neodstránená. Monitor má navyše web iba na čítanie, aby ho
nebolo možné zneužiť na zápis.

**Ako FIM rozlišuje polnočnú zmenu od útoku?**
Z receptu (šablóna a kalendár) vypočíta hash, ktorý má mať stránka pre
dnešný dátum, a porovná ho so skutočným (kapitola [2.4](#24-denne-sa-meniaci-súbor-indexhtml)).

**Prečo tolerancia 5 sekúnd po polnoci?**
Monitor a generátor nebežia v tej istej milisekunde. Počas 5 s je platná aj
presne včerajšia stránka, nie ľubovoľná úprava.

**Čo ak je server o polnoci vypnutý?**
Časovač má `Persistent=true`, prepis sa vykoná po zapnutí. Generátor
aktualizuje aj stránku staršiu o niekoľko dní, ak ide presne o vygenerovanú
stránku z niektorého predošlého dňa.

**Ako rýchlo FIM odhalí zmenu?**
Pri udalosti zo systému zvyčajne do 1 s; v meraní trvalo od zmeny po
doručenie e-mailu 1,045 s. Ak udalosť nepríde, najneskôr pri ďalšom skene
o 30 s.

**Prečo pri pretrvávajúcom útoku nepríde e-mail pri každom skene?**
Každý nález má odtlačok (hash jeho obsahu). Kým je incident s rovnakým
odtlačkom otvorený, nový sa nevytvára ([runtime.py](../src/fim/runtime.py#L52)).

**Čo ak nefunguje mailový server?**
E-mail ostane v trvalej fronte v databáze, prežije aj reštart a odošle sa
neskôr (10 s, 30 s, 60 s, potom každých 5 minút). V logu je
`alert_delivery_failed`.

**Čo ak monitor spadne alebo zamrzne?**
Systemd ho po páde spustí po 5 s znova (`Restart=on-failure`). Ak sa
prestane hlásiť, systemd ho po 60 s reštartuje (`WatchdogSec=60`).

**Ako správca legitímne zmení web?**
Zastaví služby, nasadí overené súbory a spustí
`fim baseline-update --accept-current`, čím vznikne nová baseline (postup
v [README.md](../README.md)). Po útoku sa tento príkaz použiť nesmie,
schválil by zmenený stav.

**Prečo dve databázy?**
Referenčná (baseline) je iba na čítanie a patrí rootovi. Prevádzková
(incidenty a fronta e-mailov) sa neustále mení a patrí monitoru. Pri jednej
databáze by monitor potreboval právo zápisu aj do baseline.

**Prečo Linux?**
Riešenie využíva linuxové práva súborov, systémové účty, systemd a Nginx.
Na Windows beží vo WSL. Referenčné prostredie je Ubuntu 24.04.

**Prečo log vo formáte JSON?**
Každý záznam má rovnakú štruktúru a dá sa strojovo vyhľadávať a spracovať.

**Ako sa mení príjemca alertov?**
V `/etc/fim/config.toml`, sekcia `[smtp]`, položka `recipients`, a potom
`sudo systemctl restart fim-monitor`.

**Čo znamenajú čísla `mode` a `uid` v logu?**
`mode` sú práva v desiatkovej sústave: 420 = `0644`, 436 = `0664`,
438 = `0666`, 511 = `0777` (bežné pri symlinkoch). `uid` je číslo vlastníka
súboru: 0 je root, ostatné čísla zodpovedajú systémovým účtom
(`id fim-publisher`).

---

## 11. Mapa súborov

```
src/fim/
  cli.py        vstupný bod: init / watch / check / publish / baseline-update / test-alert
  config.py     načítanie a validácia config.toml                (požiadavka 1)
  events.py     logovanie do fim.jsonl                           (požiadavka 2)
  alerts.py     odosielanie e-mailov                             (požiadavka 3)
  baseline.py   vytvorenie a čítanie baseline.sqlite             (požiadavka 4)
  safefs.py     bezpečné prechádzanie súborov a SHA-256
  monitor.py    porovnanie stavu s baseline, nálezy
  runtime.py    incidenty, deduplikácia, fronta e-mailov
  daemon.py     slučka "watch": spúšťanie kontrol
  page.py       generovanie index.html, recept, polnoc           (požiadavka 6)

deploy/                                                          (požiadavka 5)
  install.sh            inštalácia na Ubuntu
  install-mailpit.sh    testovací prijímač e-mailov
  config.toml           konfigurácia
  fim-monitor.service   služba monitora
  fim-publish.service   služba generátora
  fim-publish.timer     časovač o polnoci
  nginx.conf            webový server na porte 8080

data/
  index.template.html   šablóna stránky
  namedays.sk.json      kalendár menín (366 dní)
  SOURCE.md             pôvod kalendára

docs/
  DOCUMENTATION.md      tento dokument
  ATTACKS.md            bezpečnostné scenáre
  VALIDATION.md         výsledky overenia

tests/                  40 automatických testov
```

**Nainštalovaný systém:**

| Cesta | Obsah | Vlastník, práva |
|---|---|---|
| `/opt/fim/` | program a Python prostredie | root |
| `/etc/fim/config.toml` | konfigurácia | root:fim-read, `0640` |
| `/var/lib/fim/reference/baseline.sqlite` | baseline | root:fim-read, `0640` |
| `/var/lib/fim/runtime/runtime.sqlite` | incidenty a fronta e-mailov | fim-monitor, `0600` |
| `/var/log/fim/fim.jsonl` | log | fim-monitor |
| `/var/www/fim-demo/` | sledovaný web | root:fim-web, `2775` |

---

## 12. Slovník pojmov

| Pojem | Význam |
|---|---|
| **Baseline** | uložený známy správny stav súborov |
| **Hash (odtlačok)** | krátka hodnota vypočítaná z obsahu; iný obsah dáva iný hash |
| **SHA-256** | hashovacia funkcia z rodiny SHA-2, výsledok má 64 hexadecimálnych znakov |
| **Incident** | zistený rozdiel oproti baseline |
| **Deduplikácia** | pretrvávajúci incident sa nahlási iba raz |
| **Služba (daemon)** | program bežiaci na pozadí, spúšťaný systémom |
| **systemd** | správca služieb v Linuxe; spúšťa ich pri štarte a reštartuje po páde |
| **Časovač (timer)** | jednotka systemd, ktorá spustí službu v stanovený čas |
| **watchdog / inotify** | mechanizmus, ktorým Linux hlási zmeny súborov |
| **Nginx** | webový server |
| **SMTP** | protokol na odosielanie e-mailov |
| **Mailpit** | lokálny testovací mailový server, prijaté e-maily iba zobrazuje |
| **SQLite** | databáza uložená v jednom súbore |
| **Symlink** | symbolický odkaz na iný súbor |
| **FIFO** | pomenovaná rúra; čítanie čaká na zápis |
| **root** | správca systému s neobmedzenými právami |
| **UID / GID** | číselný identifikátor používateľa / skupiny |
| **mode** | práva súboru (čítanie, zápis, spustenie) pre vlastníka, skupinu a ostatných |
| **WSL** | Windows Subsystem for Linux |
| **Atómový zápis** | nahradenie súboru jednou operáciou, súbor nikdy nie je čiastočne zapísaný |

---

## 13. Prehľad príkazov

Príkazy sa spúšťajú v Linuxe (pri WSL: `wsl -d Ubuntu-24.04`).

**Stav:**

```bash
systemctl is-active fim-monitor fim-publish.timer nginx fim-mailpit
systemctl status fim-monitor --no-pager
systemctl list-timers fim-publish.timer --no-pager
```

**Logy:**

```bash
sudo tail -n 5 /var/log/fim/fim.jsonl                         # posledné záznamy FIM
sudo grep incident_detected /var/log/fim/fim.jsonl | tail -n 3 # posledné incidenty
sudo journalctl -u fim-publish -n 5 --no-pager                 # generátor stránky
sudo journalctl -u fim-monitor -n 20 --no-pager                # monitor
```

**História incidentov z databázy:**

```bash
sudo -u fim-monitor python3 -I - <<'PY'
import sqlite3
db = sqlite3.connect("/var/lib/fim/runtime/runtime.sqlite")
for row in db.execute("""SELECT datetime(opened, 'unixepoch', 'localtime'), kind, path,
                         CASE WHEN closed IS NULL THEN 'OTVORENÝ' ELSE 'vyriešený' END
                         FROM incidents ORDER BY opened DESC LIMIT 10"""):
    print(*row)
PY
```

**Ovládanie služieb:**

```bash
sudo systemctl restart fim-monitor        # reštart monitora
sudo systemctl start fim-publish.service  # ručné spustenie generátora
sudo systemctl start fim-mailpit          # spustenie Mailpit
```

**Jednorazová kontrola (scanner):**

```bash
sudo systemctl stop fim-monitor
sudo -u fim-monitor /opt/fim/venv/bin/python -I -m fim check --config /etc/fim/config.toml; echo "kód: $?"
sudo systemctl start fim-monitor
```

Návratový kód: `0` = zhoda, `1` = incident, `2` = chyba. Súčasne smie bežať
iba jeden proces `watch` alebo `check`, preto sa monitor pred kontrolou
zastaví.

**Obnova webu z čistých kópií:**

```bash
sudo install -m 0664 -o fim-publisher -g fim-web /var/lib/fim/clean-index.html /var/www/fim-demo/index.html
sudo install -m 0664 -o root -g fim-web /var/lib/fim/clean-style.css /var/www/fim-demo/style.css
```
