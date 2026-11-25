# FIM — monitorovanie integrity webových súborov

Riešenie zadania zo softvérovej bezpečnosti: **Python + SQLite + Linux**.
Program odhaľuje zmenené, pridané a odstránené súbory, zmeny oprávnení a typov,
zapisuje JSON logy a odosiela e-mailové alerty. Denná stránka `index.html`
sa fyzicky prepisuje podľa času **Europe/Bratislava**.

## Rýchle spustenie bez administrátorských práv

Potrebný je Linux alebo WSL a Python 3.12+. Všetky nasledujúce príkazy sú pre
**Bash na Linuxe**, nie pre PowerShell. Z Windows otvor napríklad:

```powershell
wsl -d Ubuntu-26.04
```

V Linuxe prejdi do projektu. V tomto pracovnom priečinku je to:

```bash
cd /mnt/c/TUKE/5-ZS/SB/Zadanie1-FIM
```

S nástrojom `uv` nainštaluj uzamknuté závislosti a priprav izolovanú ukážku:

```bash
uv sync --frozen --python 3.12
uv run python tools/create_demo.py --directory /tmp/tuke-fim-demo
uv run fim init --config /tmp/tuke-fim-demo/config.toml
uv run fim watch --config /tmp/tuke-fim-demo/config.toml
```

Nástroj `create_demo.py` odmietne existujúci adresár. Ak už taká ukážka existuje,
použi inú cestu alebo vynechaj `--directory`; vypíše novú dočasnú cestu.
Ukážku umiestňuj na linuxový súborový systém, napríklad do `/tmp`, aby fungovali
skutočné POSIX oprávnenia; adresár na `/mnt/c` ich nemusí presadzovať.

Alternatíva bez `uv`: vytvor venv, nainštaluj `requirements.txt` cez
`pip install --require-hashes -r requirements.txt` a projekt cez `pip install --no-deps .`.
Potom používaj `fim` z aktivovaného prostredia namiesto `uv run fim`.

Vo druhom termináli zmeň sledovaný súbor:

```bash
printf '\nbody { background: red; }\n' >> /tmp/tuke-fim-demo/web/style.css
tail -n 5 /tmp/tuke-fim-demo/logs/fim.jsonl
```

Monitor zostáva spustený do `Ctrl+C`. Bez dostupného SMTP sa správa bezpečne
uloží do frontu a doručovanie sa opakuje. Chyba SMTP neblokuje monitorovanie.

Vývojová ukážka má `require_root_owned = false` a všetko vlastní jeden používateľ.
Overuje funkcie, **nepredstavuje bezpečnostné oddelenie účtov**. Na nasadenie
použi postup so systemd nižšie.

## Nasadenie na Linux so systemd

Referenčné prostredie je **Ubuntu Server 24.04 LTS, Python 3.12, x86_64**.
Inštalátor je určený pre čerstvú vyhradenú VM s administrátorským prístupom.
Inštaluje balíky cez apt, vytvorí dva systémové účty, nakonfiguruje Nginx na
porte 8080 a zapne služby. Existujúcu inštaláciu ani webový adresár neprepíše.

```bash
sudo bash deploy/install.sh
sudo bash deploy/install-mailpit.sh
```

- Web: **http://localhost:8080**
- Zachytené e-maily v Mailpit: **http://localhost:8025** (iba loopback)
- Konfigurácia: `/etc/fim/config.toml`
- Referenčná databáza: `/var/lib/fim/reference/baseline.sqlite`
- Incidenty a front správ: `/var/lib/fim/runtime/runtime.sqlite`
- Logy: `/var/log/fim/fim.jsonl`, päť archívov po 5 MiB

Pri vzdialenej VM použi pre Mailpit SSH tunel, napríklad
`ssh -L 8025:127.0.0.1:8025 user@server`. Mailpit je voliteľný testovací prijímač,
neodosiela správy do skutočných schránok. Jeho binárny súbor je stiahnutý
z oficiálneho vydania v1.33.0 a kontrolovaný pripnutým SHA-256.

```bash
sudo systemctl status fim-monitor.service
sudo systemctl list-timers fim-publish.timer
sudo journalctl -u fim-monitor -u fim-publish -n 30
sudo -u fim-monitor /opt/fim/venv/bin/python -I -m fim test-alert --config /etc/fim/config.toml
```

`test-alert` vytvorí správu vo fronte. Ak monitor beží, odošle ju jeho pracovník;
inak príkaz skúsi jedno čakajúce doručenie. Návratový kód 0 znamená prijatie do
frontu, nie potvrdenie doručenia. Doručenie potvrdí `alert_delivered` a správa
v Mailpit alebo skutočnej schránke.

### Skutočný e-mail

V `[smtp]` nastav `host`, `port = 587`, `mode = "starttls"`, `username`, `sender`
a `recipients`. Vytvor `/etc/fim/smtp.env` podľa vzoru
`deploy/smtp.env.example`, s vlastníkom `root:root` a právami `0600`, a vlož heslo.
Reštartuj monitor. Produkčné SMTP vždy overuje TLS certifikát; nepoužíva
automatický návrat k nezašifrovanému spojeniu. Režim `plain` je povolený iba
pre localhost. Heslo nevkladaj do TOML ani repozitára.

## Príkazy a bežná prevádzka

Všetky príkazy vyžadujú `--config /absolútna/cesta/config.toml`.

| Príkaz | Význam |
|---|---|
| `init` | Jednorazový bootstrap stránky a baseline; existujúcu DB odmietne |
| `watch` | Úvodná kontrola, sledovanie udalostí a úplné kontroly každých 30 s |
| `check` | Jedna úplná kontrola a uloženie incidentov/alertov |
| `publish` | Prepis dennej stránky, iba ak je existujúca stránka dôveryhodná |
| `baseline-update --accept-current` | Výslovné schválenie aktuálneho overeného webu |
| `test-alert` | Zaradenie testovacieho e-mailu do frontu |

`check`: **0** = zhoda, **1** = bezpečnostný incident, **2** = chyba kontroly.
Prevádzkové príkazy `watch`, `check`, `test-alert` spúšťaj pod `fim-monitor`,
`publish` pod `fim-publisher`, správu baseline pod root. Súčasne môže bežať
iba jeden proces `watch` alebo `check`.

Pri schválenej aktualizácii statických súborov:

```bash
sudo systemctl stop fim-publish.timer fim-monitor.service
sudo systemctl stop fim-publish.service
# Teraz nasaď a nezávisle over schválené súbory.
sudo /opt/fim/venv/bin/python -I -m fim baseline-update --accept-current --config /etc/fim/config.toml
sudo systemctl start fim-monitor.service fim-publish.timer
```

Tento príkaz prijíma **celý aktuálny web**; nespúšťaj ho ako reakciu na útok.
Pri zmene šablóny alebo kalendára musí administrátor pred schválením nasadiť
aj presný správny `index.html` pre dnešok s očakávanými právami. Aktualizácia
odmietne nesúlad. Program nepreberá neznámy obsah stránky ako referenciu.

## Ako funguje polnoc a baseline

Statické súbory sa kontrolujú SHA-256 a metadátami. V databáze sú aj šablóna a
úplný lokálny kalendár menín; očakávaný obsah stránky vzniká ich deterministickým
renderovaním pre aktuálny dátum. Zdrojové súbory šablóny a kalendára sa pri
bežnej kontrole znovu nepreberajú. Zdroj údajov a reprodukcia importu sú v
[data/SOURCE.md](data/SOURCE.md).

Generátor beží ako samostatný účet. Pred prepisom overí celý existujúci obsah,
dátum aj očakávané oprávnenia. Ak ide o kanonickú staršiu verziu, aktualizuje ju
aj po viacdennom výpadku. Napadnutú, budúcu, chýbajúcu či inak neplatnú stránku
neopraví — odmietne zápis a monitor nahlási problém.

Nová stránka vznikne v súkromnom adresári na rovnakom súborovom systéme a
nahradí pôvodnú atómovým premenovaním. Prvých päť sekúnd po polnoci sa pripúšťa
iba presný správny obsah dnešného alebo včerajšieho dňa, nie ľubovoľná úprava.
Po uplynutí tejto lehoty sa stránka skontroluje aj bez udalosti zo súborového
systému. Časovač má presnosť 1 s; nejde o real-time systém.

## Bezpečnostné hranice

- Webový účet môže meniť web, ale nie FIM, jeho prostredie, konfiguráciu,
  referenciu ani ich nadradené adresáre. Referenčné údaje vlastní root.
- Monitor má web a baseline iba na čítanie. Zapisuje do oddelenej prevádzkovej
  databázy a logov; do webu nezapisuje ani pri útoku.
- Otváranie súborov odmieta symbolické odkazy vo všetkých komponentoch cesty,
  čítanie kontroluje zmeny počas merania. Špeciálne súbory sa nečítajú.
- Limit je 10 000 položiek, 64 MiB na súbor a hĺbka 64 adresárov pod koreňom.
  Počet položiek sa obmedzuje už počas enumerácie, pred vytvorením celého zoznamu.
  Neplatný UTF-8 názov sa zaznamená bezpečne ako chyba kontroly nadradeného adresára.
  Prekročenie limitu je chyba kontroly
  s alertom, nie úspešný výsledok. Pre väčší web uprav konfiguráciu a otestuj výkon.
- Opakované zistenie tej istej pretrvávajúcej odchýlky nevytvára ďalšie e-maily.
  Nový stav znamená nový incident. Front prežije reštart. Po nejasnom výsledku
  SMTP môže prísť duplicitná správa — doručovanie je „aspoň raz“.
- Cieľom je odhaliť pretrvávajúcu zmenu na malej ukážke do 2 s cez udalosti,
  prípadne pri ďalšom 30-sekundovom skene. Krátke zmeny medzi meraniami môžu uniknúť.
- systemd reštartuje pád a watchdog kontroluje odozvu procesu. Nedokáže však
  nezávisle upozorniť na vypnutý server, úmyselne vypnutú službu alebo plne
  kompromitovaný OS. Proti plnému root by bolo potrebné nezávislé meranie mimo VM.
- FIM kontroluje súbory na disku. Nezaručuje nezmenené HTTP odpovede, databázový
  obsah webovej aplikácie ani stav jej pamäte. Bezpečnostné aktualizácie OS,
  Pythonu a knižníc ostávajú úlohou správcu.

## Testy a predvedenie

```bash
uv run pytest -q
```

Root testy oddelených oprávnení a chráneného inštalovaného prostredia:

```bash
sudo .venv/bin/python -m pytest tests/test_linux_permissions.py tests/test_installed_smoke.py -q
```

Voliteľný end-to-end test so skutočným Mailpit binárnym súborom (nič nesťahuje,
vlastné dočasné procesy aj dáta po teste uprace):

```bash
uv run python tools/smoke_mailpit.py /opt/fim/tools/mailpit
```

Testy bežia na Linuxe, používajú dočasné adresáre a vlastný lokálny SMTP prijímač.
Nepotrebujú reálne e-mailové heslo. Testy prepnutia UID sa spúšťajú iba pod root;
nevytvárajú systémové účty. Návod na ručné testy je v
[docs/ATTACKS.md](docs/ATTACKS.md).

Overená vývojová konfigurácia: WSL Ubuntu 26.04 a Python 3.12.14.
Referenčné nasadenie na Ubuntu 24.04 treba pri odovzdaní overiť podľa postupu
vyššie; testy vo WSL nenahrádzajú celé nasadenie na konkrétnom serveri.
Konkrétne výsledky sú zaznamenané v [docs/VALIDATION.md](docs/VALIDATION.md).
