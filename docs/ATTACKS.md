# Predvedenie bezpečnostných testov

Použi vyhradenú testovaciu VM a inštaláciu podľa README. Mailpit musí byť
spustený, monitor aktívny a web na začiatku zodpovedať baseline.

Pred každým pokusom si odlož čistú verziu mimo sledovaného webu:

```bash
sudo install -m 0600 /var/www/fim-demo/index.html /var/lib/fim/clean-index.html
sudo install -m 0600 /var/www/fim-demo/style.css /var/lib/fim/clean-style.css
```

Na simuláciu zápisu do webu používame existujúci účet `fim-publisher`.
V skutočnom scenári môže ísť o kompromitovaný účet správy obsahu. Tento účet
neovláda monitor, referenciu ani konfiguráciu. Všetky útoky sú obmedzené na
ukážkový adresár `/var/www/fim-demo`.

## 1. Zmena obsahu a vloženie skriptu

```bash
sudo -u fim-publisher sh -c 'printf "\n<script>alert(1)</script>\n" >> /var/www/fim-demo/index.html'
```

Očakávaj `daily_content_changed` v logu a e-mail v Mailpit. Opakované skeny
toho istého stavu nevytvoria ďalšie e-maily. Over, že generátor útok nezmaže:

```bash
sudo systemctl start fim-publish.service
sudo journalctl -u fim-publish -n 5
```

Generátor má skončiť chybou `Refusing to overwrite noncanonical index.html`.
Ručná obnova zo známeho čistého zdroja, nie aktualizácia baseline:

```bash
sudo install -m 0664 -o fim-publisher -g fim-web /var/lib/fim/clean-index.html /var/www/fim-demo/index.html
sudo systemctl start fim-publish.service
```

Ak bola čistá kópia zo skoršieho dňa, generátor ju následne korektne aktualizuje.
Monitor zaznamená vyriešenie incidentu.

## 2. Pridaný alebo odstránený súbor

```bash
sudo -u fim-publisher sh -c 'printf "<?php echo 1; ?>\n" > /var/www/fim-demo/probe.php'
sudo -u fim-publisher unlink /var/www/fim-demo/style.css
```

Očakávaj incidenty `added` a `removed`. Nginx má vykonanie PHP v ukážke
zakázané; detekcia nespočíva v spustení vloženého súboru.

Po zdokumentovaní výsledku odstráň iba testovací súbor a obnov CSS:

```bash
sudo -u fim-publisher unlink /var/www/fim-demo/probe.php
sudo install -m 0664 -o root -g fim-web /var/lib/fim/clean-style.css /var/www/fim-demo/style.css
```

## 3. Rovnaká veľkosť a zachovaný čas

```bash
sudo -u fim-publisher python3 - <<'PY'
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
```

Očakávaj `content_changed` napriek zachovanej veľkosti a mtime.
Obnov CSS príkazom `install` z predošlého scenára.

## 4. Symbolický odkaz alebo FIFO

```bash
sudo -u fim-publisher ln -s /etc/passwd /var/www/fim-demo/link-test
sudo -u fim-publisher mkfifo /var/www/fim-demo/fifo-test
```

Oba objekty sa majú nahlásiť ako `unexpected_type`. Monitor sa nesmie zablokovať
na FIFO a nesmie čítať cieľ odkazu. Po teste:

```bash
sudo -u fim-publisher unlink /var/www/fim-demo/link-test
sudo -u fim-publisher unlink /var/www/fim-demo/fifo-test
```

## 5. Pokus o zmenu referencie alebo programu

```bash
sudo -u fim-publisher touch /etc/fim/config.toml
sudo -u fim-publisher touch /var/lib/fim/reference/baseline.sqlite
sudo -u fim-publisher touch /opt/fim/venv/lib/python3.12/site-packages/fim/config.py
```

Na referenčnom Ubuntu 24.04 sa všetky pokusy musia skončiť `Permission denied`.
Na inom Pythone uprav iba cestu k `site-packages`. Nejde o očakávaný incident
zmeny webu: samotné oprávnenia musia zápisu zabrániť.

## 6. Polnoc, výpadok SMTP a reštart

- Reálnu polnoc over cez `systemctl list-timers fim-publish.timer`. Zmeň sa iba
  dátum a meniny; nevznikne bezpečnostný alert. Na rýchle opakovateľné testy
  použi `uv run pytest tests/test_daily.py -q`; hodiny OS sa nemenia.
- Zastav Mailpit cez `sudo systemctl stop fim-mailpit`, vykonaj nový útok a
  over `alert_delivery_failed`. Po reštarte monitora a Mailpit sa čakajúci
  alert doručí. Opakovanie môže po predchádzajúcich pokusoch trvať až 300 s.
- Pád procesu môžeš otestovať cez `sudo systemctl kill --signal=SIGKILL fim-monitor`.
  systemd má službu znovu spustiť. `systemctl stop` je administrátorský pokyn
  na zastavenie a automatický reštart nevyvoláva.

## Dôkazy pre odovzdanie

Ku každému scenáru zachovaj čas pokusu, príkaz, JSON záznam s `incident_id`
a zodpovedajúci e-mail. Prevádzková DB navyše obsahuje históriu incidentov
a front správ. Referenčná DB sa pri týchto pokusoch nemení.
