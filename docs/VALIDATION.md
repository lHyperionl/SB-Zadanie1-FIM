# Výsledky overenia

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

## Čo tieto výsledky nepokrývajú

Kompletný inštalátor s apt, Nginx a zapnutím trvalých systemd služieb nebol
spustený na používateľovom systéme. Treba ho pred odovzdaním overiť v čerstvej
Ubuntu 24.04 VM podľa README. Vyššie uvedený root smoke test overuje chránené
rozloženie a prácu účtov, nenahrádza beh celého servera so systemd sandboxom.

Testy letného času používajú správne časové pásmo a relevantné dátumy;
neposúvajú systémové hodiny a nesimulujú každý možný skok systémového času.
Nejde o dôkaz odolnosti voči root ani o záruku zachytenia každej krátkej zmeny.
