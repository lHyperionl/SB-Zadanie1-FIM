# Pôvod kalendára menín

`namedays.sk.json` je lokálny prepis dátumov a mien z Oficiálneho kalendária
Ministerstva kultúry SR, vydanie **2025**, v poradí uvedenom v zdroji.
Nejde o automaticky aktualizovaný internetový kalendár.

- Stránka zdroja: https://www.culture.gov.sk/sk/oficialne-kalendarium
- PDF: https://www.culture.gov.sk/storage/2020/03/Oficialne-kalendarium_2025.pdf
- SHA-256 PDF: `7c4855e5411fb2998043534fb0381678d10c4d5f486bb4a6755091b07142ce57`
- SHA-256 JSON: `2bc934f860ed71c48a5bf24b4da13fa4d0b951605774ad910178e8946be296aa`

Prepis obsahuje 366 kľúčov `MM-DD`, vrátane 29. februára. Pomlčka zo zdroja
je reprezentovaná prázdnym zoznamom. Mená aj ich poradie sa zachovávajú;
novšie doplnenia kalendária sa bez administrátorského schválenia nepreberajú.

Reprodukcia prepisu (Poppler je potrebný iba pri importe):

```bash
pdftotext -layout Oficialne-kalendarium_2025.pdf calendar.txt
python tools/import_calendar.py calendar.txt data/namedays.sk.json
```

PDF a nástroje na jeho čítanie nie sú potrebné na prevádzku FIM.
