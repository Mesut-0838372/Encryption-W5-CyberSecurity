# AES-256-GCM Encryption Tool

**Naam:** Mesut Özen  
**Vak:** Cyber Security – Week 5  
**Programmeertaal:** Python

## 1. Beschrijving

Deze applicatie is ontwikkeld voor de opdracht Symmetrische Encryptie.
Met de applicatie kan een gebruiker tekst versleutelen en ontsleutelen met een wachtwoord.
De applicatie gebruikt AES-256-GCM voor encryptie en Scrypt voor het genereren van een cryptografische sleutel op basis van een wachtwoord.

De applicate heeft alleen een:
- Command Line Interface (CLI)

## 2. Installatie

### Vereisten

- Python 3.10 of hoger
- pip
- De Python-library `cryptography`

### Installatiestappen

**Stap 1:** Download of clone de GitHub-repository.

**Stap 2:** Open de projectmap in PyCharm of een terminal.

**Stap 3:** Maak eventueel een virtuele omgeving aan:

```bash
python -m venv .venv
```

Activeer deze op Windows:

```powershell
.venv\Scripts\activate
```

**Stap 4:** Installeer de benodigde dependencies:

```bash
python -m pip install -r requirements.txt.txt
```

**Stap 5:** Start de applicatie:

```bash
python main.py
```

## 3. Functionaliteiten

De applicatie biedt de volgende mogelijkheden:

1. Tekst versleutelen met AES-256-GCM.
2. Versleutelde tekst ontsleutelen met het juiste wachtwoord.
3. Foutmeldingen weergeven bij verkeerde wachtwoorden of ongeldige gegevens.

## 4. Hoe werkt de applicatie?

### Encryptie

1. De gebruiker voert een tekst en wachtwoord in.
2. De applicatie genereert een willekeurige salt van 16 bytes.
3. Met Scrypt wordt uit het wachtwoord en de salt een sleutel van 256 bits afgeleid.
4. De applicatie genereert een willekeurige nonce van 12 bytes.
5. AES-256-GCM versleutelt de tekst en genereert een authenticatietag.
6. De versie, salt, nonce, ciphertext en authenticatietag worden gecombineerd.
7. De gegevens worden met Base64 omgezet naar een tekstrepresentatie.

### Decryptie

1. De gebruiker voert de versleutelde tekst en het wachtwoord in.
2. De applicatie decodeert de Base64-gegevens.
3. De salt en nonce worden uit de gegevens gehaald.
4. Met Scrypt wordt opnieuw de sleutel afgeleid.
5. AES-GCM probeert de gegevens te ontsleutelen.
6. De authenticatietag wordt gecontroleerd.
7. Als de controle slaagt, verschijnt de oorspronkelijke tekst.

Bij een verkeerd wachtwoord of gewijzigde versleutelde gegevens mislukt de authenticatiecontrole.

## 5. Keuze voor AES-256-GCM

Voor mijn applicatie heb ik gekozen voor het symmetrische encryptie algoritme AES-256 in GCM modus.

Volgens ENISA wordt voor block ciphers een minimale sleutel lengte van 128 bits geadviseerd.
Daarnaast wordt voor veel toepassingen een blokgrootte van minimaal 128 bits aanbevolen.
In tabel ![tabel, block cipher.png](tabel%2C%20block%20cipher.png)  
wordt AES aangemerkt als geschikt voor zowel bestaande als toekomstige toepassingen.
AES-256 gebruikt een sleutel van 256 bits en een blokgrootte van 128 bits.

Hiermee voldoet het algoritme aan de genoemde aanbevelingen van ENISA.
Ik heb gekozen voor GCM (Galois/Counter Mode), omdat deze modus niet alleen gegevens versleutelt, 
maar ook controleert of de versleutelde gegevens zijn gewijzigd.
Hierdoor biedt mijn applicatie zowel vertrouwelijkheid als integriteitsbescherming.

## 6. Sleutelbeheer

De applicatie gebruikt geen hardcoded cryptografische sleutel.
De sleutel wordt gegenereerd met Scrypt, een Key Derivation Function (KDF).
De volgende instellingen worden gebruikt:

| Parameter | Waarde |
|---|---|
| Algoritme | AES-256-GCM |
| Sleutellengte | 256 bits |
| Salt | 128 bits |
| Nonce | 96 bits |
| Scrypt n | 2^15 |
| Scrypt r | 8 |
| Scrypt p | 1 |

De sleutel wordt uitsluitend tijdens het uitvoeren van de encryptie of decryptie afgeleid en niet permanent opgeslagen.
De salt en nonce worden samen met de versleutelde tekst opgeslagen. Deze waarden hoeven niet geheim te blijven.
Het wachtwoord wordt niet permanent opgeslagen.

### Beveiligingsrisico's

Een zwak wachtwoord kan kwetsbaar zijn voor woordenboekaanvallen.
Scrypt maakt deze aanvallen duurder door extra rekenkracht en geheugen te vereisen.
Wanneer het wachtwoord verloren gaat, kunnen de gegevens niet meer worden ontsleuteld.
Voor uitwisseling met andere gebruikers moet het wachtwoord via een veilig en afzonderlijk communicatiekanaal worden gedeeld.
Bij een groot aantal gebruikers wordt sleutelbeheer ingewikkeld, omdat wachtwoorden veilig moeten worden gedeeld, vervangen en beheerd.

## 7. Kerckhoffs's Principe
In 1883 werd Kerkhoffs zijn cryptografische principes gepubliceerd.
- De beveiliging door een versleutelingssysteem mag niet afhangen van de geheimhouding van het systeem, 
  maar alleen geheimhouding van de sleutel.
- Je moet aannemen dat de vijand je systeem kent.


1. Veiligheid: Het systeem moet wiskundig, of op zijn minst praktisch, niet te ontcijferen zijn zonder de juiste sleutel.
2. Openbaarheid: De beveiliging mag niet afhankelijk zijn van het geheimhouden van het systeem. Zelfs wanneer het systeem in handen van de vijand valt, moet het veilig blijven.
3. Sleutelbeheer: De sleutel moet eenvoudig uitgewisseld en onthouden kunnen worden, zonder schriftelijke aantekeningen. Daarnaast moet de sleutel gewijzigd kunnen worden wanneer dat nodig is.
4. Communicatie: Het systeem moet geschikt zijn voor communicatie via telegrafie.
5. Gebruiksgemak en draagbaarheid: Het systeem moet draagbaar zijn en door één persoon bediend kunnen worden.
6. Eenvoud: Het systeem moet gemakkelijk te gebruiken zijn, zonder ingewikkelde regels of grote mentale inspanning.

## 8. Gebruikte libraries

| Library | Toepassing |
|---|---|
| cryptography | AES-256-GCM en Scrypt |
| os | Genereren van willekeurige bytes |
| base64 | Coderen en decoderen van binaire gegevens |
| binascii | Foutafhandeling bij Base64 |
| getpass | Verborgen wachtwoordinvoer in de CLI |

## 9. Bronnen

European Union Agency for Network and Information Security. (2014). *Algorithms, key size and parameters report – 2014*. https://www.enisa.europa.eu/publications/algorithms-key-size-and-parameters-report-2014

Dworkin, M. (2007). *Recommendation for block cipher modes of operation: Galois/Counter Mode (GCM) and GMAC* (NIST Special Publication 800-38D). National Institute of Standards and Technology. https://doi.org/10.6028/NIST.SP.800-38D

Python Cryptographic Authority. (z.d.). *Authenticated encryption*. https://cryptography.io/en/stable/hazmat/primitives/aead/

Python Cryptographic Authority. (z.d.). *Key derivation functions*. https://cryptography.io/en/stable/hazmat/primitives/key-derivation-functions/

Python Software Foundation. (z.d.). *Python 3 documentation*. https://docs.python.org/3/

Wikipedia contributors. (z.d.). Kerckhoffs's principle. Wikipedia. Geraadpleegd op 9 november 2026, van https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle

