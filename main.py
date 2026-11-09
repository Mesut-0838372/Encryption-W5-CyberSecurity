
import os
import base64
import binascii

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidTag


# Cryptographic settings
SALT_SIZE = 16       # 128 bits
NONCE_SIZE = 12      # 96 bits
KEY_SIZE = 32        # 256 b1its
VERSION = b"\x01"    # Encryption format version

def generate_key(password: str, salt: bytes) -> bytes:
    """ Derive a 256-bit AES key from a password using Scrypt. The key is generated in memory and is not stored.
        Source: https://cryptography.io/en/latest/hazmat/primitives/key-derivation-functions/#scrypt
    """

    if not password:
        raise ValueError("Password cannot be empty.")

    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=2**15, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))


def encrypt(data: str, password: str) -> str:
    """
    Encrypt text using AES-256-GCM.
    Returns a Base64 string containing: version + salt + nonce + ciphertext + authentication tag
    """

    if not isinstance(data, str):
        raise TypeError("Data must be a string.")

    if not data:
        raise ValueError("Text cannot be empty.")

    # Generate a random salt and nonce
    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)

    # Derive AES-256 key from password
    key = generate_key(password, salt)

    # Initialize AES-GCM
    aesgcm = AESGCM(key)

    # Encrypt the text and generate authentication tag
    ciphertext = aesgcm.encrypt(nonce, data.encode("utf-8"), VERSION)

    # Combine all required encryption information
    encrypted_data = VERSION + salt + nonce + ciphertext

    # Convert binary data to printable Base64 text
    return base64.b64encode(encrypted_data).decode("ascii")


def decrypt(data: str, password: str) -> str:
    """
    Decrypt AES-256-GCM encrypted Base64 text.
    Raises ValueError if the password is incorrect
    or the encrypted data has been modified.
    """

    if not isinstance(data, str):
        raise TypeError("Data must be a string.")

    if not data:
        raise ValueError("Encrypted text cannot be empty.")

    try:
        # Convert Base64 back into binary data
        encrypted_data = base64.b64decode(
            data,
            validate=True
        )

    except (binascii.Error, ValueError):
        raise ValueError("Invalid Base64 encrypted text.") from None

    # Validate minimum encrypted data length
    minimum_size = 1 + SALT_SIZE + NONCE_SIZE + 16

    if len(encrypted_data) < minimum_size:
        raise ValueError("Encrypted data is incomplete.")

    # Extract encryption components
    version = encrypted_data[:1]

    if version != VERSION:
        raise ValueError("Unsupported encryption format.")

    salt_start = 1
    salt_end = salt_start + SALT_SIZE
    nonce_end = salt_end + NONCE_SIZE

    salt = encrypted_data[salt_start:salt_end]
    nonce = encrypted_data[salt_end:nonce_end]
    ciphertext = encrypted_data[nonce_end:]

    # Recreate the same key using password and salt
    key = generate_key(password, salt)

    aesgcm = AESGCM(key)

    try:
        # Decrypt and verify authentication tag
        plaintext = aesgcm.decrypt(
            nonce,
            ciphertext,
            VERSION
        )

    except InvalidTag:
        raise ValueError(
            "Decryption failed: wrong password or modified data."
        ) from None

    return plaintext.decode("utf-8")

def main():
    """ Command-line interface for AES-256-GCM.
        Source: https://ascii.co.uk/art/skull
    """


    while True:
        print(r"""
        
             ..ooo@@@XXX%%%xx..
          .oo@@XXX%x%xxx..     ` .
        .o@XX%%xx..               ` .
      o@X%..                  ..ooooooo
    .@X%x.                 ..o@@^^   ^^@@o
  .ooo@@@@@@ooo..      ..o@@^          @X%
  o@@^^^     ^^^@@@ooo.oo@@^             %
 xzI    -*--      ^^^o^^        --*-     %
 @@@o     ooooooo^@@^o^@X^@oooooo     .X%x
I@@@@@@@@@XX%%xx  ( o@o )X%x@ROMBASED@@@X%x   [unknown]
I@@@@XX%%xx  oo@@@@X% @@X%x   ^^^@@@@@@@X%x   Mesut Özen
 @X%xx     o@@@@@@@X% @@XX%%x  )    ^^@X%x
  ^   xx o@@@@@@@@Xx  ^ @XX%%x    xxx
        o@@^^^ooo I^^ I^o ooo   .  x
        oo @^ IX      I   ^X  @^ oo
        IX     U  .        V     IX
         V     .           .     V
         
         
▐▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▀▌
▐       AES-256-GCM ENCRYPTION           ▌
▐      ----------------------------      ▌
▐          1. Encrypt text               ▌
▐          2. Decrypt text               ▌
▐          3. Exit                       ▌
▐          4. View Readme                ▌
▐          5. ?????                      ▌
▐▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▄▌
        """)
        choice = input("\nChoose an option (1-5): ").strip()

        if choice == "1":
            print("\n--- ENCRYPT TEXT ---")

            data = input("Enter text to encrypt: ")
            password = input("Enter password: ")

            try:
                result = encrypt(data, password)
                print("\nEncryption successful!")
                print("\nEncrypted text:")
                print(result)

                print("\nIMPORTANT:")
                print("Save encrypted text, remember PW")

            except (ValueError, TypeError) as error:
                print(f"\nError: {error}")

        elif choice == "2":
            print("\n--- DECRYPT TEXT ---")

            data = input("Enter encrypted text: ").strip()
            password = input("Enter pas4sword: ")

            try:
                result = decrypt(data, password)

                print("\nDecryption successful!")
                print("\nOriginal text:")
                print(result)

            except (ValueError, TypeError) as error:
                print(f"\nError: {error}")

        elif choice == "3":
            print("\nSee you later!")
            break

        elif choice == "4":
            print(r""" 
[ Kerckhoffs's Principe. ]
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
Bron: https://en.wikipedia.org/wiki/Kerckhoffs%27s_principle

[ ONDERBOUWING KEUZE AES-256-GCM]
Voor mijn applicatie heb ik gekozen voor het symmetrische encryptie algoritme AES-256 in GCM modus.

Volgens ENISA wordt voor block ciphers een minimale sleutel lengte van 128 bits geadviseerd.
Daarnaast wordt voor veel toepassingen een blokgrootte van minimaal 128 bits aanbevolen.
In tabel ![tabel, block cipher.png](tabel%2C%20block%20cipher.png)  wordt AES aangemerkt als geschikt voor zowel bestaande als toekomstige toepassingen.
AES-256 gebruikt een sleutel van 256 bits en een blokgrootte van 128 bits.

Hiermee voldoet het algoritme aan de genoemde aanbevelingen van ENISA.
Ik heb gekozen voor GCM (Galois/Counter Mode), omdat deze modus niet alleen gegevens versleutelt, maar ook controleert of de versleutelde gegevens zijn gewijzigd.
Hierdoor biedt mijn applicatie zowel vertrouwelijkheid als integriteitsbescherming.
Block Cipher Bron: https://www.enisa.europa.eu/sites/default/files/publications/Algorithms%2C%20key%20size%20and%20parameters%20report%20%20-%202014.pdf (pagina 22-23)
Modus Bron: https://www.enisa.europa.eu/sites/default/files/publications/Algorithms%2C%20key%20size%20and%20parameters%20report%20%20-%202014.pdf (pagina 46-48)
            """)

        elif choice == "5":
            print(r"""
            
                         ,-------------.
                        ( Why should I? )
                _     O  `-------------'
              ,'-`. o
              :_ _:
   ..._       \ _ /       _.,,
    `-.>.   _,-`-'-._   ,<,-'
      :  \ /    _    `./  ;
       \  `    '_)       /
        \  ,|  (_,  |.  /
         `' |   .   | `'
            :_______:
            |       |
            |       |
            |   .   |
            |   |   |
            |   |   |
            |   |   |
            |   |   |
            |___:___|
            /___/___\ SSt


             I keep six honest serving men
                (They taught me all I knew);
     ____________________________________________________
    |____________________________________________________|
    | __     __   ____   ___ ||  ____    ____     _  __  |
    ||  |__ |--|_| || |_|   |||_|**|*|__|+|+||___| ||  | |
    ||==|^^||--| |=||=| |=*=||| |~~|~|  |=|=|| | |~||==| |
    ||  |##||  | | || | |JRO|||-|  | |==|+|+||-|-|~||__| |
    ||__|__||__|_|_||_|_|___|||_|__|_|__|_|_||_|_|_||__|_|
    ||_______________________||__________________________|
    | _____________________  ||      __   __  _  __    _ |
    ||=|=|=|=|=|=|=|=|=|=|=| __..\/ |  |_|  ||#||==|  / /|
    || | | | | | | | | | | |/\ \  \\|++|=|  || ||==| / / |
    ||_|_|_|_|_|_|_|_|_|_|_/_/\_.___\__|_|__||_||__|/_/__|
    |____________________ /\~()/()~//\ __________________|
    | __   __    _  _     \_  (_ .  _/ _    ___     _____|
    ||~~|_|..|__| || |_ _   \ //\\ /  |=|__|~|~|___| | | |
    ||--|+|^^|==|1||2| | |__/\ __ /\__| |==|x|x|+|+|=|=|=|
    ||__|_|__|__|_||_|_| /  \ \  / /  \_|__|_|_|_|_|_|_|_|
    |_________________ _/    \/\/\/    \_ _______________|
    | _____   _   __  |/      \../      \|  __   __   ___|
    ||_____|_| |_|##|_||   |   \/ __|   ||_|==|_|++|_|-|||
    ||______||=|#|--| |\   \   o    /   /| |  |~|  | | |||
    ||______||_|_|__|_|_\   \  o   /   /_|_|__|_|__|_|_|||
    |_________ __________\___\____/___/___________ ______|
    |__    _  /    ________     ______           /| _ _ _|
    |\ \  |=|/   //    /| //   /  /  / |        / ||%|%|%|
    | \/\ |*/  .//____//.//   /__/__/ (_)      /  ||=|=|=|
  __|  \/\|/   /(____|/ //                    /  /||~|~|~|__
    |___\_/   /________//   ________         /  / ||_|_|_|
    |___ /   (|________/   |\_______\       /  /| |______|
        /                  \|________)     /  / | |





           Their names are What and Why and When
                And How and Where and Who.

    What       Why      When       How      Where      Who

     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
  / | . | \ / | . | \ / | . | \ / | . | \ / | . | \ / | . | \
  \_| . |_/ \_| . |_/ \_| . |_/ \_| . |_/ \_| . |_/ \_| . |_/
   \|___|/   \|___|/   \|___|/   \|___|/   \|___|/   \|___|/
    | | |     | | |     | | |     | | |     | | |     | | |
 __ | | | ___ | | | ___ | | | ___ | | | ___ | | | ___ | | | __
    |_|_|     |_|_|     |_|_|     |_|_|     |_|_|     |_|_|
    (_|_)     (_|_)     (_|_)     (_|_)     (_|_)     (_|_)



        ____
       /    \
    /\/      \    /\             /\
   /          \  /  \         __/  \
  /            \/    \       /      \
         /\     \     \     /        \
        //\\      ____ \   /          \
    /\ ///\\\    / /\_\ \  /\
   //\\  ||      \( oo    //\\
  __||___||____   \_-/ ____||_________
    .          (_)/  \        .
        ~      | / / |    .     I send them over land
     ~     .   |_\_\_|
               () \_)|
  .     .         / /\
                 / /\ \      .   ~
                /_/ /_/
    .    ~      [__)[__)  .


                  '.'.         \  |  |   /
         |    |     '.'.    '.  \ .---. / .'
         |    |       '.'.  ___ .'     '. ___
         |    |         '.'.    :       :
    ~~~~ |    | ~~~~~~~~~ '.'. ~~~~~~~~~~~~~~~~~
     ~~  |    |     ~~~     '.'.     ~~    ~      and sea,
   ~~~   |    | ~~~~~     _.-._ '. ~~~~~  ~~~~~
      ~~ |    |    ~~~   \_____/'.'.  ~~~   ~~
     ____|    |_________ ( o o ) _'.'. _________
     // (|    |) ///////  \_-_/  // '.'.////////
         |    |          /^\_/^\      '.'.
         |    |         /_/: :\_\       '.'.
      ___|____|________/ /|___|\ \________'.'.___
      ________________(_/_______\_)______________
      ___________________________________________
      ___________________________________________
     ___________________________________________
    ____________________________________________
   ____________________________________________
  _______________________________________________
  ~~~~~~~~  ~~~~~~~ ~~~~~~~~~ ~~~~~~~ ~~~~~~ ~~~~
  ~~ ~~~~~ ~~~~~~ ~~~~~~~   ~~~~    ~~~~ ~~~~~ ~~~
  ~~~~    ~~~~   ~~~~~  ~~~~~ ~~~~~ ~~~ ~~~ ~~~~~

 I send them
              _____                        ___
             //\___\                   ___|___|___
             ( - - )                     ( o o )
              \_-_/                       \_-_/
             /*\_/*\                     /\/x\/\
            /_*_ _*_\                   / | . | \
           (_*_(|)_*_)                  \_| . |_/
             |* * *|                     \|___|/
             | * * |                     )UU*UU
             |*_*_*|                     \| | |
              | | |                       | | |
              |_|_|                       |_|_|
             (__|__)                     <__|__>

    ___         _         __       __      __      _
   | __|__ _ __| |_      / _|___   \ \    / /__ __| |_
   | _|/ _` (_-<  _|     > _|_ _|   \ \/\/ / -_|_-<  _|
   |___\__,_/__/\__|     \_____|     \_/\_/\___/__/\__|



  But after they have worked for me,
       I give them all a rest.


             z           z        z     z        z    z
    ()_________z_______z_________z____z_________z______z_________()
    ||   ___  z    ___ z     ___z    z ___     z ___     z ___   ||
    ||  //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\  ||
    || ( - - )   ( - - )   ( - - )   ( - - )   ( - - )   ( - - ) ||
    ||  \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/  ||
    || /\/ \/\   /\/ \/\   /\/ \/\   /\/ \/\   /\/ \/\   /\/ \/\ ||
   /_.~~---~~~-.-~~---~~-.-~~--~~~-..-~---~~-.-~~--~~~-.-~~--~~~-_\
  /                                                                \



        I let them rest from ___
                            / _ \
                            \__ /
                           /___/ till ____
                                     / __/
                                    /__ \
                                   /____/
           For I am busy then,


     ____________________________________________________
    |____________________________________________________|
    | __     __   ____   ___ ||  ____    ____     _  __  |
    ||  |__ |--|_| || |_|   |||_|**|*|__|+|+||___| ||  | |
    ||==|^^||--| |=||=| |=*=||| |~~|~|  |=|=|| | |~||==| |
    ||  |##||  | | || | |JRO|||-|  | |==|+|+||-|-|~||__| |
    ||__|__||__|_|_||_|_|___|||_|__|_|__|_|_||_|_|_||__|_|
    ||_______________________||__________________________|
    | _____________________  ||      __   __  _  __    _ |
    ||=|=|=|=|=|=|=|=|=|=|=| __..\/ |  |_|  ||#||==|  / /|
    || | | | | | | | | | | |/\ \  \\|++|=|  || ||==| / / |
    ||_|_|_|_|_|_|_|_|_|_|_/_/\_.___\__|_|__||_||__|/_/__|
    |____________________ /\~()/()~//\ __________________|
    | __   __    _  _     \_  (_ .  _/ _    ___     _____|
    ||~~|_|..|__| || |_ _   \ //\\ /  |=|__|~|~|___| | | |
    ||--|+|^^|==|1||2| | |__/\ __ /\__| |==|x|x|+|+|=|=|=|
    ||__|_|__|__|_||_|_| /  \ \  / /  \_|__|_|_|_|_|_|_|_|
    |_________________ _/    \/\/\/    \_ _______________|
    | _____   _   __  |/      \../      \|  __   __   ___|
    ||_____|_| |_|##|_||   |   \/ __|   ||_|==|_|++|_|-|||
    ||______||=|#|--| |\   \   o    |   || |  |~|  | | |||
    ||______||_|_|__|_|_\   ________|   /|_|__|_|__|_|_|||
    |_________ __________\_|   ||   |__/__________ ______|
    |__    _  /    ________|   ||   |            /| _ _ _|
    |\ \  |=|/   //    /| /|___||___|  |        / ||%|%|%|
    | \/\ |*/  .//____//.//           (_)      /  ||=|=|=|
  __|  \/\|/   /(____|/ //                    /  /||~|~|~|__
    |___\_/   /________//   ________         /  / ||_|_|_|
    |___ /   (|________/   |\_______\       /  /| |______|
        /                  \|________)     /  / | |


   As well as breakfast, lunch, and tea,
        For they are hungry men:

        ___                ___                 ___
       //\\\              ///\\               //\\\
      ( o o )            ( o o )             ( o o )      ~
       \_-_/           /\_)=o_/               \_-_/   _ _~
      / \|/ \         / // \|/ \             / \|/ \/\(|_|
     / | . | \ )      \___| . \ \  _        / | . |\_/
   __\_\___/_/(___________|___/_/_|~|_______\_\___|_____
      __/   _)           _______  |_|        _______
      \_/  |_|]          \_____/            \ (:)(:)\
                                             \ (:)(:)\
                                              \_______\



         But different folk have different views;
     ____________________________________________________
    |____________________________________________________|
    | __     __   ____   ___ ||  ____    ____     _  __  |
    ||  |__ |--|_| || |_|   |||_|**|*|__|+|+||___| ||  | |
    ||==|^^||--| |=||=| |=*=||| |~~|~|  |=|=|| | |~||==| |
    ||  |##||  | | || | |JRO|||-|  | |==|+|+||-|-|~||__| |
    ||__|__||__|_|_||_|_|___|||_|__|_|__|_|_||_|_|_||__|_|
    ||_______________________||__________________________|
    | _____________________  ||      __   __  _  __    _ |
    ||=|=|=|=|=|=|=|=|=|=|=| __..\/ |  |_|  ||#||==|  / /|
    || | | | | | | | | | | |/\ \  \\|++|=|  || ||==| / / |
    ||_|_|_|_|_|_|_|_|_|_|_/_/\_.___\__|_|__||_||__|/_/__|
    |____________________ /\~()/()~//\ __________________|
    | __   __    _  _     \_  (_ .  _/ _      _     _____|
    ||~~|_|..|__| || |_ _   \ //\\ /  |=|_  /) |___| | | |
    ||--|+|^^|==|1||2| | |__/\ __ /\__| |(\/((\ +|+|=|=|=|
    ||__|_|__|__|_||_|_| /  \ \  / /  \_|_\___/|_|_|_|_|_|
    |_________________ _/    \/\/\/    \_ /   /__________|
    | _____   _   __  |/      \../      \/   /   __   ___|
    ||_____|_| |_|##|_||   |   \/ __\       /=|_|++|_|-|||
    ||______||=|#|--| |\   \   o     \_____/  |~|  | | |||
    ||______||_|_|__|_|_\   \  o     | |_|_|__|_|__|_|_|||
    |_________ __________\___\_______|____________ ______|
    |__    _  /    ________     ______           /| _ _ _|
    |\ \  |=|/   //    /| //   /  /  / |        / ||%|%|%|
    | \/\ |*/  .//____// //   /__/__/ (_)      /  ||=|=|=|
  __|  \/\|/   /(____|/ //                    /  /||~|~|~|__
    |___\_/   /________//   ________         /  / ||_|_|_|
    |___ /   (|________/   |\_______\       /  /| |______|
        /                  \|________)     /  / | |


                I know a person small ---

                  @___
                 / ___)
                / ( o(
               /  \._/
               |  /_\
               (_//_/\
                 \\ \/
                 /~\_)
                /_____\
                 / )\ )
                /_/  \_\
               /__)  /__)

                ______        _ _____
               <  / _ \__ _  (_) / (_)__  ___
               / / // /  ' \/ / / / / _ \/ _ \
    She keeps /_/\___/_/_/_/_/_/_/_/\___/_//_/ serving-men,
         Who get no rest, at all!

     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
  / | . | \ / | . | \ / | . | \ / | . | \ / | . | \ / | . | \
  \_| . |_/ \_| . |_/ \_| . |_/ \_| . |_/ \_| . |_/ \_| . |_/
   \|___|/   \|___|/   \|___|/   \|___|/   \|___|/   \|___|/
    | | |     | | |     | | |     | | |     | | |     | | |
 __ | | | ___ | | | ___ | | | ___ | | | ___ | | | ___ | | | __
    |_|_|     |_|_|     |_|_|     |_|_|     |_|_|     |_|_|
    (_|_)     (_|_)     (_|_)     (_|_)     (_|_)     (_|_)
                            ____@
                           (()))))
                          ))))(((((
                          ((((())))
                          ))))(((((   _
                         /(((())())\ / )
                        /_)))((()()/\ /
                        \ \((())())\_/
                         \ \_____/
                         (_/     \
                          /       \
                         /_________\
                           |  |  |
                           |- | -|
                           |__|__|
                           /__|__\

      She sends 'em abroad on her own affairs,
        from the second she opens her eyes ---



       One million Hows,

     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \


                        two million Wheres,

     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \


      and seven million Whys!
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
       ___       ___       ___       ___       ___
      //\\\     /_/\\     //\_\     //\\\     ///\\
     ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
      \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
     / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \
     ___       ___       ___       ___       ___       ___
    //\\\     /_/\\     //\_\     //\\\     ///\\     //\_\
   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )   ( o o )
    \_-_/     \_-_/     \_-_/     \_-_/     \_-_/     \_-_/
   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \   / \|/ \

                   Oh well,
               Jonathon R. Oglesbee4
               https://ascii.co.uk/art/why
            """)


        else:
            print("\nInvalid option. Choose 1, 2, 3, 4, 5?.")



if __name__ == "__main__":
    main()
