import os
import re
import yaml
from termcolor import colored
import pwinput

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

RSA_NONCE_SIZE = 16
RSA_TAG_SIZE = 16

"""
Outside class functions:
helpMessage() -> returns the help message

"""
def helpMessage() -> None:
    print(
        "\"add\" -> Add a new contact\n" \
        "\"list\" -> List all online contacts\n" \
        "\"send\" -> Transfer file to contact\n" \
        "\"exit\" -> Exit SecureDrop"
    )

class User():
    """
    The login information of a user
        
    Attributes:
        name (str): The name of the user
        email (str): The email of the user
        password (str): The password of the user
        data (list): The packaged login information (used for yaml export)
    """

    def __init__(self):
        self.name = None
        self.email = None
        self.password_hash = None
        self.salt = None
        self.data = {'name': self.name, 'email' : self.email, 'password_hash' : self.password_hash, 'salt': self.salt}
        

    
    def verifyUser(self, isNewUser, attempts = 0):
        """
        Returns a boolean for whether user is valid or not
        
            isNewUser = A boolean determining whether user is registering a new account (True) or logging in (False)
            attempts = An integer displaying number of login attempts; Used exclusively for userLogIn()
        """
        
        if (os.path.exists("userInfo.txt")):
            loadedData = yaml.safe_load(Security.decryptScript().decode('utf-8'))
            if (isinstance(loadedData, list)):
                ymlFile = loadedData
            elif (isinstance(loadedData, dict)):
                ymlFile = [loadedData]
        else:
            ymlFile = []

        ymlUser = next((n for n in ymlFile if n.get('email') == self.email), None)

        import hashlib
        if (isNewUser):
            if (ymlUser):
                self.email = None
        else:
            if (not ymlUser):
                self.email = None
                self.password_hash = None
            else:
                # Hash the entered password with the stored salt and compare
                salt = ymlUser.get('salt')
                password_hash = ymlUser.get('password_hash')
                if salt and password_hash:
                    test_hash = hashlib.sha256((salt + self.password_hash).encode('utf-8')).hexdigest()
                    if test_hash == password_hash:
                        self.password_hash = password_hash
                        self.name = ymlUser.get('name')
                    else:
                        self.email = None
                        self.password_hash = None
                else:
                    self.email = None
                    self.password_hash = None

        if (not self.email or not self.password_hash):
            if (isNewUser):
                print(colored(f"User already exists in the database.", "red", attrs=["bold"]))
                print(colored(f"Please try again", "red"))
            else:
                if (attempts < 5):
                    print(colored(f"Email and Password Combination Invalid.", "red", attrs=["bold"]))
                    print(colored(f"You have {5 - attempts} attempts left.\nEnter the information again:", "red"))
                else:
                    print(colored(f"You cannot do any more attempts", "red", attrs=["bold"]))

            return False

        return True
        

class Security():

    def rsaKeyGen():
        """
        The private and public key generation
        """

        pubKey = None
        privKey = None
        key = RSA.generate(2048)

        privKey = key.export_key()
        with open("private.pem", "wb") as f:
            f.write(privKey)

        pubKey = key.publickey().export_key()
        with open("public.pub", "wb") as f:
            f.write(pubKey)

    def encryptScript(decoded_text):
        """
        Encrypted the given data into the file using the public key.
        """
        
        with open("public.pub", "rb") as key_file:
            pubKey = RSA.import_key(key_file.read())
        
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipherText, tag = cipher_aes.encrypt_and_digest(decoded_text)

        rsa_cipher = PKCS1_OAEP.new(pubKey)
        encrypted_session_key = rsa_cipher.encrypt(session_key)

        with open("userInfo.txt", 'wb') as output_file:
            output_file.write(encrypted_session_key)
            output_file.write(cipher_aes.nonce)
            output_file.write(tag)
            output_file.write(cipherText)



    def decryptScript():
        """
        Returns the decrypted data using the private key
        """
        
        decoded_text = ""
        
        with open("private.pem", "rb") as key_file:
            privKey = RSA.import_key(key_file.read())
            privKey.size_in_bytes()

        with open("userInfo.txt", 'rb') as input_file:
            encrypted_session_key = input_file.read(privKey.size_in_bytes())
            nonce = input_file.read(RSA_NONCE_SIZE)
            tag = input_file.read(RSA_TAG_SIZE)
            cipherText = input_file.read()

            rsa_cipher = PKCS1_OAEP.new(privKey)
            session_key = rsa_cipher.decrypt(encrypted_session_key)

            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            decoded_text = cipher_aes.decrypt_and_verify(cipherText, tag)

        return decoded_text

def userRegister():
    """
    Creates a new account for the user
    """
        
    newUser = User()
    _isUserValid = False

    import hashlib, base64, secrets
    while (not _isUserValid):
        while (not newUser.email):
            newUser.email = input(colored(f"What is your email? ", "yellow"))
            if (not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", newUser.email)):
                print(colored(f"Invalid email.", "red", attrs=["bold"]))
                print(colored(f"Must be in the format: [name]@[website].[domain]", "red"))
                newUser.email = None
        while (not newUser.password_hash):
            password = pwinput.pwinput(colored(f"What is your new password? ", "yellow"))
            passAuth = pwinput.pwinput(colored(f"Can you retype your new password? ", "yellow"))
            if (password == passAuth):
                # Generate salt and hash
                salt = base64.b64encode(secrets.token_bytes(16)).decode('utf-8')
                password_hash = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
                newUser.salt = salt
                newUser.password_hash = password_hash
            else:
                print(colored(f"Passwords do not match.", "red", attrs=["bold"]))
                print(colored(f"Please try a different password instead", "red", attrs=["bold"]))
                newUser.password_hash = None
        while (not newUser.name):
            name = input(colored(f"What is your name? ", "yellow"))
            # Sanitize name input
            if re.match(r"^[A-Za-z0-9 .'-]+$", name):
                newUser.name = name
            else:
                print(colored(f"Invalid name. Use only letters, numbers, spaces, and .'-", "red"))
                newUser.name = None
        _isUserValid = newUser.verifyUser(True)

    newUser.data = {'name': newUser.name, 'email' : newUser.email, 'password_hash' : newUser.password_hash, 'salt': newUser.salt}

    try:
        if (os.path.getsize("userInfo.txt")):
            currentData = yaml.safe_load(Security.decryptScript()) + "...\n---\n"
    except FileNotFoundError:
        currentData = "---\n"

    currentData = currentData + yaml.safe_dump(newUser.data)

    Security.encryptScript(currentData.encode('utf-8'))

    print(colored(f"Ok {newUser.name}, you are now able to use your account now!", "green"))

    # Remove plaintext password from memory
    password = None
    passAuth = None

    return newUser


def userLogIn():
    """
    Logs in into an existing account for the user
    """

    import hashlib
    currentUser = User()
    _isUserValid = False
    _numOfAttempts = 0
    ymlUser = None

    while (not _isUserValid):
        # Load user info and hash the entered password with the stored salt
        if (os.path.exists("userInfo.txt")):
            loadedData = yaml.safe_load(Security.decryptScript().decode('utf-8'))
            if (isinstance(loadedData, list)):
                ymlFile = loadedData
            elif (isinstance(loadedData, dict)):
                ymlFile = [loadedData]
        else:
            ymlFile = []

        password = None
        while ((not currentUser.email) and (not password) and (_numOfAttempts < 5)):
            currentUser.email = input(colored(f"Enter Email Address: ", "yellow"))
            ymlUser = next((n for n in ymlFile if n.get('email') == currentUser.email), None)

            if not ymlUser:
                currentUser.email = None
            password = pwinput.pwinput(colored(f"Enter Password: ", "yellow"))

            if ymlUser:
                salt = ymlUser.get('salt')
                password_hash = ymlUser.get('password_hash')
                if salt and password_hash:
                    test_hash = hashlib.sha256((salt + password).encode('utf-8')).hexdigest()
                    if test_hash == password_hash:
                        currentUser.password_hash = password_hash
                        currentUser.salt = salt
                        currentUser.name = ymlUser.get('name')
                        _isUserValid = True
                    else:
                        _numOfAttempts += 1
                        if _numOfAttempts >= 5:
                            print(colored("Deactivating Too many login attempts", 'red', attrs=['bold']))
                            quit()
                        print(colored(f"Email and Password Combination Invalid.", "red", attrs=["bold"]))
                        print(colored(f"You have {5 - _numOfAttempts} attempts left, try again.", "red"))
                        password = None
                else:
                    print(colored(f"User record corrupted.", "red", attrs=["bold"]))
                    quit()
            else:
                _numOfAttempts += 1
                password = None
                print(colored(f"Email and Password Combination Invalid.", "red", attrs=["bold"]))
                print(colored(f"You have {5 - _numOfAttempts} attempts left", "red"))
                if (_numOfAttempts >= 5):
                    print(colored("Deactivating Too many login attempts", 'red', attrs=['bold']))
                    quit()

    print(colored(f"Login Complete", "green"))
    return currentUser



def main(args=None):
    _regUserPrompt = ''
    user = User()
    
    if (os.path.exists("userInfo.txt")):

        user = userLogIn()
    else:
        print("No users are registered with this client.")
        _regUserPrompt = input(colored(f"Do you want to register a new user (y/n) ", "yellow"))

        if (_regUserPrompt == 'y'):
            Security.rsaKeyGen()
            user = userRegister()

        elif (_regUserPrompt == 'n'):
            quit()
        else:
            print(colored(f"Invalid Response.", "red", attrs=["bold"]))
            print(colored(f"Please try again.", "red"))
            _regUserPrompt = ''

    print(f"Hello {user.name}, Welcome to SecureDrop")

    # Milestone 3: Secure Contacts management
    from contacts_secure import add_contact, list_contacts
    while True:
        cmd = input(colored("secure_drop> " , "yellow")).strip().lower()
        if not user.password_hash or not user.salt:
            print(colored("Error: User credentials missing. Please log in again.", "red"))
            break
        if cmd == "add":
            contact_email = None
            while not contact_email:
                contact_email = input(colored("Enter contact's email: ", "yellow")).strip()
                if not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", contact_email):
                    print(colored("Invalid email format.", "red"))
                    contact_email = None
                    continue
            try:
                add_contact(user.email, user.password_hash, user.salt, contact_email)
                print(colored(f"Contact {contact_email} added.", "green"))
            except Exception as e:
                print(colored(f"Error: {e}", "red"))
        elif cmd == "list":
            try:
                contacts = list_contacts(user.email, user.password_hash, user.salt)
                if contacts and len(contacts) > 0:
                    print(colored("Your contacts:", "green"))
                    for c in contacts:
                        print(f"- {c}")
                else:
                    print(colored("No contacts found.", "yellow"))
            except Exception as e:
                print(colored(f"Error: {e}", "red"))
        elif cmd == "exit":
            print(colored("Exiting SecureDrop...", "cyan"))
            break
        elif cmd == "help":
            helpMessage()
        elif cmd == "send":
            print("Coming soon!")
        else:
            print(colored("Unknown command.", "red"))


if __name__ == '__main__':
    main()