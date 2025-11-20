import getpass
import os
import re
import yaml
from termcolor import colored

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
        "\"exit\" -> Exit SecureDrop\n"
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
        self.password = None
        self.data = {'name': self.name, 'email' : self.email, 'password' : self.password}
        

    
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

        if (isNewUser):
            if (ymlUser):
                self.email = None
        else:
            if (not ymlUser):
                self.email = None
                self.password = None
            else:
                if (self.password == ymlUser.get('password')):
                    self.password = ymlUser.get('password')
                    self.name = ymlUser.get('name')
                else:
                    self.email = None
                    self.password = None

        if (not self.email or not self.password):
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

    while (not _isUserValid):
        
        while (not newUser.email):
            newUser.email = input(colored(f"What is your email?", "yellow"))

            if (not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", newUser.email)):
                print(colored(f"Invalid email.", "red", attrs=["bold"]))
                print(colored(f"Must be in the format: [name]@[website].[domain]", "red"))
                newUser.email = None
        
        while (not newUser.password):
            newUser.password = getpass.getpass(colored(f"What is your new password?", "yellow"), echo_char='*')
            passAuth = getpass.getpass(colored(f"Can you retype your new password?", "yellow"), echo_char='*')

            if (newUser.password == passAuth):
                newUser.password = passAuth
            else:
                print(colored(f"Passwords do not match.", "red", attrs=["bold"]))
                print(colored(f"Please try a different password instead", "red", attrs=["bold"]))
                newUser.password = None
        
        newUser.name = input(colored(f"What is your name?", "yellow"))

        _isUserValid = newUser.verifyUser(True)


    newUser.data = {'name': newUser.name, 'email' : newUser.email, 'password' : newUser.password}

    try:
        if (os.path.getsize("userInfo.txt")):
            currentData = yaml.safe_load(Security.decryptScript()) + "...\n---\n"
    except FileNotFoundError:
        currentData = "---\n"

    currentData = currentData + yaml.safe_dump(newUser.data)

    Security.encryptScript(currentData.encode('utf-8'))

    print(colored(f"Ok {newUser.name}, you are now able to use your account now!", "green"))

    return newUser


def userLogIn():
    """
    Logs in into an existing account for the user
    """

    currentUser = User()
    _isUserValid = False
    _numOfAttempts = 0

    while (not _isUserValid):
        while (not currentUser.email):
            currentUser.email = input(colored(f"Enter Email Address:", "yellow"))

        while ((not currentUser.password) and (_numOfAttempts <= 5)):
            currentUser.password = getpass.getpass(colored(f"Enter Password:", "yellow"), echo_char='*')

        _isUserValid = currentUser.verifyUser(False, attempts=_numOfAttempts)

        if (not _isUserValid):
            if (_numOfAttempts < 5):
                _numOfAttempts = _numOfAttempts + 1
            else:
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
        _regUserPrompt = input(colored(f"Do you want to register a new user (y/n)", "yellow"))

        if (_regUserPrompt == 'y'):
            Security.rsaKeyGen()
            user = userRegister()

        elif (_regUserPrompt == 'n'):
            quit()
        else:
            print(colored(f"Invalid Response.", "red", attrs=["bold"]))
            print(colored(f"Please try again.", "red"))
            _regUserPrompt = ''

    print(f"Hello {user.name}, Welcome to Secure Boot")


if __name__ == '__main__':
    main()