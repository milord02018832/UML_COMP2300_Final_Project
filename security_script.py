import getpass
import os
import re
import yaml

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

PRINT_RESET = "\033[0m"
PRINT_BOLD = "\033[1m"
PRINT_ITALICS = "\033[3m"
PRINT_RED = "\033[31m"
PRINT_GREEN = "\033[32m"
PRINT_YELLOW = "\033[33m"

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

class CurrentUser():
    def __init__(self):
        self.name = None
        self.email = None
        self.password = None
        self.data = {'name': self.name, 'email' : self.email, 'password' : self.password}
        
    ##--- For Login ---##
    
    """
    def verifyEmail(self):
        try:
            with open('info.yml', 'r') as f:
                ymlFile = list(yaml.safe_load_all(f))
                ymlUser = next((n for n in ymlFile if n.get('email') == self.email), None)
        except FileNotFoundError:
            print(f"{PRINT_RED + PRINT_BOLD}File does not exist{PRINT_RESET}")

        if (ymlUser is None):
            self.email = None
            print(f"{PRINT_RED + PRINT_BOLD}Email does not exist{PRINT_RESET}")
            return None
        
        return ymlUser

    def verifyPassword(self, password, attempts):
        if (self.password == password):
            print(f"{PRINT_GREEN}Password is valid {PRINT_RESET}")
            self.password = password
        else:
            if (attempts < 5):
                print(f"{PRINT_RED + PRINT_BOLD}Invalid Password.\n{PRINT_RESET + PRINT_RED}You have {5 - attempts} attempts left.\nEnter the information again:{PRINT_RESET}")
            else:
                print(f"{PRINT_RED + PRINT_BOLD}You cannot do any more attempts{PRINT_RESET}")
            self.password = None
    """

    def verifyUser(self, password, attempts):
        try:
            with open('info.yml', 'r') as f:
                Security.decryptScript()
                ymlFile = list(yaml.safe_load_all(f))
                ymlUser = next((n for n in ymlFile if n.get('email') == self.email), None)
                
        except FileNotFoundError:
            print(f"{PRINT_RED + PRINT_BOLD}File does not exist{PRINT_RESET}")
            return False

        ymlFile = list(yaml.safe_load(Security.decryptScript()))

        if (ymlUser is None):
            self.email = None
        
        if (self.password == password):
            self.password = password
        else:
            self.password = None
    
        if (ymlUser is None or self.password is None):
            if (attempts < 5):
                print(f"""{PRINT_RED + PRINT_BOLD}Email and Password Combination Invalid.\n{PRINT_RESET + PRINT_RED}
                      You have {5 - attempts} attempts left.\nEnter the information again:{PRINT_RESET}""")
            else:
                print(f"{PRINT_RED + PRINT_BOLD}You cannot do any more attempts{PRINT_RESET}")

            return False
        
        return True
            


    ##--- For Registeration ---##
    """
    def validateEmail(self):
        try:
            with open('info.yml', 'r') as f:
                ymlFile = list(yaml.safe_load_all(f))
                ymlUser = next((n for n in ymlFile if n.get('email') == self.email), None)
        except FileNotFoundError:
            print(f"{PRINT_RED + PRINT_BOLD}File does not exist{PRINT_RESET}")

        if (ymlUser):
            print(f"{PRINT_RED + PRINT_BOLD}Email already exists in the database.\n{PRINT_RESET + PRINT_RED}Please try a different email")
            self.email = None

    def validatePassword(self, password):
        if (self.password == password):
            print(f"{PRINT_GREEN}Password is valid {PRINT_RESET}")
            self.password = password
        else:
            print(f"{PRINT_RED + PRINT_BOLD}Passwords do not match.\n{PRINT_RESET + PRINT_RED}Please try a different password instead{PRINT_RESET}")
            self.password = None

    """
    def validateUser(self, password):
        try:
            with open('info.yml', 'r') as f:
                ymlFile = list(yaml.safe_load_all(f))
                ymlUser = next((n for n in ymlFile if n.get('email') == self.email), None)
        except FileNotFoundError:
            print(f"{PRINT_RED + PRINT_BOLD}File does not exist{PRINT_RESET}")

        if (ymlUser):
            print(f"{PRINT_RED + PRINT_BOLD}Email already exists in the database.\n{PRINT_RESET + PRINT_RED}Please try a different email")
            self.email = None
        
        if (self.password == password):
            print(f"{PRINT_GREEN}Password is valid {PRINT_RESET}")
            self.password = password
        else:
            print(f"{PRINT_RED + PRINT_BOLD}Passwords do not match.\n{PRINT_RESET + PRINT_RED}Please try a different password instead{PRINT_RESET}")
            self.password = None

class Security():
    def __init__(self):
        _pub_key = None
        _priv_key = None

    def rsaKeyGen(self):
        from Crypto.PublicKey import RSA

        key = RSA.generate(2048)

        self._priv_key = key.export_key()
        with open("private.pem", "wb") as f:
            f.write(self._priv_key)

        self._pub_key = key.publickey().export_key()
        with open("public.pub", "wb") as f:
            f.write(self._pub_key)

        print("Keys generated and saved to 'private.pem' and 'public.pub'")

    def encryptScript(self, decoded_text, output_fn):

        with open("public.pub", "rb") as key_file:
            self._pub_key = RSA.import_key(key_file.read())
        
        session_key = get_random_bytes(16)
        cipher_aes = AES.new(session_key, AES.MODE_EAX)
        cipherText, tag = cipher_aes.encrypt_and_digest(decoded_text)

        rsa_cipher = PKCS1_OAEP.new(self._pub_key)
        encrypted_session_key = rsa_cipher.encrypt(session_key)

        with open(output_fn, 'wb') as output_file:
            output_file.write(encrypted_session_key)
            output_file.write(cipher_aes.nonce)
            output_file.write(tag)
            output_file.write(cipherText)



    def decryptScript(self):

        decoded_text = ""

        with open("private.pem", "rb") as key_file:
            self._priv_key = RSA.import_key(key_file.read())

        with open("userInfo.txt", 'rb') as input_file:
            encrypted_session_key = input_file.read(self._priv_key.size_in_bytes())
            nonce = input_file.read(RSA_NONCE_SIZE)
            tag = input_file.read(RSA_TAG_SIZE)
            cipherText = input_file.read()

            rsa_cipher = PKCS1_OAEP.new(self._priv_key)
            session_key = rsa_cipher.decrypt(encrypted_session_key)

            cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
            decoded_text = cipher_aes.decrypt_and_verify(cipherText, tag)
            
        return decoded_text


def userLogIn():
    currentUser = CurrentUser()
    ymlUser = None
    _numOfAttempts = 0

    while (not currentUser.email):
        currentUser.email = input(f"{PRINT_YELLOW}Enter Email Address:{PRINT_RESET}")
        ymlUser = currentUser.verifyEmail()
    

    while ((not currentUser.password) and (_numOfAttempts <= 5)):
        currentUser.password = getpass.getpass(f"{PRINT_YELLOW}Enter Password:{PRINT_RESET}", echo_char='*')
        currentUser.verifyPassword(ymlUser.get('password'), _numOfAttempts)

        if (not currentUser.password):
            _numOfAttempts = _numOfAttempts + 1

    if (currentUser.password):
        print(f"{PRINT_GREEN + PRINT_BOLD}Login Complete{PRINT_RESET}")
        return currentUser
    else:
        return None

def userRegister():
        
    newUser = CurrentUser()
    while (not newUser.email):
        newUser.email = input(f"{PRINT_YELLOW}What is your email?{PRINT_RESET}")
        if (not re.match(r"^[\w\.-]+@[\w\.-]+\.\w+$", newUser.email)):
            print(f"{PRINT_RED + PRINT_BOLD}Invalid email.{PRINT_RESET + PRINT_RED}\nMust be in the format: {PRINT_ITALICS}[name]@[website].[domain]{PRINT_RESET}")
            newUser.email = None
        newUser.validateEmail()
    
    while (not newUser.password):
        newUser.password = getpass.getpass(f"{PRINT_YELLOW}What is your new password?{PRINT_RESET}", echo_char='*')
        passAuth = getpass.getpass(f"{PRINT_YELLOW}Can you retype your new password?{PRINT_RESET}", echo_char='*')
        newUser.validatePassword(passAuth)
    
    newUser.name = input(f"{PRINT_YELLOW}What is your name?{PRINT_RESET}")

    newUser.data = {'name': newUser.name, 'email' : newUser.email, 'password' : newUser.password}
    with open('info.yml', 'a+') as f:
        Security.decryptScript()
        f.write("...\n---\n")
        yaml.dump(newUser.data, f)

    print(f"{PRINT_GREEN}Ok {newUser.name}, you are now able to use your account now!{PRINT_RESET}")

    return newUser
        


def main(args=None):
    _regUserPrompt = ''
    currentUser = CurrentUser()
    currentSec = Security()
    
    if (os.path.exists("userInfo.txt")):
        with open("private.pem", 'rb') as key_file:
            currentSec._priv_key = RSA.import_key(key_file.read())
            currentSec._priv_key.size_in_bytes()

        with open("public.pub", 'rb') as key_file:
            currentSec._pub_key = RSA.import_key(key_file.read())

        userLogIn(currentSec)
    else:
        _regUserPrompt = input(f"{PRINT_YELLOW}Do you want to register a new user {PRINT_BOLD}(y/n){PRINT_RESET}\n")

        if (_regUserPrompt == 'y'):
            currentSec.rsaKeyGen()
            f = open("uInfo.txt", "x")
            f.close()
            currentUser = userRegister(currentSec)

        elif (_regUserPrompt == 'n'):
            exit()
        else:
            print(f"{PRINT_RED + PRINT_BOLD}Invalid Response.{PRINT_RESET + PRINT_RED} Please try again.{PRINT_RESET}")
            _regUserPrompt = ''

    
    """
    while(not _regUserPrompt):
        _regUserPrompt = input(f"{PRINT_YELLOW}Do you want to register a new user {PRINT_BOLD}(y/n){PRINT_RESET}\n")
        if (_regUserPrompt == 'y'):
            currentUser = userRegister()

        elif (_regUserPrompt == 'n'):
            
            currentUser = userLogIn() 
        else:
            print(f"{PRINT_RED + PRINT_BOLD}Invalid Response.{PRINT_RESET + PRINT_RED} Please try again.{PRINT_RESET}")
            _regUserPrompt = ''

    """


if __name__ == '__main__':
    main()