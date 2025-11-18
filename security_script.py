import argparse
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


class CurrentUser():
    def __init__(self):
        self.name = None
        self.email = None
        self.password = None
        self.data = {'name': self.name, 'email' : self.email, 'password' : self.password}
        
    ##--- For Login ---##
    
    def verifyEmail(self):
        try:
            with open('info.yml', 'r') as f:
                ymlFile = list(yaml.safe_load_all(f))
                ymlUser = next((n for n in ymlFile if n.get('email') == self.email), None)
                print(ymlUser)
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

    ##--- For Registeration ---##

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

        

def userLogIn():
    currentUser = CurrentUser()
    ymlUser = None
    _numOfAttempts = 0

    while (not currentUser.email):
        currentUser.email = input(f"{PRINT_YELLOW}Enter Email Address:{PRINT_RESET}")
        ymlUser = currentUser.verifyEmail()
    

    while ((not currentUser.password) and (_numOfAttempts <= 5)):
        currentUser.password = getpass.getpass(f"{PRINT_YELLOW}Enter Password:{PRINT_RESET}")
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
        newUser.password = getpass.getpass(f"{PRINT_YELLOW}What is your new password?{PRINT_RESET}")
        passAuth = getpass.getpass(f"{PRINT_YELLOW}Can you retype your new password?{PRINT_RESET}")
        newUser.validatePassword(passAuth)
    
    newUser.name = input(f"{PRINT_YELLOW}What is your name?{PRINT_RESET}")

    newUser.data = {'name': newUser.name, 'email' : newUser.email, 'password' : newUser.password}
    with open('info.yml', 'a+') as f:
        f.write("...\n---\n")
        yaml.dump(newUser.data, f)

    print(f"{PRINT_GREEN}Ok {newUser.name}, you are now able to use your account now!{PRINT_RESET}")

    return newUser
        


def main(args=None):
    _regUserPrompt = ''
    currentUser = CurrentUser()

    while(not _regUserPrompt):
        _regUserPrompt = input(f"{PRINT_YELLOW}Do you want to register a new user {PRINT_BOLD}(y/n){PRINT_RESET}\n")
        if (_regUserPrompt == 'y'):
            currentUser = userRegister()

        elif (_regUserPrompt == 'n'):
            
            currentUser = userLogIn() 
        else:
            print(f"{PRINT_RED + PRINT_BOLD}Invalid Response.{PRINT_RESET + PRINT_RED} Please try again.{PRINT_RESET}")
            _regUserPrompt = ''


if __name__ == '__main__':
    main()