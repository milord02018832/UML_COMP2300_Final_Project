import argparse
import os
import yaml

PRINT_RESET = "\033[0m"
PRINT_BOLD = "\033[1m"
PRINT_RED = "\033[31m"
PRINT_GREEN = "\033[32m"
PRINT_YELLOW = "\033[33m"


class CurrentUser():
    def __init__(self):
        self.name = None
        self.email = None
        self.password = None
        
    def verifyEmail(self, ymlUser):

        if (ymlUser is None):
            self.email = None
            print(f"{PRINT_RED + PRINT_BOLD}Email does not exist{PRINT_RESET}")
            return None
        
        return ymlUser

    def validatePassword(self, password, attempts):
        if (self.password == password):
            print(f"{PRINT_GREEN}Password is valid {PRINT_RESET}")
            self.password = password
        else:
            if (attempts < 5):
                print(f"{PRINT_RED + PRINT_BOLD}Invalid Password.\n{PRINT_RESET + PRINT_RED}You have {5 - attempts} attempts left.\nEnter the information again:{PRINT_RESET}")
            else:
                print(f"{PRINT_RED + PRINT_BOLD}You cannot do any more attempts{PRINT_RESET}")
            self.password = None

def userLogIn():
    currentUser = CurrentUser()
    ymlUser = None
    _numOfAttempts = 0

    while (not currentUser.email):
        currentUser.email = input(f"{PRINT_YELLOW}Enter Email Address:{PRINT_RESET}")

        try:
            with open('info.yml', 'r') as f:
                ymlFile = list(yaml.safe_load_all(f))
                ymlUser = next((n for n in ymlFile if n.get('email') == currentUser.email), None)
        except FileNotFoundError:
            print(f"{PRINT_RED + PRINT_BOLD}File does not exist{PRINT_RESET}")
            
        ymlUser = currentUser.verifyEmail(ymlUser)
    

    while ((not currentUser.password) and (_numOfAttempts <= 5)):
        currentUser.password = input(f"{PRINT_YELLOW}Enter Password:{PRINT_RESET}")
        currentUser.validatePassword(ymlUser.get('password'), _numOfAttempts)

        if (not currentUser.password):
            _numOfAttempts = _numOfAttempts + 1

    if (currentUser.password):
        print(f"{PRINT_GREEN + PRINT_BOLD}Login Complete{PRINT_RESET}")
        return currentUser
    else:
        return None

def userRegister():
    pass

def main(args=None):
    _regUserPrompt = ''
    currentUser = CurrentUser()

    while(not _regUserPrompt):
        _regUserPrompt = input(f"{PRINT_YELLOW}Do you want to register a new user {PRINT_BOLD}(y/n){PRINT_RESET}\n")
        if (_regUserPrompt == 'n'):
            currentUser = userLogIn()

        elif (_regUserPrompt == 'y'):
            ### Implement statement for creating a new user
            # newUser = currentUser()           [Create a new user object]
            # input("What is your name?: ")     [Asks for new user's email address]
            # Searches within the yml file for the specific address
            ## If <email> exists in the database:
            # print("Email already exists. Unable to make a new profile") and boots back to the prompt
            ## If <email> does not exist in the database:
            # input("What is your name?: ")     [Asks for new user's name]
            # input("What is your password?: ") [Asks for new user's password]
            # 
            pass 
        else:
            print(f"{PRINT_RED + PRINT_BOLD}Invalid Response.{PRINT_RESET + PRINT_RED} Please try again.{PRINT_RESET}")
            _regUserPrompt = ''


if __name__ == '__main__':
    main()