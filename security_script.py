import argparse
import os
import yaml

class currentUser():
    def __init__(self):
        self.name = ""
        self.email = ""
        self.password = ""
        
    def validatePassword(self, password):
        if (self.password == password):
            return False
        else:
            return True
            

def main(args=None):
    _registerUser = ""
    _isPasswordValid = False
    _numOfAttempts = 0

    
    print("Do you want to register a new user (y/n)")
    input(_registerUser)
    if (_registerUser == "n"):
        filepath = 'info.yaml'
        newUser = currentUser()
        if os.path.exists(filepath):
            print("Enter Full Name: ")
            input(newUser.name)
            print("Enter Email Address: ")
            input(newUser.email)

            while ((not _isPasswordValid) or (_numOfAttempts < 5)):
                print("Enter Password: ")
                input(newUser.password)

                with open(filepath) as f:
                    dict = yaml.safe_load(f)
                    if (newUser.validatePassword(dict.get('password'))):
                        _isPasswordValid = True
                
                if (_isPasswordValid):
                    print("Password is valid ")
                else:
                    if (_numOfAttempts < 5):
                        print("Invalid Password. Enter the information again: ")
                    else:
                        print("You cannot do any more attempts")
    elif (_registerUser == "y"):
        pass
    else:
        print("Invalid")


if __name__ == '__main__':
    main()