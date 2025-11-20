# UML_COMP2300_Final_Project
## Group Members 
Christian Milord, Theodor Farag, 

### Python Libraries
pip install pyyaml<br>
pip install pycryptodome<br>
pip install termcolor<br>
pip install pwinput<br>


### Virtual Environment
- python3 -m venv <Name of the virtual environment>
- source ./venv/bin/activate (to activate the virtual environment)
- deactivate (to leave the venv)

### Instructions

--  security_script.py  --
- On first use, the user will be prompted with a question of registering a new user.
- After the user has the valid set of information, the user is registered within the data.
- Running the script after registration allows the user to log in. If the user fails to log in 5 times, the program ends.

--  clean_script.py  --
- Removes all of the previous RSA keys as well as the user's information, allowing for a fresh install.