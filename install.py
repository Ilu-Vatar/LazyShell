#!/usr/bin/python
# -*- coding: utf-8 -*-
import os
import sys
import platform

# here it begins
os.system('clear')
print('\n\n')

# ---- RESIDUE ----
try:
    cur = os.getcwd()
    os.chdir('/opt/lazyshell')
    whattodo = input('Looks like LazyShell is already installed. So do what ?\n\n\n[1] Reinstall (troubles... Please do the "uninstall.py" and "install.py")\n[2] Internet-Connection-thing\n[3] Exit\n\n >>> ')
    if whattodo == '1':
        print('uninstalling first')
        os.system('python '+cur+'/uninstall.py')
    elif whattodo == '2':
        os.system('apt update && apt install python3 -y && apt install net-tools -y && apt install nmap -y && apt install python-pip -y && pip install terminaltables && apt install git -y && apt install -f && echo Finished')
        sys.exit()
    elif whattodo == '3':
        sys.exit('Exiting')
    else:
        sys.exit('Please choose 1, 2 or 3')
except FileNotFoundError:
    pass

# ---- INSTALL ----
if os.geteuid() != 0:
    sys.exit("""\033[1;91m\n[!] LazyShell installer must be run as root. \n\033[1;m""")

print(""" \033[1;36m

     ┌═┐ ┌═┐  ┌═┐ ┌═┐ ┌═┐ ┌═┐ ┌═┐ 
   █   < LazyShell  Installer >   █
   └═┘ └═┘  └═┘ └═┘ └═┘ └═┘ └═┘ └═┘
   
\033[1;m""")

def main():
    input("\033[1;34m\n[!!] The installation process is only for Linux environment.\nWindows or Mac computers won't support it. OK ?\033[1;m")
    print('Checking your Operating System ...')
    system0 = platform.system().lower()
    if system0 == 'windows' or system0 == 'darwin':
        sys.exit('Windows or OSX OS detected ... Exiting.')
    qconn = input('Are you connected to the Internet ? [y/n] ')
    # installation
    print("\033[1;34m\n ---- Installing LazySehll ---- \033[1;m")
    os.system("""mkdir /opt/lazyshell && cp lazyshell.py /opt/lazyshell/lazyshell.py && cp banner.py /opt/lazyshell/banner.py && cp -r data /opt/lazyshell/data && cp data/lazy.sh /usr/bin/lazyshell && chmod +x /usr/bin/lazyshell && echo "LazyShell has been successfully installed. Execute 'lazyshell' in your terminal"   """)
    print('Partially installed. You can already use it if you have "terminaltables" module installed')
    if qconn.lower() != 'n':
        os.system('apt update && apt install python3 -y && apt install net-tools -y && apt install nmap -y && apt install python-pip -y && pip install terminaltables && apt install git -y && apt install -f && echo Finished')
    print()

main()











