#!/usr/bin/python
# -*- coding: utf-8 -*-

import os
import sys

if os.geteuid() != 0:
    sys.exit("""\033[1;91m\n[!] LazyShell installer must be run as root. \n\033[1;m""")

if input('Are you sure you want to UNINSTALL LazyShell (ENTER to continue) ?') == '':
    pass
else:
    sys.exit('Exiting.')

os.system('rm -rf /opt/lazyshell && rm /usr/bin/lazyshell && echo Successfully uninstalled LazyShell. Bye !')
