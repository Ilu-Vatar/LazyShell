#!/usr/bin/python
# -*- coding: utf-8 -*-
################################################################################
# Lazyshell
import os, shutil, glob, importlib, time, string, platform, zipfile
import socket, threading, sys, random, traceback, subprocess
from datetime import datetime
from terminaltables import DoubleTable
import banner

################################################################################
# variables
version='0.2.7'
user = open('/opt/lazyshell/data/files/user.txt','r').read()
user = user.replace('\n','')
starting_path = os.getcwd()
system = platform.system().lower()
shell_paths = '/opt/lazyshell/data/shell_paths'
# colors
Green="\033[1;32m"
BrokenYellow = "\033[1;33m"
DarkBlue = "\033[1;34m"
Blue = "\033[1;35m"
LightBlue = "\033[1;36m"
Grey="\033[1;30m"
Reset="\033[0m"
Red="\033[1;31m"
Finish = "\033[1;m"
################################################################################
# checking
if os.geteuid() != 0:
    print('Must be root to run LazyShell')
    quit()
show_check = open('/opt/lazyshell/data/files/show.txt','r').read()
show_check = show_check.replace('\n','')
if show_check == '0':
    show_check = False
else:
    show_check = True
if system == 'darwin':
    print('''
 --- WARNING ---
Switching to linux config because lazyshell has no special config for osx (mac).
Some options may not be available on osx ...
 --- WARNING ---
''')
    system = 'linux'
if show_check: print('<-------------\nChecking Paths:')
try:
    if show_check: print('Home Path ... [OK]')
    os.chdir(starting_path)
    if show_check: print('Lazyshell Shortcut Path ... [OK]')
    os.chdir(shell_paths)
    if show_check: print('\nShortcuts:')
    for sc in os.listdir(shell_paths):
        if system == 'linux' or system == 'darwin':
            try:
                open(os.path.join(shell_paths, sc), 'r')
                if show_check: print(sc.split('.')[0]+' ... [OK]')
            except:
                print(sc.split('.')[0]+' ... [ERROR]')
    if show_check:
        print('------------->\n')
        input('Press ENTER to continue')
except Exception as e:
    print('Error: '+e.__class__.__name__)
    if input('Show the checking of paths to help debugging ? [y/n] ') == 'y': open('/opt/lazyshell/data/files/show.txt','w').write('1')
    input('Press ENTER to quit')
    quit()
# reseting show_check to False
open('/opt/lazyshell/data/files/show.txt','w').write('0')

# THE MOST IMPORTANT THING !!!
if system != 'windows': os.system('clear') # linux and osx
else: os.system('cls') # windows
wonder = banner.header()
info = '''\033[1;30m            {~} A Terminal for Lazy people (by lazy people) {~}
            {~}               Version %s                 {~}
            {~}        Created by: Valar/Ilu-Vatar          {~}
            {~}           My Github: Ilu-Vatar              {~}
            {~}          My Discord: neo#8489               {~}
            {~}         Type "help" to get some             {~}
            {~} ------------------------------------------- {~}
\033[1;m''' % version
print(wonder+info)

################################################################################
# commands
com_list =['about'
           ,'help'
           ,'cd'
           ,'ls'
           ,'cat'
           ,'start'
           ,'clear'
           ,'echo'
           ,'sys'
           ,'options'
           
           ,'newcatego'
           
           ,'copy'
           ,'move'
           ,'mkdir'
           ,'rmdir'
           ,'rmfile'
           ,'ren'
           ,'extract'
           
           ,'newcatego'
           
           ,'ip'
           ,'scan'
           ,'portscan'
           ,'config'
           ,'connect'
           ,'server'
           ,'udpflood'
           
           ,'newcatego'
           
           ,'set'
           ,'update'
           ,'upgrade'
           ,'restart'
           ,'exec'
           
           ,'newcatego'

           ,'version'
           ,'wait'
           ,'py2shell'
           ,'py3shell'
           ,'show_sc'
           ,'load_paths'
           ,'shortcut'
           ,'sysinfo'
           
           ]
hidden =['sudormdir'
         ,'while_true'
         ,'wonderful'
         ]
com_list.extend(['exit','help'])
shell_list = ['terminal', 'lazyshell', 'cmd']


################################################################################
# functions
def password():
    if input('Password : ') == '': return True
    else: return False

def error(errcode, com):
    if len(com)==1: com.extend(com)
    if com == ['exit']: return None
    if errcode == 'FileNotFoundError': print('/!\\ File Not Found : '+com[1])
    elif errcode == 'IndexError':
        if len(com) == 1: print('\\?/ Syntax Error : No Options Given')
        else: print('\\?/ Syntax Error : Missing or Too Much Options')
    elif errcode == 'ArgumentError': print('/!\\ Too much arguments given')
    elif errcode == 'WrongOption': print('\\?/ Not existing option chosen')
    elif errcode == 'ShortcutNotFound': print('/!\\ The Shortcut '+com[0]+' has not been found')
    elif errcode == 'InvalidName': print('/!\\ Invalid Name : '+com[0])
    elif errcode == 'BrokenPipeError': print('/!\\ Broken Pipe ! Lost Connection !')

    else: print('/!\\ unknown error : '+errcode)
    return print('syntax: '+com_syntax(com[0]))

def com_descript(com):
    if com == 'cd': return 'change the current working directory'
    if com == 'ls': return 'show all the files and folders in the working directory'
    if com == 'cat': return 'show all the content of a text-based file'
    if com == 'start': return 'launch external python programs in lazyshell'
    if com == 'clear': return 'clear the lazyshell (could remove shell-data, if there is)'
    if com == 'echo': return 'return the text value'
    if com == 'sys': return 'executes the command in a system subshell (need to run python program in terminal or cmd)'
    if com == 'copy': return 'copy a file/folder to a path'
    if com == 'move': return 'move a file/folder to a path'
    if com == 'mkdir': return 'create a folder'
    if com == 'rmdir': return 'remove a folder'
    if com == 'rmfile': return 'remove a file'
    if com == 'ren': return 'rename a file'
    if com == 'set': return 'set user data'
    if com == 'options': return 'show advanced options about a specific command if there is some'
    if com == 'update': return 'updates all the packages (linux only!)'
    if com == 'upgrade': return 'upgrade your system packages (linux only!)'
    if com == 'restart': return 'restarts the lazyshell'
    if com == 'wait': return 'wait for n seconds'
    if com == 'exec': return 'start a bash or shell script'
    if com == 'shortcut': return 'Add, edit or remove shortcuts in your lazyshell. They act like commands.\n For windows, please pre-write a .bat file. Its path will be asked. (pay attention to what your operating system supports or not)'
    if com == 'sysinfo': return 'Get system information'
    if com == 'load_paths': return 'Load the shortcuts paths'
    if com == 'extract': return 'Extracts files by file-tpe'
    if com == 'show_sc': return 'Show all the shortcuts that are loaded'
    if com == 'connect': return 'Connect as Client or Host to remote Device'
    if com == 'server': return 'Create an TCP or UDP server'
    if com == 'ip': return 'Get your local IP'
    if com == 'while_true': return 'Executes for ever a command'
    if com == 'py2shell': return 'Open a python 2.7.15+ shell'
    if com == 'py3shell': return 'Open a python 3.6.7 shell'
    if com == 'about': return 'Tells you more about the "lazyshell" project'
    if com == 'wonderful': return 'Shows you a wonderful thing'
    if com == 'scan': return 'Scan of your network'
    if com == 'udpflood': return 'Down a target using UDP' # flood: fr. inonder
    if com == 'config': return 'Config your interface and gateway'
    if com == 'portscan': return 'Scans a target for open ports'
    if com == 'version': return 'Gives the LazyShell verion'
    #if com == 'proxy': return 'Create a proxy-server'

    if com == 'exit': return 'exit the lazyshell'
    if com == 'help': return 'show this help window'

def com_syntax(com):
    if com == 'cd': return 'cd [path]'
    if com == 'ls': return 'ls [option] [filter]'
    if com == 'cat': return 'cat [file]'
    if com == 'start': return 'start [program] [option]'
    if com == 'clear': return 'clear'
    if com == 'echo': return 'echo [data] [options...]'
    if com == 'sys': return 'sys [system_command]'
    if com == 'copy': return 'copy [source] [destination]'
    if com == 'move': return 'move [source] [destination]'
    if com == 'mkdir': return 'mkdir [path/folder_name]'
    if com == 'rmdir': return 'rmdir [path]'
    if com == 'rmfile': return 'rmfile [path]'
    if com == 'set': return 'set [option]'
    if com == 'options': return 'options [command]'
    if com == 'update': return 'update'
    if com == 'upgrade': return 'upgrade [option]'
    if com == 'restart': return 'restart'
    if com == 'wait': return 'wait [time-in-seconds]'
    if com == 'exec': return 'exec [file-to-start]'
    if com == 'shortcut': return 'shortcut [name] [terminal/cmd/lazyshell]'
    if com == 'sysinfo': return 'sysinfo'
    if com == 'load_paths': return 'load_paths'
    if com == 'extract': return 'extract [file] [option] [password(optional)]'
    if com == 'show_sc': return 'show_sc'
    if com == 'connect': return 'connect [IP] [port] [protocol] [advanced] [additional]'
    if com == 'server': return 'server [protocol] [bind-IP] [port] [clients] [type(purpose)] [additional]'
    if com == 'ip': return 'ip'
    if com == 'ren': return 'ren [file] [newfile]'
    if com == 'while_true': return 'while_true [command]'
    if com == 'py2shell': return 'py2'
    if com == 'py3shell': return 'py3'
    if com == 'about': return 'about'
    if com == 'wonderful': return 'wonderful'
    if com == 'scan': return 'scan'
    if com == 'udpflood': return 'udpflood [IP] [port] [packet-size(optional)]'
    if com == 'config': return 'config'
    if com == 'portscan': return 'portscan [targetIP] [port-range(optional)]'
    if com == 'verion': return 'version'
    #if com == 'proxy': return 'proxy [localhost] [localport] [remotehost] [remoteport] [receive_first]'

    if com == 'exit': return 'exit'
    if com == 'help': return 'help [option]'

def options(com):
    com_descript(com)
    com_syntax(com)
    if com == 'ls':
        print('-l >> present data in a list form')
        print('*filter >> filter the data')
    elif com == 'set':
        print('user >> change the username')
    elif com == 'upgrade':
        print('-y >> no asking for permission')
    elif com == 'start':
        print('n >> specify your python-version you want to use (1,2,3)')
    elif com == 'shortcut':
        print('name >> only ascii letters and numbers (no extension)')
    elif com == 'connect':
        print('protocol >> TCP, UDP')
        print('adv >>> base (by default), send_spread(only sending data to spreader server),'+
              '\n   recv_spread(only receiving data from spreader server')
        print('advanced auto_ex mode >> give the path (add it after "auto_ex") to a text_file\n'+
              ' and sends all the values in it to specified server.\n'+
              ' As last argument, you can add a sleep time between each request if same as before (in seconds)')
    elif com == 'server':
        print('protocol >> TCP, UDP')
        print('max-clients >> n (e.g. 3)')
        print('Bind-IP is set to default (which is 0.0.0.0) if == "df"')
        print('type >>> com(communication), spreader(spreads received info to every client,'+
              '\n   infospread(acts like a spreder)')
        print('infospread >> you can add a python program/script that will handle the data (please handle empty data)\n'+
              ' as the first argument. All the arguments that follow can be specified after the script_path'+
              '\n If your script gives any output, it will be printed'+
              '\n e.g. server TCP df 5201 infospread /folder/handler.py (here comes the data as argument (str)) arg1 arg2')
    #elif com == 'proxy':
        #print('receive-first >>> True, False')
    elif com == 'portscan':
        print('if no port-range is specified, it is equal to 1024')
    else: print('No more data about this')

def change_dir(com):
    try:
        if len(com) != 2: return error('IndexError', com)
        if com[1] == '..' or com[1] == '../':
            directory = os.getcwd()[:-len(os.getcwd().split('/')[-1])-1]
            os.chdir(directory)
        elif com[1][0] == '/': os.chdir(com[1])
        else: os.chdir(os.path.join(os.getcwd(), com[1]))
    except Exception as e:
        error(e.__class__.__name__, com)

def conf():
    con = ['','y','yes']
    if input('Are you sure [y/n] ? ').lower() in con: return True
    else: return False

def scan_paths():
    global shortcuts
    cur = os.getcwd()
    os.chdir(shell_paths)
    if system == 'linux': shortcuts = [shortcut for shortcut in os.listdir(shell_paths) if shortcut.split('.')[-1] != '.bat']
    if system == 'windows': shortcuts = [shortcut for shortcut in os.listdir(shell_paths) if shortcut.split('.')[-1] == '.bat' or shortcut.split('.')[-1] == '.txt']
    print('Shortcuts ...')
    for sc in os.listdir(shell_paths): print(sc.split('.')[0]+' ... [OK]')
    os.chdir(cur)


def execute(com):
    global shortcuts
##    if len(com) != 1: return error('ArgumentError',list(com[0]))
    for shortcut in shortcuts:
        if com[0] == shortcut:
            com = shortcut
            break
    if type(com) == list: return error('ShortcutNotFound',com)
    if system == 'linux':
        if com.split('.')[-1] == 'txt':
            with open(os.path.join(shell_paths,com),'r') as f:
                f = f.read().split('\n')
                if '' in f: del f[f.index('')]
                for command in f:
                    interpreter(command)
            return None
        elif com.split('.')[-1] != 'bat': # just in case there's an error
            with open(os.path.join(shell_paths,com),'r') as f:
                f = f.read().split('\n')
                for command in f:
                    os.system(command)
            return None
    elif system == 'windows':
        if com.split('.')[-1] == 'txt':
            with open(os.path.join(shell_paths,com),'r') as f:
                f = f.read().split('\n')
                for command in f:
                    interpreter(command)
            return None
        elif com.split('.')[-1] == 'bat': # just in case there's an error
            with open(os.path.join(shell_paths,com),'r') as f:
                f = f.read().split('\n')
                for command in f:
                    os.system(command)
            return None

def extract(com):
    print('not tested yet')
    file=com[1]
    if len(com) == 3: option = com[2]+' '
    else: option=''
    if len(com) == 4: password = com[3]
    else: password=None
    if file.split('.')[-1] == 'zip':
        try:
            if password==None:
                file.extractall()
            else:
                file.extractall(pwd=str.encode(password))
        except Exception as e:
            error(e.__class__.__name__)
        finally:
            return None
    elif file.split('.')[-1] == 'tar' and system == 'linux':
        try:
            os.system('tar '+option+file)
        except Exception as e:
            error(e.__class__.__name__)
        finally:
            return None
    elif file.split('.')[-1] == 'deb' and system == 'linux':
        try:
            os.system('dpkg -i '+option+file)
        except Exception as e:
            error(e.__class__.__name__)
        finally:
            return None
    elif file.split('.')[-1] == 'rar':
        print('rarfile extraction missing')
        return None

def config_network():
    global iface
    iface = open('/opt/lazyshell/data/files/iface.txt').read()
    iface = iface.replace('\n','')
    if iface == '0':
        iface = os.popen("route | awk '/Iface/{getline; print $8}'").read()
        iface = iface.replace('\n','')
    open('/opt/lazyshell/data/files/iface.txt','w').write(iface)
    global gateway
    gateway = open('/opt/lazyshell/data/files/gateway.txt').read()
    gateway = gateway.replace('\n','')
    if gateway == '0':
        gateway = os.popen("ip route show | grep -i 'default via'| awk '{print $3 }'").read()
        gateway = gateway.replace('\n','')
    open('/opt/lazyshell/data/files/gateway.txt','w').write(gateway)
    global n_name, n_mac, n_ip, n_host
    n_name = os.popen('iwgetid -r').read() # Get wireless network name
    n_mac = os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read() # Get network mac
    n_ip = os.popen("hostname -I").read() # Local IP address
    n_host = os.popen("hostname").read() # hostnamedef config_network():

def auto_config_network():
    global iface
    iface = os.popen("route | awk '/Iface/{getline; print $8}'").read()
    iface = iface.replace('\n','')
    open('/opt/lazyshell/data/files/iface.txt','w').write(iface)
    global gateway
    gateway = os.popen("ip route show | grep -i 'default via'| awk '{print $3 }'").read()
    gateway = gateway.replace('\n','')
    open('/opt/lazyshell/data/files/gateway.txt','w').write(gateway)
    global n_name, n_mac, n_ip, n_host
    n_name = os.popen('iwgetid -r').read() # Get wireless network name
    n_mac = os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read() # Get network mac
    n_ip = os.popen("hostname -I").read() # Local IP address
    n_host = os.popen("hostname").read() # hostname

# TCP COM
def com_client_thread(connection, ip, port, max_buffer_size = 5120):
    try:
        is_active = True
        while is_active:
            request = receive_input(connection, max_buffer_size)

            if '--exit--' in request:
                print('[!!] Client is requesting to quit.')
                connection.close()
                print('[*] Connection '+ip+':'+port+'closed')
                is_active = False
            else:
                print('[*] From {ip}, {port}: {r}'.format(ip=ip,port=port,r=request))
                connection.sendall('-'.encode('utf8'))
    except ConnectionResetError:
        print('ConnectionResetError occured. Closed client socket?')
    except KeyboardInterrupt:
        print('Keyboard Interrupt. Stopping Thread')
        threading.Thread.stop()
# universal
def receive_input(connection, max_buffer_size):
    client_input = connection.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        print("The input size is greater than expected {}".format(client_input_size))

    decoded_input = client_input.decode('utf8').rstrip() # le rstrip est la pr les \n je crois

    return decoded_input

# TCP SPREADER
def spread_client_thread(connection, ip, port, max_buffer_size = 5120):
    global client_list
    is_active = True
    while is_active:
        request = receive_input(connection, max_buffer_size)

        if '--exit--' in request:
            print('[!!] Client is requesting to quit.')
            connection.close()
            print('[*] Connection '+ip+':'+port+'closed')
            is_active = False
        elif request != '':
            print('[R] From {ip}, {port}: {r}'.format(ip=ip,port=port,r=request))
            for client in client_list:
                print('[S] Sending to client '+str(client_list.index(client)))
                connection.sendall(request.encode('utf8'))
        else:
            pass

def infospread_client_thread(connection, ip, port, script, args, max_buffer_size = 5120):
    global client_list, infospread_data
    is_active = True
    while is_active:
        request = infospread_receive_input(connection, max_buffer_size)
        infospread_data = request

        # Script output
        if system == 'linux': output = os.popen('python3 {s} "{data}" {a}'.format(s=script,data=infospread_data,a=args)).read()
        if system == 'windows': output = os.popen('py {s} "{data}" {a}'.format(s=script,data=infospread_data,a=args)).read()
        if output != '': print('Output of Script: '+output)

        # Closing Client-Socket
        if '--exit--' in request:
            print('[!!] Client is requesting to quit.')
            connection.close()
            print('[*] Connection '+ip+':'+port+'closed')
            is_active = False

        # Spreading data
        elif request != '':
            print('[*] Got data from {ip}, {port} of size {size}'.format(ip=ip,port=port,size=sys.getsizeof(request)))
            for client in client_list:
                print('Sending data to client number '+str(client_list.index(client)))
                client.sendall(request.encode('utf8'))
            print('[*] Spread finished')
        else:
            pass

def infospread_receive_input(connection, max_buffer_size):
    global infospread_data
    client_input = connection.recv(max_buffer_size)
    client_input_size = sys.getsizeof(client_input)

    if client_input_size > max_buffer_size:
        print("The input size is greater than expected {}".format(client_input_size))

    decoded_input = client_input.decode('utf8').rstrip() # le rstrip est la pr les \n je crois

    return decoded_input




################################################################################
# var_setup
if system == 'linux': shortcuts = [shortcut for shortcut in os.listdir(shell_paths) if shortcut.split('.')[-1] != '.bat']
if system == 'windows': shortcuts = [shortcut for shortcut in os.listdir(shell_paths) if shortcut.split('.')[-1] == '.bat' or shortcut.split('.')[-1] == '.txt']
os.chdir(starting_path)
# config network
config_network()
# categories
com_list_copy = com_list[:]
basics = com_list_copy[:com_list_copy.index('newcatego')]
del com_list_copy[:com_list_copy.index('newcatego')+1]
file_managing = com_list_copy[:com_list_copy.index('newcatego')]
del com_list_copy[:com_list_copy.index('newcatego')+1]
network_coms = com_list_copy[:com_list_copy.index('newcatego')]
del com_list_copy[:com_list_copy.index('newcatego')+1]
system_coms = com_list_copy[:com_list_copy.index('newcatego')]
del com_list_copy[:com_list_copy.index('newcatego')+1]
other_commands = com_list_copy[:]
del com_list_copy
# category dictionnary
catego_dict = {'basics': basics,
                      'file-managing': file_managing,
                      'network': network_coms,
                      'system': system_coms,
                      'other': other_commands}
# purging the commands_list from 'newcatego'
while 'newcatego' in com_list: del com_list[com_list.index('newcatego')]
################################################################################
# interpreter
def interpreter(com): # faut encore faire le nombre d'args par commande, sinn error
    global version, user, lvl, shortcuts, shell_list, shell_paths, client_list, infospread_data
    if com=='exit': quit()
    if com=='': return None
    if ' & ' in com and not '&&' in com:
        for c in com.split(' & '):
            interpreter(c)
        return True
    if '\\ ' in com:
        com2=com.split()
        com=['']
        for b in com2:
            if b[-1] == '\\':
                com += [b[:-1]+' '+com2[com2.index(b)+1]]
            else:
                com += [b]
        del com[0]
        del com[-1]
    else: com=com.split()
    try:
        # handling-of-shortcuts
        for sc in shortcuts:
            if com[0] == sc.split('.')[0]:
                if len(com) > 1: sc = [sc].extend(com[1:])
                elif len(com) == 1: sc = [sc]
                print('executing '+com[0]+' ...')
                return execute(sc)
        # commands
        if com[0] not in com_list and com[0] not in hidden: return print('command "'+com[0]+'" not found')
        elif len(com) > 1:
            if com[1] == 'help':
                if len(com) == 2:
                    return print(com[0]+' - '+com_descript(com[0]))
                elif len(com) == 3:
                    return print(com[0]+' - '+com_syntax(com[0]))
                else: return error('IndexError', com)
            else: pass
        if com[0] == 'options':
            return options(com[1])
        elif com[0] == 'sys':
            s=''
            for a in com[1:]: s+=a+' '
            return print(os.system(s))
        elif com[0] == 'help':
            if len(com) == 1:
                table_data = [
                    ["\n\n\nCOMMAND\nCATEGORIES\n", '''
BASICS

FILE-MANAGING

NETWORK

SYSTEM

OTHER\n''']]
                table = DoubleTable(table_data)
                print('\033[1;36m'+table.table+Finish)
                print(Green+'[+] Type "help" + \'category\' to get the commands from the specified category\n'+Finish)
            elif com[1].lower() in catego_dict and len(com) == 2:
                s=''
                for command in catego_dict[com[1].lower()]:
                    s+='\n\n'+command
                table_data = [['\n\n{}\n'.format(com[1].upper()),s+'\n']]
                table = DoubleTable(table_data)
                print('\n'+BrokenYellow+table.table+Finish)
                print(Green+'[+] Type "help" + \'command\' to get the commands from the specified category\n'+Finish)
            elif com[1] == '--syntax':
                print('All Avalaible Commands (syntax) :')
                for command in com_list:
                    print(command+' - '+com_syntax(command))
                print('To get usage, type "help" or "[command] help"')
            elif len(com) == 2 and com[1] in com_list:
                print(com[1]+' - '+com_descript(com[1]))
                print('syntax: - '+com_syntax(com[1]))
            elif com[1] == 'all':
                print('THIS IS DEPRECATE. Please use the help by category help command')
                print('All Avalaible Commands (use) :')
                for command in com_list:
                    print(command+' - '+com_descript(command))
                print('To get the syntax, type "help --syntax" or "[command] help --syntax')
                print('Use "&" to separate your commands if written in one line (isnt fixed for windows, so "&" will work for lazyshell and not sub-cmd')
                print('Use "options [command] to get the available options for a specified command')
            else:
                raise IndexError

        # write from here new commands
        elif com[0] == 'version':
            if len(com) == 1: return print('Version: '+version)
            else: return error('ArgumentError',com)
        elif com[0] == 'wonderful':
            print(banner.header())
        elif com[0] == 'about':
            print(
                '''
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
   ----------------------------
  {This Shell is the LazyShell!}
   ----------------------------

LazyShell is a project which started in October 2018
It's creator is Valar ( me ;-} )

LazyShell has been built to work in Linux environment,
but can also be used in Windows or OSX.
It has completely benn written in python (its first name was "pyshell")
and is open-source.

The LazyShell presents a lot more simplified commands,
although those from terminal/cmd still are available (see "sys" command).
You can add Shortcuts to it. They are added to your available commands.

I hope you enjoy it
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
''')
        elif com[0] == 'py2shell' and system == 'linux': return os.system('cd ~ && pyshell')
        elif com[0] == 'py3shell' and system == 'linux': return os.system('cd ~ && idle')
        elif com[0] == 'while_true':
            s=''
            for c in com[1:]: s+=c+' '
            input('This is dangerous! Only way to get out of it is to close program!')
            while True:
                interpreter(s)
                #if input('exit?') == 'exit': sys.exit()
        elif com[0] == 'ren':
            os.rename(com[1], com[2])
        # network
        elif com[0] == 'portscan':
            targetIP = com[1]
            try:
                port_range = int(com[2])
            except IndexError:
                port_range = 1024
                # Print that gonna scan ... blablabla
            print('-'*60,'\nScanning for {}'.format(targetIP),'\n'+'-'*60)
            # Set time value
            t1 = datetime.now()
            try:
                for port in range(1,port_range+1): # from port 1 to 1024
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    result = sock.connect_ex((targetIP, port))
                    if result == 0:
                        print('Port {}: Open'.format(port))
                    sock.close()
            except KeyboardInterrupt:
                prit('Stopping ...')
                sock.close()
                return None
            except socket.gaierror:
                print('Hostname could not be resolved. Exiting')
                sys.exit()
            except socket.error:
                print('Couldn\'t connect to server')
                return None
            # Return the time
            t2 = datetime.now()
            print('Scanning completed in: {}'.format(t2-t1))
            return None
        elif com[0] == 'udpflood':
            if len(com) == 3: size = 1024
            elif len(com) == 4: size = int(com[3])
            else: raise IndexError
            sock=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            bytes=random._urandom(size) # normally only 1024
            ip=com[1]
            port=int(com[2])
            sent=1
            while True:
                sock.sendto(bytes,(ip,port))
                if sent % 100 == 0: print('Sent %s amount of packets to %s at port %s' % (sent,ip,port))
                sent += 1
        elif com[0] == 'config':
            wtd = input('Configuration of your Network\n[1] manually\n[2] automatic\n>>> ')
            if wtd == '1':
                open('/opt/lazyshell/data/files/iface.txt','w').write(input('Interface: '))
                open('/opt/lazyshell/data/files/gateway.txt','w').write(input('Gateway: '))
            elif wtd == '2':
                auto_config_network()
            else:
                return print('Please choose a valid choice')
        elif com[0] == 'scan':
            print(DarkBlue+'Scanning your Network ...'+Finish)
            scan = os.popen("nmap " + gateway + "/24 -n -sP ").read()
            f = open('/opt/lazyshell/data/log/scan.txt','w')
            f.write(scan)
            f.close()
            devices = os.popen(" grep report /opt/lazyshell/data/log/scan.txt | awk '{print $5}'").read()
            devices_mac = os.popen("grep MAC /opt/lazyshell/data/log/scan.txt | awk '{print $3}'").read() + os.popen("ip addr | grep 'state UP' -A1 | tail -n1 | awk '{print $2}' | cut -f1  -d'/'").read().upper() # get devices mac and localhost mac address
            devices_name = os.popen("grep MAC /opt/lazyshell/data/log/scan.txt | awk '{print $4 ,S$5 $6}'").read() + "\033[1;32m(This device)\033[1;m"
            table_data = [
			    ['IP Address', 'Mac Address', 'Manufacturer'],
			    [devices, devices_mac, devices_name]
			]
            table = DoubleTable(table_data)
            # Show devices found on your network
            print("\n\033[1;36m ------ [ Devices found on your network ] ------ \n\033[1;m")
            print(table.table)
        elif com[0] == 'server':
            if com[1].lower() == 'tcp':
                bind_ip = com[2]
                bind_port = int(com[3])
                if com[2] == 'df': bind_ip = '0.0.0.0'
                server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                print('Socket created.')
                try:
                    server.bind((bind_ip, bind_port))
                except:
                    return print("Bind failed. Error : " + str(sys.exc_info()))
                server.listen(int(com[4]))
                print('Listening for clients ...')
                server_info = '{protocol} {ip} {port} {serv_type}'.format(protocol=com[1],ip=bind_ip,port=bind_port,serv_type=com[5])
                print(server_info)
                client_list = []
                if com[5] == 'com':
                    while True:
                        client,addr = server.accept()
                        print('[*] Accepted connection from %s: %d' % (addr[0],addr[1]))
                        client.sendall(server_info.encode('utf8'))
                        try:
                            threading.Thread(target=com_client_thread, args=(client,addr[0],addr[1])).start()
                        except:
                            print('Thread did not start.')
                            traceback.print_exc()
                    server.close()
                    return None
                elif com[5] == 'spreader':
                    while True:
                        client,addr = server.accept()
                        client_list.append(client)
                        print('[*] Accepted connection from %s: %d' % (addr[0],addr[1]))
                        client.sendall(server_info.encode('utf8'))
                        try:
                            threading.Thread(target=spread_client_thread, args=(client,addr[0],addr[1])).start()
                        except:
                            print('Thread did not start.')
                            traceback.print_exc()

                    server.close()
                elif com[5] == 'infospread':
                    script = com[6]
                    infospread_data = server_info
                    try:
                        args = ''
                        for arg in com[7:]: args+=arg+' '
                    except IndexError: args = ''
                    while True:
                        client,addr = server.accept()
                        client_list.append(client)
                        print('[*] Accepted connection from %s: %d' % (addr[0],addr[1]))
                        client.sendall(server_info.encode('utf8'))
                        try:
                            threading.Thread(target=infospread_client_thread, args=(client,addr[0],addr[1],script,args)).start()
                        except:
                            print('Thread did not start.')
                            traceback.print_exc()
                else:
                    return error('WrongServerTypeError',com)
            elif com[1].lower() == 'udp':
                return print('Not done yet')
        elif com[0] == 'connect':
            if com[3].lower() == 'udp':
                target_host = com[1]
                if target_host == 'df': target_host = '0.0.0.0'
                target_port = com[2]
                client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                while True:
                    request = input('Send (exit): ')
                    if request == 'exit':
                        break
                    client.senndall(request, (target_host, target_port)) # sendto a la base
                    data, addr = client.recvfrom(1024)
                    print('Received: '+data)
                client.close()
            # TCP
            elif com[3].lower() == 'tcp':
                client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                try:
                    client.connect((com[1], int(com[2])))
                except:
                    print('Connection Error')
                    client.close()
                    return None
                try:
                    server_type = com[4]
                except IndexError:
                    server_type = 'base'
                if server_type == 'base':
                    server_info = client.recv(1024).decode('utf8')
                    print('Server Info: '+server_info)
                    request = input('Send (exit) : ')
                    while request != 'exit':
                        client.sendall(request.encode('utf8'))
                        answer = client.recv(5120).decode('utf8')
                        if answer == '-':
                            pass
                        else:
                            print('[*] Received: {} from Server'.format(answer))
                        request = input('Send (exit) : ')
                    client.sendall(b'exit')
                elif server_type == 'send_spread':
                    while True:
                        request = input('Send (exit) : ')
                        if request == 'exit':
                            break
                        data = request.encode('utf-8')
                        client.sendall(data)
                    client.close()
                elif server_type == 'recv_spread':
                    while True:
                        t1 = time.perf_counter()
                        if t1 > 5000: print('Waiting for data ...')
                        data = client.recv(1024).decode('utf-8')
                        print('Got: '+data)
                    client.close()
                elif server_type == 'auto_ex':
                    path = com[5]
                    try: sleep_time = int(com[6])
                    except IndexError: sleep_time = .1
                    while True:
                        with open(path) as f:
                            request = f.read()
                            try:
                                if request == last_request: time.sleep(sleep_time)
                            except UnboundLocalError: pass
                            if request != '':
                                print('[*] Sending request of size {}'.format(sys.getsizeof(request)))
                                client.sendall(request.encode('utf-8'))
                            last_request = request[:]
                            f.close()
                    client.close()
                else:
                    raise 'Wrong Advanced Server Type'
            else:
                return print('Invalid Client-type')
        # shortcuts
        elif com[0] == 'show_sc':
            print('Shortcuts:')
            for sc in shortcuts: print(sc.split('.')[0])
        elif com[0] == 'ip':
            if system == 'windows':
                return print(os.popen('ipconfig').read())
            temp_ip = os.popen('hostname -I').read()
            temp_ip = temp_ip.replace('\n','')
            print(temp_ip)
            del temp_ip
        elif com[0] == 'echo':
            s=''
            for c in com[1:]: s+=c+' '
            print(os.system(s))
        elif com[0] == 'sysinfo':
            print('Machine: '+platform.machine())
            print('Architecture: '+platform.architecture()[0]+' - '+platform.architecture()[1])
            print('System: '+platform.system())
            # je sais pas si ils marchent bien, et ils sont depasses de tt facon
            #if system == 'linux': print('Linux Distro: '+platform.linux_distribution())
            #if system == 'windows': print('Win32 version: '+platform.win32_ver())
            print('OS version: '+platform.version())
            print('Python version: '+platform.python_version())
        elif com[0] == 'load_paths' and len(com) == 1: scan_paths()
        elif com[0] == 'restart' and len(com) == 1: # marche pas
            if system == 'linux': os.system('exit && ./lazyshell')
            if system == 'windows': interpreter('sys py lazyshell.py')
        elif com[0] == 'update' and system == 'linux' and len(com) == 1: os.system('apt update')
        elif com[0] == 'upgrade' and system == 'linux' and len(com) == 2: os.system('apt full-upgrade '+com[1])
        elif com[0] == 'upgrade' and system == 'linux' and len(com) == 1: os.system('apt full-upgrade')
        elif com[0] == 'set':
            if com[1] == 'user':
                user = input('UserName : ')
                open('/opt/lazyshell/data/files/user.txt','w').write(user)
        elif com[0] == 'copy': shutil.copy(com[1],com[2])
        elif com[0] == 'move': shutil.move(com[1],com[2])
        elif com[0] == 'mkdir': os.mkdir(com[1])
        elif com[0] == 'rmdir' and conf(): shutil.rmtree(com[1])
        elif com[0] == 'sudormdir': shutil.rmtree(com[1], ignore_errors=True)
        elif com[0] == 'rmfile' and conf(): os.remove(com[1])
        elif com[0] == 'clear' and len(com) == 1:
            if system == 'linux': os.system('clear')
            if system == 'windows': os.system('CLS')
            return True
        elif com[0] == 'cd':
            change_dir(com)
            return True
        elif com[0] == 'wait':
            time.sleep(int(com[1]))
        elif com[0] == 'ls':
            if len(com) == 1: return print(str(os.listdir())[1:-1])
            elif len(com) == 3:
                if com[1] == '-l' and '*' in com[2]:
                    for f in glob.glob(com[2]):
                        print(f)
            elif com[1] == '-l':
                for f in os.listdir():
                    print(f)
            elif '*' in com[1]:
                print(str([f for f in glob.glob(com[1])])[1:-1])
            return True
        elif com[0] == 'cat':
            with open(com[1], 'r') as f:
                print(f.read())
            return True
        elif com[0] == 'start':
            option = ' '
            if len(com) > 4: return error('ArgumentError')
            if len(com) == 3: option = com[2]+' '
            print('STARTING')
            os.system('python'+option+com[1])
            return print('FINISHED')
        elif com[0] == 'exec':
            os.system('./'+com[1])
            return print('\nFINISHED')
        elif com[0] == 'shortcut':
            ext = ['txt','bat','help']
            if com[1] in ext: return error('InvalidName',[com[1]])
            if len(com) > 3: return error('ArgumentError')
            if len([let for let in com[1] if let not in string.ascii_letters+string.digits+'_'+'-']) != 0 or com[1] in com_list: return print('/!\\ Invalid Name')
            if com[2] not in shell_list: return print('/!\\ '+com[2]+' is not supported')
            else:
                mode = ['write']
                if com[1] in [f.split('.')[0] for f in os.listdir(shell_paths)] and system != 'windows':
                    con_list = ['overwrite', 'edit', 'remove']
                    con = input('Name already exists. [overwrite/edit/remove] : ')
                    if con in con_list:
                        mode.append(con)
                    else: return error('WrongOption')
                mode = mode[::-1]
                if com[2] == 'terminal' and system == 'linux': # peut-être pré-écrire le #!/bin/bash
                    for command in mode:
                        if command == 'write' or command == 'edit':
                            input('Write a shell script, info: it starts with "#!/bin/bash"\nPlease be sure you are running this in terminal !!\nPress ENTER to continue ...')
                            os.system('cd '+shell_paths+' && nano '+com[1])
                            break
                        elif command == 'ovrewrite':
                            input('Write a shell script, info: it starts with "#!/bin/bash"\nPlease be sure you are running this in terminal !!\nPress ENTER to continue ...')
                            os.system('cd '+shell_paths+' && rm '+com[1]+' && nano '+com[1])
                            break
                        elif command == 'remove':
                            os.remove(os.path.join(shell_paths, com[1]))
                            print('shortcut removed')
                            break
                elif com[2] == 'lazyshell':
                    for command in mode:
                        if command == 'write' or command == 'edit':
                            input('Write a lazyshell script\nPlease be sure you are running this in terminal !!\nPress ENTER to continue ...')
                            os.system('cd '+shell_paths+' && nano '+com[1]+'.txt')
                            break
                        elif command == 'ovrewrite':
                            input('Write a lazyshell script\nPlease be sure you are running this in terminal !!\nPress ENTER to continue ...')
                            os.system('cd '+shell_paths+' && rm '+com[1]+'.txt')
                            break
                        elif command == 'remove':
                            os.remove(os.path.join(shell_paths, com[1]+'.txt'))
                            print('shortcut removed')
                            break
                elif com[2] == 'cmd':# and system == 'windows': #remettre apres
                    for command in mode:
                        if command != 'remove':
                            path = input('Please enter your .bat file path. There must be batch written in it!\nPath : ')
                            shutil.copy(path, shell_paths)
                        elif command == 'remove':
                            os.remove(os.path.join(shell_paths, com[1]))
                            print('shortcut removed')
                            break
                if 'remove' not in mode: print('To launch your script, type it\'s name in the shell')
                return print('Type "load_paths" to load your newest paths')

        else: return print('not done yet')

    except Exception as e:#ZeroDivisionError:#
        error(e.__class__.__name__, com)
        try:
            # closing the sockets after Error
            server.close()
            client.close()
        except:
            pass

# command temp
# connect 192.168.178.134 123 TCP auto_ex /text_file.txt 5
# server TCP df 123 5 infospread /root/python/lazyshell/data_handler.py hello world





# main loop
while True:
    command = input(Green+user+Finish+' > \033[1;34m'+os.getcwd()+'\033[1;m # ')
    interpreter(command)




