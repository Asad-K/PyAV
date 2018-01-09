import subprocess
import re
import os
from ctypes import *
from datetime import datetime
kernel32 = windll.kernel32
psapi = windll.psapi
PROCESS_ALL_ACCESS = ( 0x00F0000 | 0x00100000 | 0xFFF )
pat = re.compile('\s{2,}')


class ProcessMonitor():
    def __init__(self):

        self.void = ['taskkill.exe', 'cmd.exe', 'WMIC.exe', 'conhost.exe', 'chrome.exe', 'FileMonitor.exe',
                     'EasyHook32Svc.exe', 'EasyHook64Svc.exe']

    @staticmethod 
    def parse_path(path):
            path = path.split('\\')
            path = '\\'.join(path[3:])
            return path
        
    @staticmethod            
    def get_orignal_drive_name():
        rtn = windll.kernel32.GetLogicalDrives()
        letters = [chr(65 + i) for i in range(26) if rtn >> i & 1]
        yield from (f'{i}:\\' for i in letters)
    
    
    def get_all_hookable_processes(self):
        MAX_PATH = 260
        ImageFileName = (c_char*MAX_PATH)()
        pProcessIds = (c_ulong * 4096)()
        pBytesReturned = c_ulong()
        hModule = c_ulong()
        count = c_ulong()
        kernel32.K32EnumProcesses(byref(pProcessIds), sizeof(pProcessIds), byref(pBytesReturned))
        nReturned = pBytesReturned.value/sizeof(c_ulong())#find size of data returned
        pids = [i for i in pProcessIds][:int(nReturned)]#removes empty part of the array
        for i in pids:
            handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, i)
            if handle:
                psapi.EnumProcessModules(handle, byref(hModule), sizeof(hModule), byref(count))
                psapi.GetProcessImageFileNameA(handle, ImageFileName, MAX_PATH)
                path = ImageFileName.value.decode()
                yield int(i), os.path.basename(path)
                 

    def get_path_of_pid(self, pid):
        pid = int(pid)
        MAX_PATH = 260
        ImageFileName = (c_char*MAX_PATH)()
        handle = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
        if handle:
            psapi.GetProcessImageFileNameA(handle, ImageFileName, MAX_PATH)
            for drive in self.get_orignal_drive_name():
                path = drive+self.parse_path(ImageFileName.value.decode())
                if os.path.exists(path):
                    return path
        else:
            raise OSError('Unable to get handle to process:', pid)                  


    def find_match(self, prev_pids, curr_pids):
        return curr_pids & prev_pids

    def find_dead(self, prev_pids, curr_pids):
        return prev_pids - curr_pids

    def find_live(self, prev_pids, curr_pids):
        return curr_pids - prev_pids

    def clean_output(self, dead, live):
        obj_live = list(live)
        obj_dead = list(dead)
        [[obj_dead.remove(x) for i in self.void if x[-1] == i] for x in dead]
        [[obj_live.remove(x) for i in self.void if x[-1] == i] for x in live]
        return obj_dead, obj_live

    def proc_tracker(self):
        prev_pids = set(self.get_all_hookable_processes())

        while True:
            curr_pids = set(self.get_all_hookable_processes())

            dead = self.find_dead(prev_pids, curr_pids)
            live = self.find_live(prev_pids, curr_pids)

            # matches = self.find_match(prev_pids, curr_pids)

            prev_pids = curr_pids

            dead = list(dead)
            live = list(live)
            dead, live = self.clean_output(dead, live)

            if dead:
                print('--',datetime.now().time(),'--','died:', dead)
            elif live:
                print('--',datetime.now().time(),'--','spawned:', live)


if __name__ == '__main__':
    p = ProcessMonitor()
    #p.proc_tracker()
    #print(p.get_path_of_pid(5632))
    x = p.get_all_hookable_processes()
    for i, a in x:
        print(p.get_path_of_pid_bck(int(i)), i, a ,sep = '|' )
