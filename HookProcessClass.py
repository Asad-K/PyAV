import os
from datetime import datetime
from ProcessesClass import ProcessMonitor
from CleanMemoryClass import CleanMemory
from ScannerClass import Scanner

# timer
'''
curr_time = 0
inital_time = str(datetime.now().time()).split(':')[-1]
while curr_time < 10:
    get_time = str(datetime.now().time()).split(':')[-1]
    curr_time = float(get_time) - float(inital_time)        
'''


class HookProcess(ProcessMonitor, Scanner):
    def __init__(self):

        Scanner.__init__(self)
        ProcessMonitor.__init__(self)

        self.active_file_mons = []
        self.active_hooked_pids = dict()  # HookedPid : FileMonPid

        self.__void = ['cmd.exe', 'WMIC.exe', 'pythonw.exe', 'conhost.exe', 'FileMonitor.exe', 'iexplore.exe',
                       'EasyHook32Svc.exe', 'chrome.exe']
        self.processes = []
        self.name = ''
        self.pid = 0

    @staticmethod
    def get_state():
        with open('config\config.txt', 'r') as f:
            for line in f:
                line_ = line.split(':')
                if line_[0] == 'state':
                    state = line_[-1]
                    state.strip()
                    return int(state)

    @staticmethod
    def change_state(state):
        with open('config\config.txt', 'w') as f:
            f.write('state:' + state)

    # noinspection PyTypeChecker
    def hook(self):
        if self.name in self.__void:
            print('Did not inject into', self.name)
        elif not self.scan_process():
            with open('args.bat', 'w') as f:
                print('echo off\nEngine\FileMonitor.exe', self.pid, file=f)
                print('HookAgent Initialized on', self.pid, self.name)

            os.startfile('hidewin.vbs')
            self.get_spawned_file_mon_Pid()
        self.name = ''
        self.pid = 0
        # time.sleep(1)

    def get_spawned_file_mon_Pid(self):
        found = False
        curr_time = 0
        inital_time = str(datetime.now().time()).split(':')[-1]
        while curr_time < 5:
            if found:
                break
            get_time = str(datetime.now().time()).split(':')[-1]
            curr_time = float(get_time) - float(inital_time)
            pids = list(self.get_all_hookable_processes())
            for i in pids:
                if 'FileMonitor.exe' == i[1]:
                    if i[0] not in self.active_file_mons:
                        self.active_file_mons.append(i[0])
                        self.active_hooked_pids[self.pid] = i[0]
                        print('FileMon PID:', i[0])
                        found = True

    def initialize_hook(self):
        try:
            for pid, name in self.get_all_hookable_processes():
                self.name = name
                self.pid = pid
                self.hook()
        except BaseException as e:
            self.active_file_mons = []
            self.active_hooked_pids = dict()
            print('Error whilst injecting into target;', e)
            self.garbage_collection()

    def hook_single_pid(self, pid):
        try:
            self.pid = pid
            self.hook()
        except BaseException as e:
            print('Error whilst injecting into target;', e)
            self.garbage_collection()

    def scan_process(self):
        path = self.get_path_of_pid(self.pid)
        print(path)
        try:
            result = self.file_scan(path, 1)
        except BaseException as e:
            print(e)
            return
        if result:
            self.kill_process_via_pid(self.pid)
            print('killed')
            self.quarantine_file(self.detections)
            print('cleaned')
        return result


if __name__ == '__main__':
    h = HookProcess()
    c = CleanMemory()
    c.garbage_collection()
    h.initialize_hook()
    c.garbage_collection()
