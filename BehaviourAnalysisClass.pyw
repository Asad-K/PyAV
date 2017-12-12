# [6536:5380]: WRITE (2 bytes) "\\?\C:\Users\0\Desktop\text.txt"
# TypeOfAccess = WRITE
# ObjectAccessed = \\?\C:\Users\0\Desktop\text.txt
# pid = 6536

# [6536:10196]: READ (120 bytes) "\\?\C:\Users\0\Desktop\Softhound.com.url"
# TypeOfAccess = CREATE
# ObjectAccessed = \\.\aswSnx
# pid = 2716


# [2716:7656]: CREATE (OPEN_ALWAYS) "\\.\aswSnx"
# TypeOfAccess = CREATE
# ObjectAccessed = \\.\aswSnx
# pid = 2716
import os
from ProcessesClass import ProcessMonitor
from ScannerClass import Scanner
from MainMemProtection import update_and_display_notification
from CleanMemoryClass import CleanMemory


class BehaviourAnalysis(ProcessMonitor, Scanner, CleanMemory):
    def __init__(self):
        super().__init__()
        self.pid = ''
        self.path = ''
        self.definitions = []
        self.file_location = 'definitions\\behavioural_definitions.txt'
        self.get_definitions()

    def run_ba_args(self, arg1, arg2):
        if arg1 == '-add':
            if self.write_new_def(arg2):
                return 'definition successfully added'
            raise EnvironmentError('ERROR: Path does not exist on file system')
        elif arg1 == '-remove':
            if self.remove_def(arg2):
                return 'definition successfully removed'
            raise EnvironmentError('ERROR: Path not in definitions')
        elif arg1 == '-s':
            return [line for line in open('definitions\\behavioural_definitions.txt', 'r')]
        raise EnvironmentError('ERROR: Invalid Command')

    def write_new_def(self, file_path):
        if not os.path.exists(file_path):
            return False
        with open(self.file_location, 'a') as f:
            f.write(file_path+'\n')
        self.get_definitions()
        return True

    def remove_def(self, file_path):
        path = file_path + '\n'
        items = [line for line in open(self.file_location)]
        if path not in items:
            return False
        items.remove(path)
        with open('config\exclusions.txt', 'a') as f:
            f.truncate(0)
            [f.write(item) for item in items]
        return True

    def get_actions(self):
        action = ''
        with open('temp.txt', 'r+') as f:
            for line in f:
                action = line
        if action:
            path = action.strip().split('"')
            del path[0]
            path = ''.join(path)
            pid = action.split(':')[0].lstrip('[')
            if self.pid != pid:
                print(self.pid)
                self.pid = pid
                self.path = path
            else:
                return False

    def check_action(self):
        try:
            self.get_actions()
        except:
            pass
        if self.path:
            for item in self.definitions:
                if item in self.path:
                    self.potential_detection(self.pid)
                    self.path = ''
                    return True

    def get_definitions(self):
        if not self.definitions:
            self.definitions = [line.strip() for line in open(self.file_location)]

    def potential_detection(self, pid):
        newline = '& vbCrLf & '
        path_of_pid = self.get_path_of_pid(pid)
        if not path_of_pid:
            path_of_pid = 'Error resolving path'
        msg = '"Potential detection!"' + newline + '"PATH: ' + path_of_pid + '"' + newline + '"PID:' + self.pid + '"' \
              + newline + '"PATH ACCESSED:' + self.path + '"'
        update_and_display_notification(msg)
        if self.virus_total_scan(path_of_pid) > 2:
            # print('MALWARE DETECTED')
            # msg == '"MALWARE DETECTED"' + newline + '"PATH: ' + path_of_pid + '"'
            self.kill_process_via_pid(self.pid)
            self.quarantine_file([self.pid])
        else:
            print('clean')


if __name__ == '__main__':
    b = BehaviourAnalysis()
    # update_and_disapay_notification('"Potenital detection!"& vbCrLf & "PATH: c:\\desktop\\mal.exe"& vbCrLf &
    # "PID:903284"')
    # print(b.get_actions())
    # while True:
    # b.check_action()
