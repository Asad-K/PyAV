# [6536:5380]: WRITE (2 bytes) "\\?\C:\Windows"
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
from ConfigMGRClass import update_and_display_notification
from CleanMemoryClass import CleanMemory

class BehaviourAnalysis(ProcessMonitor, Scanner, CleanMemory): 
    
    def __init__(self, run=False):
        super().__init__()
        self.checked_pids = []
        open('temp.txt', 'w').close() #clear file
        self.definitions = self.get_definitions()
        self.action = self.get_action()
        self.new_action = ''
        self.path = ''
        self.pid = ''
        if run:
            self.run()
            
    def run(self):
        while True:
            while True:
                if self.new_action == self.action or (self.ba_parse_pid(self.new_action) in self.checked_pids) or (self.new_action == ''):
                    self.action = self.new_action
                    self.new_action = self.get_action()
                else:
                    break

            self.action = self.new_action
            self.check_action()
            self.path = ''
            self.pid = ''
    
    def run_ba_args(self, arg1, arg2):
        if arg1 == '-add':
            self.write_new_def(arg2)
            return 'definition successfully added restart the program for changes to take effect'
        elif arg1 == '-remove':
            self.remove_def(arg2)
            return 'definition successfully removed'    
        elif arg1 == '-s':
            return [line for line in open('definitions\\behavioural_definitions.txt', 'r')]
        raise EnvironmentError('ERROR: Invalid Command')
    

    def write_new_def(self, file_path):
        file_path = os.path.abspath(file_path)
        if not os.path.exists(file_path):
            raise EnvironmentError('ERROR: Path does not exist on file system')
        with open('definitions\behavioural_definitions.txt', 'a') as f:
            f.write(file_path+'\n')
        self.get_definitions()
        return True


    def remove_def(self, file_path):
        path = file_path + '\n'
        items = [line for line in open('definitions\behavioural_definitions.txt')]
        if path not in items:
            raise EnvironmentError('ERROR: Path not in definitions')
        items.remove(path)
        with open('definitions\behavioural_definitions.txt', 'a') as f:
            f.truncate(0)
            [f.write(item) for item in items]
        return True

    def check_action(self):
        self.path = self.ba_parse_path(self.action)
        self.pid = self.ba_parse_pid(self.action)
        self.checked_pids.append(self.pid)
        if self.path:
            try:
                self.path = os.path.abspath(self.path)
                for item in self.definitions:
                        if item in self.path:
                            self.potential_detection()
                            break
                        elif os.path.samefile(self.path, item):    
                            self.potential_detection()
                            break
                        elif os.path.samefile(self.path[:len(item)], item):
                            self.potential_detection()
                            break
            except BaseException as e:
                print(e)
                
    def ba_parse_pid(self, action):
        if action:
            pid = action.split(':')[0].lstrip('[')
        else:
            pid= False
        return pid
            
                   
    def ba_parse_path(self, action):
        if action:
            path = action.strip().split('"')
            del path[0]
            path = ''.join(path)
            if '?' in path:
                path = path.split('?\\')[-1]
            return path
        
        
    def get_action(self):
        try:
            action = [line for line in open('temp.txt', 'r')][0]
            return action
        except:
            return ''
            
    
    def get_definitions(self):
        defintions = [line.strip() for line in open('definitions\\behavioural_definitions.txt', 'r')]
        return defintions
    
    def potential_detection(self):
        newline = ''
        print('potential detection pid', self.pid)
        try:
            path_of_pid = self.get_path_of_pid(self.pid)
        except BaseException as e:
            path_of_pid = 'Unable to reolve path to proccess'
        if path_of_pid:
            msg = f'Potential detection!\nPATH:{path_of_pid}\nPID:{self.pid}\n' \
                  f'PATH ACCESSED:{self.path}\n Do you wish to proccess the threat'
            choice = update_and_display_notification(msg, 1)
            if choice:
                self.scan(path_of_pid)
            else:
                return
            
    def scan(self, path_of_pid):
        try:
            rtn = self.virus_total_scan(path_of_pid)
        except:
            update_and_display_notification('Unable to access VirusTotal')
            return False
            
        if rtn > 2:
            print('MALWARE DETECTED')
            msg = f'MALWARE DETECTED\nPATH:{path_of_pid}'
            self.kill_process_via_pid(self.pid)
            self.quarantine_file([path_of_pid])
        else:
            print('clean')


       
if __name__ == '__main__':
    #try:
    b = BehaviourAnalysis()
    b.run()
    #except BaseException as e:
          #  e = str(e)
           # update_and_display_notification(f'Behavioural Analysis crashed: {e}')
           # exit(-1)
            

