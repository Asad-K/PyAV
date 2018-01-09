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

class BehaviourAnalysis(ProcessMonitor, Scanner, CleanMemory): #need to get read and write functions from old version
    
    def __init__(self, run=False):
        super().__init__()
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

                if self.new_action == self.action:
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
            return 'definition successfully added'
        elif arg1 == '-remove':
            self.remove_def(arg2)
            return 'definition successfully removed'    
        elif arg1 == '-s':
            return [line for line in open('definitions\\behavioural_definitions.txt', 'r')]
        raise EnvironmentError('ERROR: Invalid Command')  


    def check_action(self):
        self.ba_parse_path(self.action)
        if self.path:
            try:
                for item in self.definitions:
                        if os.path.samefile(self.path, item):    
                            self.potential_detection()
                            break
                        elif item in self.path:
                                self.potential_detection()
                                break
            except BaseException as e:
                print(e)
                
                    
                
    def ba_parse_path(self, action):
        
        if action:
            path = action.strip().split('"')
            del path[0]
            path = ''.join(path)
            pid = action.split(':')[0].lstrip('[')
            self.pid = pid
            self.path = path
            
            if '?' in self.path:
                self.path = path.split('?\\')[-1]
                
            print('pid_parser',self.pid)
            print('path_parser',self.path)
        
        

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
        newline = '& vbCrLf & '
        print('potential detection pid', self.pid)
        try:
            path_of_pid = self.get_path_of_pid(self.pid)
        except:
            path_of_pid = 'Unable to reolve path to proccess'
        if path_of_pid:
            msg = f'Potential detection!"{newline}"PATH:{path_of_pid}"{newline}"PID:{self.pid}"' \
                  f'{newline}"PATH ACCESSED:{self.path}'
            update_and_display_notification(msg)
        else:
            path_of_pid = 'Error resolving path'
            msg = f'Potential detection!"{newline}"PATH:{path_of_pid}"{newline}"PID:{self.pid}"' \
                  f'{newline}"PATH ACCESSED:{self.path}'
            update_and_display_notification(msg)
            return False
        try:
            rtn = self.virus_total_scan(path_of_pid)
        except:
            rtn = 0
            update_and_display_notification('Unable to access VirusTotal')
            return 
            
        if rtn > 2:
            print('MALWARE DETECTED')
            msg = f'MALWARE DETECTED"{newline}"PATH:{path_of_pid}'
            #self.kill_process_via_pid(self.pid)
            #self.quarantine_file([path_of_pid])
        else:
            print('clean')
    



       
if __name__ == '__main__':
    try:
        b = BehaviourAnalysis()
        b.run()
    except BaseException as e:
            e = str(e)
            update_and_display_notification(f'Behavioural Analysis crashed: {e}')
            exit(-1)
            

