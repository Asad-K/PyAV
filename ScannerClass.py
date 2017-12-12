import pip

try:
    import requests
except:
    try:
        pip.main(['install', 'requests'])
        import requests
    except:
        print('could not install core module')
        exit(-1)

import json
import time
import os
import hashlib
import random
import inspect
from tkinter import *
from ctypes import windll
from QuarantineClass import Quarantine
from RetriveStartupProgramsClass import StartupProgramsRetrial

m = None


class Scanner(Quarantine, StartupProgramsRetrial):
    def __init__(self):
        StartupProgramsRetrial.__init__(self)
        self.detections = []
        self.lines = {}
        self.exclusions = []

    def run_scan_args(self, arg1, arg2):  # imported by MainProgram
        master = Tk()

        def stub():
            import _tkinter
            try:
                global m
                m = Scanner_UI(master)
                m.UI_print('Running arguments ' + arg1 + ' ' + arg2)
                if arg1 == '-F':
                    self.folder_scan(arg2)
                elif arg1 == '-f':
                    self.file_scan(arg2, 0)
                elif arg1 == '-all':
                    self.full_scan()
                elif arg1 == '-quick':
                    self.quick_scan()
                elif arg1 == '-apikey':
                    api_key = arg2
                    if len(api_key) == 64:
                        if self.add_key_to_config(api_key):
                            m.UI_print('Successfully added api key')
                        else:
                            m.UI_print('Api key already in file')
                    else:
                        m.UI_print('Invalid key')
                elif arg1 == '-s':
                    m.UI_print([line + '\n' for line in open('config\\exclusions.txt', 'r')])
                elif arg1 == '-add':
                    if self.add_exclusion(arg2):
                        m.UI_print('successfully added exclusion')
                    else:
                        m.UI_print(
                            'Unable to add exclusion due to either the path to the exclusion does not exist or program '
                            'is unable to access exclusion database')
                elif arg1 == '-remove':
                    if self.remove_exclusion(arg2):
                        m.UI_print('successfully removed exclusion')
                    else:
                        m.UI_print(
                            'Unable to remove exclusion due to either the exclusion is not in the database or program i'
                            's unable to access the  database')
                else:
                    m.UI_print('invalid arguments')
                time.sleep(3)
                m.destroy()
            except _tkinter.TclError:
                raise EnvironmentError('Scan was terminated by user')
            finally:
                self.detections = []

        master.after(0, stub)
        mainloop()

    @staticmethod
    def add_exclusion(path):
        path = path + '\n'
        if path in [line for line in open('config\exclusions.txt', 'r')]:
            return False
        open('config\exclusions.txt', 'a').write(path)
        return True

    @staticmethod
    def remove_exclusion(path):
        path = path + '\n'
        if path not in [line for line in open('config\exclusions.txt', 'r')]:
            return False
        items.remove(path)
        print(items)
        with open('config\exclusions.txt', 'a') as f:
            f.truncate(0)
            [f.write(item) for item in items]
        return True

    @staticmethod
    def add_key_to_config(api_key):
        if api_key not in [line for line in open('config\VirusTotalApiKeys.txt', 'r')]:
            with open('config\VirusTotalApiKeys.txt', 'a') as f:
                f.write(api_key+'\n')
                return True
        return False

    @staticmethod
    def get_key_from_config():
        api_keys = []
        with open('config\VirusTotalApiKeys.txt', 'r') as f:
            for line in f:
                api_keys.append(line)
        return random.choice(api_keys)

    def virus_total_scan(self, path):
        try:
            hash_ = self.file_hasher(path)
        except BaseException as _:
            raise FileNotFoundError('unable to hash file')
        api_key = self.get_key_from_config()
        params = {'apikey': api_key, 'resource': hash_}
        headers = {"Accept-Encoding": "gzip, deflate", "User-Agent": "Chrome/41.0.2228.0"}
        response = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params, headers=headers)
        try:
            tests = response.json()['scans']
        except:
            raise FileNotFoundError(json.loads(response.content)['verbose_msg'])
        return sum(t['detected'] for t in tests.values())

    @staticmethod
    def resolve_connected_drives():
        rtn = windll.kernel32.GetLogicalDrives()
        letters = [chr(65 + i) for i in range(26) if rtn >> i & 1]
        for i in letters:
            i = i + ':\\'
            yield i

    def pre_scan_operations(self):  # computes file line numbers for binary search, loades exclusions
        if not self.exclusions:
            self.exclusions = [line.strip() for line in open('config\\exclusions.txt')]

        if not self.lines:
            try:
                m.UI_print('running pre-scan operations')
            except:
                print('running pre-scan operations')
            chars = '0123456789abcdef'
            for i in chars:
                with open('definitions\hash_group_sorted_' + i + '.txt', 'r') as f:
                    size = len(f.readlines())
                self.lines[i] = size
        return self.lines

    @staticmethod
    def file_system_traversal(path):
        try:
            for root, dirs, files in os.walk(path):
                for name in files:
                    full_path = os.path.join(root, name)
                    m.UI_print(full_path)
                    yield full_path
        except:
            pass

    def file_hasher(self, path):
        # manipulate file path from here
        if os.path.getsize(path) > 52428800:
            raise EnvironmentError('Error: File is too large to be scanned skipping....')
        elif os.path.getsize(path) == 0:
            raise EnvironmentError('Error: File is empty skipping....')
        elif path in self.exclusions: # todo folder exclusion
            raise EnvironmentError('File Excluded From Scan skipping....')

        BLOCKSIZE = 65536
        hasher = hashlib.md5()
        with open(path, 'rb') as afile:
            buf = afile.read(BLOCKSIZE)
            while len(buf) > 0:
                hasher.update(buf)
                buf = afile.read(BLOCKSIZE)
        hash_ = hasher.hexdigest()
        return hash_.strip()

    @staticmethod
    def binary_search(t, lines_count):
        first_letter = t[0]
        file = 'definitions\hash_group_sorted_' + first_letter + '.txt'
        lines = lines_count[first_letter]
        _min = 0
        _max = lines - 1
        t = int(t, 16)

        def val(h):
            with open(file) as f:
                f.seek(h * 34)
                return int(f.read(32), 16)

        while True:
            if _max < _min:
                return -1
            m = (_min + _max) // 2
            _hash = val(m)
            if _hash < t:
                _min = m + 1
            elif _hash > t:
                _max = m - 1
            else:
                return m + 1

    def full_scan(self):
        for x in self.resolve_connected_drives():
            self.folder_scan(x)
        return self.post_scan()

    def folder_scan(self, path):
        line_count = self.pre_scan_operations()
        for i in self.file_system_traversal(path):
            try:
                hash_ = self.file_hasher(i)
                if self.binary_search(hash_.strip(), line_count) != -1:  # -1 means not found
                    self.detections.append(i)
            except BaseException as e:
                m.UI_print(str(e))

        if inspect.stack()[1][3] not in ['quick_scan', 'folder_scan']:
            return self.post_scan()

    def quick_scan(self):
        for path in self.startup_programs_retrieval():
            self.file_scan(path, 0)
            m.UI_print(path)
        self.folder_scan('C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup')
        return self.post_scan()

    def file_scan(self, path, flag):
        line_count = self.pre_scan_operations()
        try:
            hash_ = self.file_hasher(path)
            if self.binary_search(hash_.strip(), line_count) != -1:  # -1 means not found
                self.detections.append(path)
        except BaseException as e:
            try:
                m.UI_print(str(e))
            except:
                print(e)

        if flag:
            if self.detections:
                print('clean')
                return True
            else:
                return False
        elif inspect.stack()[1][3] != 'quick_scan':
            return self.post_scan()

    def post_scan(self):
        m.UI_print('complete')
        if self.detections:
            m.UI_print('Malware Detected!')
            for item in self.detections:
                m.UI_print(item)
            m.UI_print('remove malware?(Y/N)')

            def ask_user(_):
                input_ = m.get_input()
                if input_ == 'y':
                    try:
                        self.quarantine_file(self.detections)
                    except BaseException as e:
                        m.UI_print('Unable to clean file(s), ')
                        m.UI_print(e)
                        time.sleep(5)
                        m.destroy()
                        return False

                    m.UI_print('Files where successfully cleaned')
                    self.detection = []
                    time.sleep(3)
                    m.destroy()
                    return True
                else:
                    m.UI_print('Exiting scanner....')
                    time.sleep(3)
                    m.destroy()

            m.input_box.bind('<Return>', ask_user)
        else:
            m.UI_print('No malicious programmes where detected')
            time.sleep(3)
            m.destroy()
            return True

class Scanner_UI():
    def __init__(self, master):
        self.master = master
        master.protocol('WM_DELETE_WINDOW', self.destroy)
        master.iconbitmap('icons\icon.ico')
        master.winfo_toplevel().title("PyAV Scanner")

        sheight = master.winfo_screenheight()
        swidth = master.winfo_screenwidth()

        sheight = sheight // 2
        swidth = swidth // 2

        master.minsize(width=swidth, height=sheight)
        master.maxsize(width=swidth, height=sheight)

        self.input_box = Entry(master, width=swidth, background='black', foreground="yellow")
        self.input_box.config(insertbackground='yellow')
        self.input_box.pack(fill='x')

        self.text_box = Text(master, background='black', foreground="yellow")
        self.text_box.pack(fill='both', expand=1)
        self.text_box.config(state=DISABLED)

    def get_input(self):
        self.master.update()
        self.master.update_idletasks()
        arguments = self.input_box.get()
        self.input_box.delete(0, END)
        return arguments

    def destroy(self):
        self.master.update()
        self.master.update_idletasks()
        self.master.destroy()
        raise EnvironmentError('Scanner closed')
        # exit()

    def UI_print(self, data):
        self.text_box.config(state=NORMAL)
        print(data)
        try:
            self.text_box.insert(END, data + '\n')
        except:
            for i in data:
                self.text_box.insert(END, i + '\n')

        self.master.update()
        self.master.update_idletasks()

        self.text_box.see(END)
        self.text_box.config(state=DISABLED)


if __name__ == '__main__':
    s = Scanner()
    # s.quick_scan()
    # s.file_scan('C:\\Users\\163631\\Desktop\\empty.exe')
    s.run_scan_args('-all', '')
    # s.full_scan()
    # s.file_scan('C:\\Users\ASUS\Desktop\mal.exe')

# m.main(loop)
