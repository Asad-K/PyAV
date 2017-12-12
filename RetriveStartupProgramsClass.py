from winreg import *
import os
from CleanMemoryClass import CleanMemory


class StartupProgramsRetrial(CleanMemory):
    def __init__(self):
        super().__init__()
        self.common_extensions = ['.exe ', '.vbs ', '.bat ', '.dll ', '.sys ']
        self.startup_programs = []
        self.startup_services = []
        self.startup_drivers = []
        self.scheduled_tasks = []
        self.final = []

    def startup_programs_retrieval(self):
        self.retrieve_startup_programs()
        self.retrieve_startup_services()
        self.retrieve_scheduled_tasks()

        def process_data(data):
            if '%' in data:
                item = data.split('\\')
                item[0] = os.path.expandvars(item[0])
                self.final.append('\\'.join(item))
            else:
                self.final.append(data)

        for i in self.startup_programs:
            process_data(i)
        for i in self.startup_services:
            process_data(i)
        for i in self.scheduled_tasks:
            process_data(i)

        return self.final

    def retrieve_scheduled_tasks(self):

        output = self.cmd_pipe('schtasks /query /fo LIST /v')
        output = output.split('HostName:')
        for i in output:
            i = i.split('Task To Run:                          ')[-1]
            path = i.split('Start In:')[0].strip()
            path = path.strip('"')
            if path != 'COM handler':
                if path != 'Folder: \\':
                    for extn in self.common_extensions:
                        if extn in path:
                            extn_ = extn.rstrip(' ')
                            path = path.split(extn)[0] + extn_

                    if len(path.split('\\')) > 1:
                        if path not in self.scheduled_tasks:
                            self.scheduled_tasks.append(path)

    def retrieve_startup_programs(self):
        reg_paths = [r'SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
                     r'SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Run']

        def process_data(data):
            data = str(data)
            try:
                if len(data) > 0:
                    data = data.strip('"')
                    data = data.split('"')[0]
                    self.startup_programs.append(data)
            except EnvironmentError:
                pass

        def enum_vals(aKey):
            for i in range(1024):
                try:
                    n, path, t = EnumValue(aKey, i)
                    process_data(path)
                except EnvironmentError:
                    break

        aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        for i in reg_paths:
            try:
                aKey = OpenKey(aReg, i)
            except BaseException as e:
                print(i, ':', e)

            enum_vals(aKey)
            CloseKey(aKey)

        return self.startup_programs

    def retrieve_startup_services(self):
        reg_path = r'System\CurrentControlSet\Services'

        def process_data_services(data):
            data = str(data)
            try:
                if '.' in data:
                    if '\\' in data:
                        data = data.split(',')[0]
                        data = data.split(' -')[0]
                        data = data.split('//')[0]
                        data = data.rstrip('"')
                        data = data.lstrip('"')
                        data = data.lstrip('@')
                        data = data.split('" /')[0]
                        data = data.lstrip('\\')
                        for extn in self.common_extensions:
                            if extn in data:
                                extn_ = extn.rstrip(' ')
                                data = data.split(extn)[0] + extn_

                        data_list = data.split('\\')
                        if len(data_list) > 1:
                            if 'system32' not in data_list:
                                if 'System32' not in data_list:
                                    if data.split("'")[0] != 'b':
                                        if data not in self.startup_services:
                                            self.startup_services.append(data)
                        if 'drivers' in data_list:
                            self.startup_drivers.append(data)
            except:
                pass

        def enum_service(aKey, aReg):
            for i in range(1024):
                try:
                    service_key = EnumKey(aKey, i)
                    for j in range(1024):
                        try:
                            full_path = reg_path + r'\\' + service_key
                            aKey_2 = OpenKey(aReg, full_path)
                            n, data, t = EnumValue(aKey_2, j)
                            CloseKey(aKey_2)
                            process_data_services(data)
                        except EnvironmentError:
                            break
                except EnvironmentError:
                    pass

        aReg = ConnectRegistry(None, HKEY_LOCAL_MACHINE)
        try:
            aKey = OpenKey(aReg, reg_path)
        except BaseException as e:
            print(i, ':', e)
            return False

        enum_service(aKey, aReg)
        CloseKey(aKey)

        return self.startup_services


if __name__ == '__main__':
    s = StartupProgramsRetrial()
    for i in s.startup_programs_retrieval():
        print(i)

    #s.retrieve_startup_programs()
    s.retrieve_startup_services()
    #s.retrieve_scheduled_tasks()
    #print('--scheduledTasks--')
    #for i in s.scheduled_tasks:
    #    print(i)
    #print('--startupServices--')
    #for i in s.startup_services:
    #    print(i)
    #print('---startupPrograms--')
    #for i in s.startup_programs:
    #    print(i)
    #print('--startupDrivers--')
    #for i in s.startup_drivers:
    #    print(i)
