import subprocess
import re

pat = re.compile('\s{2,}')


class ProcessMonitor():
    def __init__(self):

        # self.hookablepids = []
        self.void = ['taskkill.exe', 'cmd.exe', 'WMIC.exe', 'conhost.exe', 'chrome.exe', 'FileMonitor.exe',
                     'EasyHook32Svc.exe', 'EasyHook64Svc.exe']

    def get_all_hookable_processes(self):
        string = 'WMIC PROCESS get Caption,ExecutablePath,Processid'
        p = subprocess.Popen(string, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        output = output.decode()
        for line in output.split('\n')[1:]:
            # name = line[0:0 + 25].strip()
            # path = line[25:25 + 94].strip()
            # pid = line[119:].strip()
            v = re.split(pat, line)
            if len(v) == 4:
                name, path, pid, _ = v
            else:
                continue
            if path:
                # final = pid+'*'+name
                # self.hookablepids.append(final)
                # print(name, path, pid,sep='\'')
                yield int(pid), name  # generator

    def get_path_of_pid(self, pid):
        pid = str(pid)
        arg = 'wmic process where "ProcessID=' + pid + '" get ExecutablePath'
        p = subprocess.Popen(arg, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        output = output.decode().strip()
        if output:
            output_ = output.split(':')
            drive = output_[0]
            path = drive[-1] + ':' + output_[-1]
            if path == 'h:ExecutablePath':
                return False
            return path
        return False

    def find_match(self, prev_pids, curr_pids):
        return curr_pids & prev_pids

    def find_dead(self, prev_pids, curr_pids):
        return prev_pids - curr_pids

    def find_live(self, prev_pids, curr_pids):
        return curr_pids - prev_pids

    def clean_output(self, dead, live):
        obj_live = list(live)
        obj_dead = list(dead)

        for x in dead:
            for i in self.void:
                if x[-1] == i:
                    obj_dead.remove(x)

        for x in live:
            for i in self.void:
                if x[-1] == i:
                    obj_live.remove(x)

                    #        for i in self.void:
                    #            for x in dead:
                    #                if i == x[-1]:
                    #                    dead.remove(x)
                    #
                    #            for a in live:
                    #                if i == a[-1]:
                    #                    live.remove(a)
        return obj_dead, obj_live

    def get_image_and_pids(self):
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
                print('died:', dead)
            elif live:
                print('spawned:', live)


if __name__ == '__main__':
    p = ProcessMonitor()
    print(p.get_path_of_pid('8652'))
    # x = p.get_all_hookable_processes()
    # for i, a in x:
    #   print(i, a)

    # p.get_image_and_pids() #test
