import subprocess


class CleanMemory:
    def __init__(self):
        pass

    def self_destruct(self):
        self.kill_processes(['cmd.exe', 'FileMonitor.exe', 'conhost.exe', 'pythonw.exe'])

    def garbage_collection(self):
        self.kill_processes(['FileMonitor.exe', 'conhost.exe'])

    def kill_process_via_pid(self, to_kill):
        to_kill = str(to_kill)
        self.cmd_pipe('taskkill /PID ' + to_kill + ' /f')

    def kill_process(self, to_kill):  # takes string
        self.cmd_pipe('taskkill /im ' + to_kill + ' /f')

    def kill_processes(self, to_kill):  # takes list
        for name in to_kill:
            self.cmd_pipe('taskkill /im ' + name + ' /f')

    @staticmethod
    def cmd_pipe(string):
        p = subprocess.Popen(string, stdout=subprocess.PIPE, shell=True)
        (output, err) = p.communicate()
        output = output.decode()
        return output


if __name__ == '__main__':  # test
    p = CleanMemory()
    p.garbage_collection()
    #p.self_destruct()
