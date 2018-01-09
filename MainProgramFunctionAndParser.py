from BehaviourAnalysisClass import BehaviourAnalysis
from HookProcessClass import HookProcess

class MainProgram(HookProcess, BehaviourAnalysis):
    def __init__(self):
        BehaviourAnalysis.__init__(self)
        HookProcess.__init__(self)
        self.HELP = '--?[shows list of commands]\n--exit[closes program cleans up all hooked instances and associat' \
                    'ed processes]\n--status[shows status of components enabled or disabled]\n--uninstall[removes all ' \
                    'config data from the registry and exits program]\n\n--quarantine pram1 <' \
                    'pram2> [controls malware in quarantine]\n	-q[quarantines file #Warning: do not use on folders#' \
                    ']{pram2 = path}\n	-s[displays a list of all files in quarantine]\n	-return[returns file to ' \
                    'original location]{pram2 = file_name}\n	-clear[emptys quarantine]\n\n--realtime pram1 [memory' \
                    ' based component]\n	-s[shows all hooked processes]\n\n--scan pram1 <pram2> [scanner]\n	-apik' \
                    'ey[inset api key]{parm2 = api_key}\n  	-s[list exclusions]\n  	-add[add exclusion]\n  	-remove[remove exclusion]\n  	'\
                    '-F[Scan folder]{pram2 = path}\n	-f[scans specific fi' \
                    'le]{pram2 = path}\n	-quick[runs quick scan]\n	-all[starts full system scan]\n\n--behav pra' \
                    'm1 <pram2> [behavioural analysis]\n	-s[all behavioural definitons]\n	-add[all definition]{' \
                    'pram2 = path}\n	-remove[remove definition]{pram2 = file name}\n'

    @staticmethod
    def parse_arg3(cmdline_input):
        if '<' and '>' not in cmdline_input:
            raise EnvironmentError('missing < > around third argument')
        arguments_for_path = cmdline_input.split('<')
        arg2 = arguments_for_path[1].strip('>')
        return arg2

    def main_program_parse_args(self, cmdline_input):
        arguments = cmdline_input.split(' ')

        if arguments[0] == '--exit':
            self.self_destruct()

        elif arguments[0] == '--disable':
            if self.get_state():
                self.change_state('0')
                return 'PyAv is now disabled'
            else:
                return 'already disabled'

        elif arguments[0] == '--enable':
            if not self.get_state():
                self.change_state('1')
                return 'PyAv is now enabled'
            else:
                return 'already enabled'

        elif arguments[0] == '--status':
            if self.get_state() == '1':
                return 'PyAv is enabled'
            else:
                return 'PyAv is disabled'
            
        elif arguments[0] == '--uninstall':
            try:
                self.clean_reg()
                self.self_destruct()
            except:
                return 'unable to remove config data'

        elif arguments[0] == '--?':
            return self.HELP

        elif arguments[0] == '--scan':
            if arguments[1] in ('-quick', '-all', '-s'):
                self.run_scan_args(arguments[1], '')
            elif arguments[1] in ('-f', '-F', '-apikey', '-add', '-remove'):
                arg2 = self.parse_arg3(cmdline_input)
                self.run_scan_args(arguments[1], arg2)

        elif arguments[0] == '--realtime':
            if arguments[1] == '-s':
                if self.get_state():
                    return list(self.get_all_hookable_processes())
                else:
                    return 'PyAv is disabled; no processes are being monitored'

        elif arguments[0] == '--quarantine':
            if arguments[1] in ('-s', '-clear'):
                return self.run_quarantine_args(arguments[1], '')
            elif arguments[1] in ('-return', '-q'):  # not filtered
                arg2 = self.parse_arg3(cmdline_input)
                return self.run_quarantine_args(arguments[1], arg2)

        elif arguments[0] == '--behav':
            if arguments[1] == '-s':
                return self.run_ba_args(arguments[1], '')
            elif arguments[1] in ('-add', '-remove'):
                arg2 = self.parse_arg3(cmdline_input)
                return self.run_ba_args(arguments[1], arg2)

        raise EnvironmentError('Invalid Command')


if __name__ == '__main__':
    main = MainProgram()
    while True:
        input_ = input('>> ')
        try:
            print(main.main_program_parse_args(input_))
        except BaseException as e:
            print(e)
