from tkinter import *
import os
import subprocess
from systray import SysTrayIcon
from ConfigMGRClass import update_and_display_notification
from MainProgramFunctionAndParser import MainProgram


class UI:
    def __init__(self):
        self.command_index = 0
        self.command_stack = []
        self.ASCII_ART = \
            ' _____           __      __\n' \
            '|  __ \         /\ \    / /\n' \
            '| |__) |   _   /  \ \  / / \n' \
            '|  ___/ | | | / /\ \ \/ /  \n' \
            '| |   | |_| |/ ____ \  /   \n' \
            '|_|    \__, /_/    \_\/    \n' \
            '        __/ |              \n' \
            '       |___/               \n'

        self.INITIAL_TEXT = '\nWelcome to PyAV\nType commands in the text box above\nHit enter to send them to the pro' \
                           'gram\n--? for help\nfor File paths use "\\\\" instead of "\\" except for the behavioural analysis\n' \
                            'Where you must use a single backslash\nWaiting for input...\n\n'

        master.protocol('WM_DELETE_WINDOW', self.hide_window)
        master.iconbitmap('icons\icon.ico')
        master.winfo_toplevel().title("PyAV")

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
        self.text_box.insert(END, self.ASCII_ART)
        self.text_box.insert(END, self.INITIAL_TEXT)
        self.text_box.config(state=DISABLED)

        master.bind('<Return>', self.get_input)
        master.bind('<Up>', self.load_previous_arg)

    def load_previous_arg(self, _):
        try:
            print(self.command_stack)
            text = self.command_stack[self.command_index]
            self.command_index -= 1 #stack grows down
        except:
           text = ''
        print(self.command_index)
        self.input_box.delete(0,END)
        self.input_box.insert(0,text)             
        

    def get_input(self, _): 
        arguments = self.input_box.get()
        self.input_box.delete(0, END)
        self.command_index = 0
        self.command_stack.append(arguments)
        try:
            ret = main.main_program_parse_args(arguments)
            if ret:
                self.UI_print(ret)
        except BaseException as e:
            self.UI_print(str(e))

    @staticmethod
    def destroy():
        master.destroy()

    def UI_print(self, data):
        self.text_box.config(state=NORMAL)
        print(data)
        try:
            self.text_box.insert(END, data + '\n\n')
        except:
            if data:
                for i in data:
                    i = str(i)
                    self.text_box.insert(END, i + '\n')
            else:
                self.text_box.insert(END, 'empty\n')

        self.text_box.see(END)
        self.text_box.config(state=DISABLED)

    def hide_window(self):
        master.withdraw()


class Icon:
    def __init__(self):
        if main.get_state():
            menu_options = (('Disable Protection', None, self.deactivate_av), ('Open PyAV', None, self.open_UI),)
            systray = SysTrayIcon("icons\icon1.ico", "Protected", menu_options)
        else:
            menu_options = (('Enable Protection', None, self.activate_av), ('Open PyAV', None, self.open_UI),)
            systray = SysTrayIcon("icons\icon2.ico", "UnProtected", menu_options)
        systray.start()

    def deactivate_av(self, systray):
        menu_options = (('Enable Protection', None, self.activate_av), ('Open PyAV', None, self.open_UI),)
        try:
            systray.shutdown()
        except BaseException as _:
            main.change_state('0')
            systray = SysTrayIcon("icons\icon2.ico", "UnProtected", menu_options)
            systray.start()

    def activate_av(self, systray):
        menu_options = (('Diable Protection', None, self.deactivate_av), ('Open PyAV', None, self.open_UI),)
        try:
            systray.shutdown()
        except BaseException:
            main.change_state('1')
            systray = SysTrayIcon("icons\icon1.ico", "Protected", menu_options)
            systray.start()

    def open_UI(self, systray):  # TODO: replace with '_' if unneeded
        master.deiconify()


def run_modules(module: str):
    name = "'pythonw.exe'"
    # name = "'python.exe'"
    current_path = os.path.dirname(__file__)

    out = subprocess.Popen(f'wmic process where "name={name}" get ExecutablePath', stdout=subprocess.PIPE, shell=True)
    (output, err) = out.communicate()
    python_path = output.decode().strip(' \r\n').split('\n')[1]
    current_path = current_path + '/' + module
    command = python_path.strip() + ' ' + '"' + current_path + '"'
    print(command)
    subprocess.Popen(command, stdout=subprocess.PIPE, shell=False)

def health_check(main):
    core_paths = ['Engine\\EasyHook.dll', 'Engine\\EasyHook32.dll', 'Engine\\EasyHook64.dll', 'Engine\\EasyHook32Svc.exe', 'Engine\\EasyHook64Svc.exe',
                  'Engine\\FileMonitorHook.dll', 'Engine\\FileMonitor.exe', 'definitions\\behavioural_definitions.txt']
    
    
    
    [core_paths.append(f'definitions\\hash_group_sorted_{i}.txt') for i in '0123456789abcdef']

    broken_paths = [i for i in core_paths if not os.path.exists(i)] 
    if broken_paths:
        update_and_display_notification(f'Core files missing: {broken_paths}')
        exit(-1)
     
    if not main.check_keys():
       try:
           main.load_defaults()
       except:
           update_and_display_notification('unable to load program configuration from registry')
           exit(-1)
    main.change_state('1')
    print('health check complete')
            
        


if __name__ == '__main__':
    #run_modules('MainMemProtection.py')
    # run_modules('BehaviourAnalysisClass.py')
    main = MainProgram()
    health_check(main)
    master = Tk()
    m = UI()
    i = Icon()
    mainloop()
