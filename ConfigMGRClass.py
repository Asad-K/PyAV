import pickle
import os
import io
import winreg
import random

def update_and_display_notification(msg):
    message = f'm =MsgBox("{msg}", 16, "PyAV")'
    with open('notification.vbs', 'w') as f:
        f.write(message)
    os.startfile('notification.vbs')
                              
class REG():
    '''
    0 = apikey
    1 = state
    2 = exclusions
    '''
    def __init__(self):
        pass
        


    def check_keys(self):
        try:
            hkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\PyAV',0, winreg.KEY_READ)
        except:
            return False
        if len([winreg.EnumValue(hkey, i) for i in range(3)]) == 3:
            return True
        else:
            return False
     
    def load_defaults(self):
        try:
            self.clean_reg()
        except:
            pass
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE\PyAV')
        self.set_key('apikey', ['5fe2ba1c10c5770341fa142b1b97de16dc8ffe4f5af965463c279b3f8d538785'])
        self.set_key('state', '1')
        self.set_key('exclusions', [])
        
        

    def clean_reg(self):
        hkey = winreg.CreateKey(winreg.HKEY_CURRENT_USER, 'SOFTWARE')
        winreg.DeleteKey(hkey, 'PyAV')

    def pickle_value(self, value):
        f = io.BytesIO()
        pickle.dump(value,f)
        f.seek(0)
        value = f.read()
        return value
        
    def unpickle_value(self, value):
        f = io.BytesIO()
        f.write(value)
        f.seek(0)
        value = pickle.load(f)
        return value
        

    def set_key(self, key, value):
        value = self.pickle_value(value)
        hkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\PyAV',0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(hkey, key, 0, winreg.REG_BINARY, value)

    def read_key(self, index):
        hkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, 'Software\PyAV',0, winreg.KEY_READ)
        value = winreg.EnumValue(hkey, index)
        return self.unpickle_value(value[1])

    def add_api_key(self, api_key):
        if len(api_key) != 64:
            raise OSError('invalid api key')
        else:
            curr_keys = self.read_key(0)
            if api_key in curr_keys:
                raise OSError('key already in config')
            else:
                curr_keys.append(api_key)
                self.set_key('apikey', curr_keys)
                return True
            
    def retrive_api_key(self):
        keys = self.read_key(0)
        choice = random.choice(keys)
        return choice

    def change_state(self, state):
        self.set_key('state', state)

    def get_state(self):
        state = self.read_key(1)
        return state

    def add_exclusion(self, path):
        if not os.path.exists(path):
            raise OSError('specified exclusion path does not exist')
        curr_exs = self.get_exclusion()
        if path in curr_exs:
            raise OSError('already in exlusions')
        curr_exs.append(path)
        self.set_key('exclusions', curr_exs)
        return True
    
    def remove_exclusion(self, path):
        exs = self.get_exclusion()
        if path not in exs:
            raise OSError('path not in exclusions')
        exs.remove(path)
        self.set_key('exclusions', exs)
        
    def get_exclusion(self):
        exs = self.read_key(2)
        return exs
    
        

        
                
    
        
