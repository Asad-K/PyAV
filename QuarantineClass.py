import random
import shutil
import os


class Quarantine:
    def __init__(self):
        pass

    #    def write_footer(self, dat):
    #        dat = dat.encode()
    #        _size = 360
    #        dat = (b' ' * _size + dat)[-_size:]
    #        with open(dat, 'ba') as f:
    #            f.write(dat)
    #
    #    def strip_footer(self, path):
    #        _size = 360
    #        with open(path, 'b') as f:
    #            f.seek(-_size, 'SEEK_END')
    #            dat = f.read(_size)
    #            f.seek(-_size, 'SEEK_END')
    #            f.truncate()
    #        dat = dat.decode().strip()

    def run_quarantine_args(self, arg1, arg2):
        if arg1 == '-s':
            return self.list_items()
        elif arg1 == '-clear':
            self.clear_malware_vault()
            return 'malware vault cleared'
        elif arg1 == '-return':
            if self.return_file(arg2):
                return 'Successfully returned file to original location'
            raise EnvironmentError('ERROR: Unable to return file')
        elif arg1 == '-q':
            if self.quarantine_file([arg2]):
                return 'Successfully file quarantined'
            raise EnvironmentError('ERROR: Unable to quarantine file')

        raise EnvironmentError('ERROR: Invalid Command')

    @staticmethod
    def quarantine_file(detections):
        fails = []
        for path in detections:
            fname = path.split('\\')[-1]
            if len(fname) == len(path):
                return False
            uid = str(random.randint(0, 10000))
            try:
                shutil.move(path, 'malware_vault')
                os.rename(f'malware_vault\\{fname}', f'malware_vault\\{uid}.vir')
                with open('malware_vault\QuarantineConfig.txt', 'a') as f:
                    f.write(f'{uid}>{path}\n')
                return True
            except BaseException as e:
                fails.append(path)
                print(e)
                print('unable to Quarantine file:', path)
                return fails

    @staticmethod
    def return_file(file_name):
        file = []
        found = False
        with open('malware_vault/QuarantineConfig.txt', 'r+') as f:
            for item in f:
                item = item.strip()
                path = item.split('>')[-1]
                fname = item.split('\\')[-1]
                uid = item.split('>')[0]
                if fname == file_name:
                    os.rename(f'malware_vault\\{uid}.vir', fname)
                    shutil.move(fname, path)
                    found = True
                else:
                    file.append(item)
            f.truncate(0)
            f.seek(0)
            for item in file:
                f.write(f'{item}\n')
        return found


    @staticmethod
    def clear_malware_vault():
        path = "malware_vault"
        file_list = os.listdir(path)
        for file_name in file_list:
            if file_name != 'QuarantineConfig.txt':
                print(file_name)
                os.remove(path + '//' + file_name)
        open('malware_vault/QuarantineConfig.txt', 'w').close()

    @staticmethod
    def list_items():
        defs = []
        with open('malware_vault/QuarantineConfig.txt', 'r') as f:
            for line in f:
                defs.append(line.strip())
        return defs


if __name__ == '__main__':
    q = Quarantine()
    #q.clear_malware_vault()
    #q.quarantine_file(['H:\\x.txt'])
    #q.return_file('x.txt')
