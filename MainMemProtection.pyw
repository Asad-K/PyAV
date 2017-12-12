import os
from ProcessesClass import ProcessMonitor
from HookProcessClass import HookProcess
from CleanMemoryClass import CleanMemory

h = HookProcess()
p = ProcessMonitor()
z = CleanMemory()


def update_and_display_notification(msg):
    message = 'm =MsgBox(' + msg + ', 16, "PyAV")'
    with open('notification.vbs', 'w') as f:
        f.write(message)
    os.startfile('notification.vbs')


def hook_manager():
    prev_pids = set(p.get_all_hookable_processes())

    while True:
        if not h.get_state():
            state_mgr()

        curr_pids = set(p.get_all_hookable_processes())
        dead = p.find_dead(prev_pids, curr_pids)
        live = p.find_live(prev_pids, curr_pids)

        # matches = p.find_match(prev_pids, curr_pids)

        prev_pids = curr_pids

        dead = list(dead)
        live = list(live)
        dead, live = p.clean_output(dead, live)

        dead_pids = []
        new_live_pids = []

        if dead:
            for i in dead:
                dead_pids.append(i[0])
            print(dead, 'died')

        for i in dead_pids:
            try:
                filemonPid = h.active_hooked_pids[i]
                # print('dead pid', i, 'filemonpid', filemonPid)
                z.kill_process_via_pid(filemonPid)
                h.active_file_mons.remove(filemonPid)
                del h.active_hooked_pids[i]
            except BaseException as e:
                print('process loaded before initialization therefore not in hooked dict:', e)

        if live:
            for i in live:
                new_live_pids.append(i[0])

        for pid in new_live_pids:
            h.pid = pid
            h.hook()


def state_mgr():
    z.garbage_collection()
    while not h.get_state():
        print('idle')
        pass
    h.initialize_hook()


class __CleanUpStub:  # on exit
    def __del__(self):
        print('on exit')
        z.garbage_collection()


if __name__ == '__main__':
    z.garbage_collection()
    h.initialize_hook()
    s = __CleanUpStub()
    hook_manager()
