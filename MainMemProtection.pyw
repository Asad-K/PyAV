#ensure data in the registry has been initlized before usage
import os
from ConfigMGRClass import update_and_display_notification
from ProcessesClass import ProcessMonitor 
from HookProcessClass import HookProcess
from CleanMemoryClass import CleanMemory 

h = HookProcess()
p = ProcessMonitor()
z = CleanMemory()


def hook_manager():
    prev_pids = set(p.get_all_hookable_processes())

    while True:
        try:
            if not h.get_state():
                state_mgr()
        except:
            pass

            
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
    h.initialize_hook()


if __name__ == '__main__':
    z.garbage_collection()
    try:
        h.initialize_hook()
        hook_manager()
    except BaseException as e:
        e = str(e)
        z.garbage_collection()
        update_and_display_notification(f'Mem-protection has crashed: {e}')
        exit(-1)
