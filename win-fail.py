import angr

win_adress = 0x401039
fail_adress = 0x401013

p = angr.Project('./KEY_CHECKER')
simgr = p.factory.simulation_manager(p.factory.full_init_state())
simgr.explore(find=win_adress, avoid=fail_adress)
print(simgr.found[0].posix.dumps(0))

