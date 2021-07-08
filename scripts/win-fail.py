import angr

# Adding 0x400000 because angr map PIE binaries with a base address of 0x400000
win_adress = 0x10BF + 0x400000
fail_adress = 0x10E3 + 0x400000

p = angr.Project('./binaries/phack-login')
simgr = p.factory.simulation_manager(p.factory.full_init_state())
simgr.explore(find=win_adress, avoid=fail_adress)
print(simgr.found[0].posix.dumps(0))

