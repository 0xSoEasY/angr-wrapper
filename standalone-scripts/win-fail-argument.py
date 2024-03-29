import angr
import claripy

# Adding 0x400000 because angr map PIE binaries with a base address of 0x400000
WIN = 0x12C8 + 0x400000
FAIL = 0x129F + 0x400000

proj = angr.Project('../test-binaries/shields-claripy-argv')
arg = claripy.BVS('arg', 8*0x20)

state = proj.factory.entry_state(args=['./binaries/shields-claripy-argv', arg])
simgr = proj.factory.simulation_manager(state)
simgr.explore(find=WIN, avoid=FAIL)

if len(simgr.found) > 0:
    s = simgr.found[0]
    argv_1 = s.solver.eval(arg, cast_to=bytes).split(b'\x00')[0]
    stdin = s.posix.dumps(0).split(b'\x00')[0]
    print(f"argv[1] = {argv_1}")
    print(f"stdin = {stdin}")
