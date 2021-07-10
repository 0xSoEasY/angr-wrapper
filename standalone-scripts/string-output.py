import angr

proj = angr.Project('../test-binaries/phack-login')
simgr = proj.factory.simgr()
simgr.explore(find=lambda s: b"[+] ACCESS GRANTED!" in s.posix.dumps(1))

print(simgr.found[0].posix.dumps(0))
