#!/bin/env python3
from angr import Project
from claripy import BVS
from subprocess import check_output
from argparse import ArgumentDefaultsHelpFormatter, ArgumentParser


################################## CLASS DEFINITION ##################################

class AngrWrapper:

    def __init__(self, file_path):
        self.file_path = file_path
        file_info = check_output(['file', file_path])
        
        self.is_PIE = False
        if b"shared object" in file_info:
            self.is_PIE = True
        print(f"[+] Position Independant Executable (PIE) : {self.is_PIE}")

        self.project = Project(file_path)

        
    def menu(self):
        choice = 0
        while choice not in [1, 2, 3, 4]:
            print("\n[1]  Look for a string in output")
            print("[2]  Look for a win address while avoiding a fail address")
            print("[3]  Look for a win address while avoiding a fail address with a command-line argument")
            print("[4]  Exit")

            try:
                choice = int(input("\nYour choice : "))
            except:
                print("Your choice must be a number")

        # Look for a string in output
        if choice == 1:
            string = input("--> String to look for in the output : ")
            self.process_string_output(string)
        
        # Look for a win address while avoiding a fail address
        elif choice == 2:
            win = fail = 0
            try:
                win = int(input("--> Win address in hex : "), 16)
                fail = int(input("--> Fail address in hex : "), 16)
            except:
                print("[-] Bad address")
            self.process_win_fail(win, fail)

        # Look for a win address while avoiding a fail address with a command-line argument
        elif choice == 3:
            win = fail = win = bits = length = 0
            try:
                win = int(input("--> Win address in hex : "), 16)
                fail = int(input("--> Fail address in hex : "), 16)
                bits = int(input("--> Size in bits of the argument vector (hit ENTER for default 8 bits) : ") or "8")
                length = int(input("--> Length of the argument vector : "))
            except:
                print("[-] Bad address or vector initialisation value")
            self.process_win_fail_argv(win, fail, bits, length)
        
        # Exit
        elif choice == 4:
            exit(0)

    def process_string_output(self, string):
        simgr = self.project.factory.simgr()
        simgr.explore(find=lambda s: string.encode() in s.posix.dumps(1))
        inp = simgr.found[0].posix.dumps(0)
        print(f"\n[+] Input to have '{string}' in output : {inp}")


    def process_win_fail(self, win, fail):
        if self.is_PIE:
            win += 0x400000
            fail += 0x400000

        simgr = self.project.factory.simulation_manager(self.project.factory.full_init_state())
        simgr.explore(find=win, avoid=fail)
        inp = simgr.found[0].posix.dumps(0)
        print(f"\n[+] Input to find {hex(win)} while avoiding {hex(fail)} : {inp}")
    
    def process_win_fail_argv(self, win, fail, bits, length):
        if self.is_PIE:
            win += 0x400000
            fail += 0x400000

        arg = BVS('arg', bits*length)
        state = self.project.factory.entry_state(args=[self.file_path, arg])
        simgr = self.project.factory.simulation_manager(state)
        simgr.explore(find=win, avoid=fail)

        print(f"\n[+] Inputs to find {hex(win)} while avoiding {hex(fail)} :")

        if len(simgr.found) > 0:
            s = simgr.found[0]
            argv_1 = s.solver.eval(arg, cast_to=bytes).split(b'\x00')[0]
            print(f"\t- argv[1] = {argv_1}")
            print(f"\t- stdin = {s.posix.dumps(0)}")


################################## ARGUMENTS ##################################

parser = ArgumentParser(description="angr-wrapper is a little script to accelerate your fast angr process during CTF",
                        formatter_class=ArgumentDefaultsHelpFormatter)
parser.add_argument('-f',
                    '--file',
                    help="The path to the binary you're working on")
args = parser.parse_args()


################################## MAIN METHOD ##################################

def main():
    if args.file:
        wrapper = AngrWrapper(args.file)
        wrapper.menu()

    else:
        print()
        parser.print_help()
        print()


if __name__ == '__main__':
    main()