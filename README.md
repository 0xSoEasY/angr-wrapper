# angr wrapper

angr-wrapper is a simple script to accelerate rapid uses of angr, for example during CTFs. It contains pre-defined angr scripts useful in differents situations, which are available in "standalone" versions in the `standalone-scripts` repository.

You can test the python3 `angr-wrapper` and every script in `standalone-scripts` folder (note that a little exmplication of those differents scripts is in `standalone-scripts/README.md`) on binaries contained in the `test-binaries` folder.

## How to use ?

Simply make the script executable to launch it like a binary or use python3 to launch it. Specify the path to your binary via the `-f` parameter. This is told by the help message of the script.

```bash
$ git clone https://github.com/0xSoEasY/angr-wrapper
$ cd angr-wrapper
$ chmod +x angr-wrapper.py
$ ./angr-wrapper.py 

usage: angr-wrapper.py [-h] [-f FILE]

angr-wrapper is a little script to accelerate your fast angr process during CTF

optional arguments:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The path to the binary you're working on (default: None)
```

## Examples of use

### Looking for a string in output

```bash
$ ./angr-wrapper.py -f test-binaries/phack-login
[+] Position Independant Executable (PIE) : True
WARNING | 2021-07-10 12:01:07,745 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.

[1]  Look for a string in output
[2]  Look for a win address while avoiding a fail address
[3]  Look for a win address while avoiding a fail address with a command-line argument
[4]  Exit

Your choice : 1
--> String to look for in the output : GRANTED

[+] Input to have 'GRANTED' in output : b'q4Eo-eyMq-1dd0-leKx'
```

### Giving a win and a fail address with a flag passed via argv

```bash
$ ./angr-wrapper.py -f test-binaries/shields-claripy-argv
[+] Position Independant Executable (PIE) : True
WARNING | 2021-07-10 12:13:20,836 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.

[1]  Look for a string in output
[2]  Look for a win address while avoiding a fail address
[3]  Look for a win address while avoiding a fail address with a command-line argument
[4]  Exit

Your choice : 3
--> Win address in hex : 0x12C8
--> Fail address in hex : 0x129F
--> Size in bits of the argument vector (hit ENTER for default 8 bits) : 
--> Length of the argument vector : 32

[+] Inputs to find 0x4012c8 while avoiding 0x40129f :
	- argv[1] = b'_starwars_vm_rocks_'
	- stdin = b''
```

## Contribution

I'm kind of a noob with angr so feel free to contribute :grin: !
