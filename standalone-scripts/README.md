# angr templates

This folder contains the differents scripts included in angr-wrapper 🙂. Here you'll find a little explanation of 
I think that every script here was used in a write-up posted on my (french) blog : [https://www.soeasy.re](https://www.soeasy.re)

## string-output.py

This script is the most basic one and will simply find the way to have the string "[+] ACCESS GRANTED" (for our example) in the output of the binary execution.

Then it will print the input given to the binary to have the specified string in the output.

Example of execution :
```bash
$ python3 string-output.py
WARNING | 2021-07-07 13:38:55,158 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
b'q4Eo-eyMq-1dd0-leKx\x0f`\x18"'
```
--> Here the flag was PHACK{q4Eo-eyMq-1dd0-leKx}

## win-fail.py

This script is quite simple too. The goal here is to give two addresses to angr : 
- One address to "avoid" (angr will know that when he hits this address it means it's a fail)
- One address to "find" (angr will know that when he hits this address it means it's a win !)

In this script, 0x400000 was added to the address because it's a PIE binary and angr will map PIE binaries with a base address of 0x400000. For non-PIE binaries, just put the address you find in you disassembler.

You can check if the binary is a PIE (Position Independant Executable) by using `checksec` for example :

```bash
$ checksec ./binaries/phack-login
[*] '/root/angr_templates/binaries/phack-login'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Example of execution : 
```bash
$ python3 win-fail.py 
WARNING | 2021-07-07 13:34:26,732 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
b'q4Eo-eyMq-1dd0-leKx\x06\x98\x8b\x16\x91$X"\x89J:\x08\x0c<\xa2C\x8b\x0f\xa0\x01\x10\x99\xa56\xcaa`H0(\x80F\x19\x0c\x08#\x05\x9a\x0c\x94`'
```
--> Here the flag was PHACK{q4Eo-eyMq-1dd0-leKx}

## win-fail-argument.py

This script is useful when you have to pass an arg to the program.

In this script, 0x400000 was added to the address because it's a PIE binary and angr will map PIE binaries with a base address of 0x400000 (as explained earlier).

To do this, we are using a claripy symbolic bitvector `claripy.BVS` called `arg` on 8 bits (1 byte) with a size of 0x20 in our example.
This length depends of course of the binary you're working on but keep in mind that if you put a large length is must not be a problem because the bitvector will be padded with `\x00` as we can see in this example of execution :

```bash
$ python3 win-fail-argument.py
WARNING | 2021-07-07 20:31:20,699 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
argv[1] = b'_starwars_vm_rocks_'
stdin = b''
```
--> Here the flag was SHIELDS{\_starwars_vm\_rocks\_}
