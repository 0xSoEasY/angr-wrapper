# angr templates

This repository contains some samples of very basic angr scripts made during CTF (this repository is sort of a reminder) and I think that every script here was used in a write-up posted on my (french) blog : [https://www.soeasy.re](https://www.soeasy.re)

I'm kind of a noob with angr so feel free to contribute :grin: !

## string-output

This script is the most basic one and will simply find the way to have the string "[+] ACCESS GRANTED" (for our example) in the output of the binary execution.

Then it will print the input given to the binary to have the specified string in the output.

```bash
$ python3 string-output.py
WARNING | 2021-07-07 13:38:55,158 | cle.loader | The main binary is a position-independent executable. It is being loaded with a base address of 0x400000.
b'q4Eo-eyMq-1dd0-leKx\x0f`\x18"\x00IR\xc0D\xa0\x03\x0f@\x0c\x10\x91\x1a%$\x10\x86\x10h\x00\x08(\x88\x04\xa0\x08\xbc\x80$"\xc2\x90@B\x18$&'
```

--> Here the flag was PHACK{q4Eo-eyMq-1dd0-leKx}

## win-fail

This script is quite simple too. The goal here is to give two addresses to angr : 
- One address to "avoid" (angr will know that when he hits this address it means it's a fail)
- One address to "find" (angr will know that when he hits this address it means it's a win !)

