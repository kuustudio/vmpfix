# vmpfix
*vmpfix* is a dynamic x86/x64 VMProtect 2.13-3.5 import rebuilder.
The main goal of this project was to build correct and reliable tool to fix x86/x64 applications.
## Before
![](media/before1.png) 
![](media/before2.png)

## After
![](media/after1.png)
![](media/after2.png)

## Usage
```bash
vmpfix.exe
-p: required.
Usage: Universal VMProtect Import fixer [options]

Optional arguments:
-h --help       shows help message and exits [default: false]
-v --version    prints version information and exits [default: false]
-p --pid        Target process id [required]
-s --sections   VMProtect sections in target module [default: {".vmp0" ".vmp1" ".be1" ".be0"}]
-i --iat        New IAT section name [default: ".vmp0"]
-m --module     VMProtected module name (default: main executable) [default: ""]
```

VMProtect unpacking must be complete before running *vmpfix*.

## Details
There are 3 types of IAT accesses that VMProtect patches: `call`, `jmp` and `mov`.
Every stub resolves protected import with only 3 instructions:
```
lea reg, [imm]
mov reg, [reg + imm]
lea reg, [reg + imm]
```
Although stubs are obfuscated there are only handful of instructions that matters:
```
push
pop
lea
mov
xchg
ret
```
### Call stubs
Every `call` stub ends with `xchg` instruction:
`call [IAT]` -> `call .vmp1; int3`:
```
[!] push        rax
[!] mov         rax,qword ptr [rsp+8]
[!] lea         rax,[rax+1]
[!] mov         qword ptr [rsp+8],rax
[!] lea         rax,[1401269B2h]
[!] mov         rax,qword ptr [rax+0FE1D0h]
[!] lea         rax,[rax+445A4C4Eh]
[!] xchg        rax,qword ptr [rsp]
[!] ret
```
`call [IAT]` -> `push rcx; call .vmp1`:
```
[!] pop         rsi
[!] xchg        rsi,qword ptr [rsp]
[!] push        rsi
[!] lea         rsi,[1401832EDh]
[!] mov         rsi,qword ptr [rsi+0A7558h]
[!] lea         rsi,[rsi+49C80AACh]
[!] xchg        rsi,qword ptr [rsp]
[!] ret
```
### Jmp stubs
Every `jmp` stub ends with `ret 4/8` instruction:
`jmp [IAT]` -> `push rcx; call .vmp1:
```
[!] pop         rcx
[!] xchg        rcx,qword ptr [rsp]
[!] push        rcx
[!] lea         rcx,[1400EE9C4h]
[!] mov         rcx,qword ptr [rcx+14F6B2h]
[!] lea         rcx,[rcx+36F801BAh]
[!] xchg        rcx,qword ptr [rsp]
[!] ret         8
```
### Mov stubs
Every other stub can be considered as `mov` stub. There are some patterns as well. E.g. there is no `ret 8` or `xchg` at the end.
`mov rsi, API` -> `push rsi; call .vmp1`:
```
[!] pop         rsi
[!] xchg        rsi,qword ptr [rsp]
[!] pop         rsi
[!] lea         rsi,[rsi+1]
[!] push        rsi
[!] lea         rsi,[14015634Fh]
[!] mov         rsi,qword ptr [rsi+0EF63Ch]
[!] lea         rsi,[rsi+0C2B009Ah]
[!] ret
```

## Build
```
git clone --recurse-submodules https://github.com/archercreat/vmpfix.git
cd vmpfix
cmkr build
```
## Credits
https://github.com/build-cpp/cmk
https://github.com/can1357/linux-pe
https://github.com/DarthTon/Blackbone
## TODO
- kernel support