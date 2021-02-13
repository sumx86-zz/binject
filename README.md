# binject
Elf shellcode injector

```
make all BITS='32' (For 32-bit elf injections)
make all BITS='64' (For 64-bit elf injections)
```

## Example
* simple fork()
```
[64-bits]
./binject -f /bin/ls -s \x50\x48\xc7\xc0\x39\x00\x00\x00\x0f\x05\x58 -p 4096 && chmod +x infected
./infected

##############

[32-bits]
./binject -f /32bit/elf -s \xb8\x02\x00\x00\x00\xcd\x80 -p 4096 && chmod +x infected
./infected
```

```
\x50                          -> push rax
\x48\xc7\xc0\x39\x00\x00\x00  -> mov  rax, 0x39 ( fork() )
\x0f\x05                      -> syscall
\x58                          -> pop  rax
```

## TODO
* remove page_size variable and use the shellcode size instead
