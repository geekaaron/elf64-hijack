
# ELF64 hijack

Elf64 object file relocation and plt hijack.

# Usage

```
$ make all
$ gcc -c evil_puts.c
$ gcc -o host host.c
```

```
$ ./relocate host evil_puts.o
$ ./plthijack host puts <address of evil_puts>
```

# Test

```
$ ./relocate host evil_puts.o
Searching text segment of target file...
[+] Parasite address: 0x00000858
Adjusting the sections address of object file...
[+] Section .text address: 0x00000000 --> 0x00000858
[+] Section .data address: 0x00000000 --> 0x000009aa
[+] Section .rodata address: 0x00000000 --> 0x000009aa
[+] Section .comment address: 0x00000000 --> 0x000009c9
[+] Section .note.GNU-stack address: 0x00000000 --> 0x000009f5
[+] Section .eh_frame address: 0x00000000 --> 0x000009f5
Relocating object file...
[+] Relocation linked section: .text
[+] Symbol linked section .rodata
[+] Position of relocation (P): 0x00000917
[+] Symbol value (S): 0x000009aa
[+] Symbol linked section .rodata
[+] Position of relocation (P): 0x00000922
[+] Symbol value (S): 0x000009aa
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000932
[+] Symbol value (S): 0x00000894
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000946
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .rodata
[+] Position of relocation (P): 0x00000952
[+] Symbol value (S): 0x000009aa
[+] Symbol linked section .text
[+] Position of relocation (P): 0x0000095c
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000972
[+] Symbol value (S): 0x000008c8
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000981
[+] Symbol value (S): 0x00000894
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000995
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x0000099f
[+] Symbol value (S): 0x000008f2
[+] Relocation linked section: .eh_frame
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a15
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a35
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a55
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a75
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a95
[+] Symbol value (S): 0x00000858
[+] Parasite size: 597 Bytes
Extacting object code from object file...
[+] Section .text: 338Bytes --> Object code
[+] Section .data: 0Bytes --> Object code
[+] Section .rodata: 31Bytes --> Object code
[+] Section .comment: 44Bytes --> Object code
[+] Section .note.GNU-stack: 0Bytes --> Object code
[+] Section .eh_frame: 184Bytes --> Object code
Searching text segment of target file...
[+] Text segment offset: 0x00000000
[+] Text segment address: 0x00000000
[+] Text segment file size: 2136Byte --> 2733Byte
[+] Text segment memory size: 2136Byte --> 2733Byte
Adjuting segments offset of the target file...
[+] Segment 3 offset: 0x00000db8 --> 0x00001db8
[+] Segment 4 offset: 0x00000dc8 --> 0x00001dc8
[+] Segment 8 offset: 0x00000db8 --> 0x00001db8
Adjuting section offset of the target file...
[+] Section .eh_frame size: 264Bytes --> 861Bytes
[+] Section .init_array offset: 0x00000db8 --> 0x00001db8
[+] Section .fini_array offset: 0x00000dc0 --> 0x00001dc0
[+] Section .dynamic offset: 0x00000dc8 --> 0x00001dc8
[+] Section .got offset: 0x00000fb8 --> 0x00001fb8
[+] Section .data offset: 0x00001000 --> 0x00002000
[+] Section .bss offset: 0x00001010 --> 0x00002010
[+] Section .comment offset: 0x00001010 --> 0x00002010
[+] Section .symtab offset: 0x00001040 --> 0x00002040
[+] Section .strtab offset: 0x00001628 --> 0x00002628
[+] Section .shstrtab offset: 0x0000182a --> 0x0000282a
Adjuting section header offset of the target file...
[+] Section header offset: 0x00001928 --> 0x00002928
Searching symbol table of target file...
[+] Symbol table offset: 0x00002040
[+] Symbol table address: 0x00000000
[+] Symbol table size: 1512Bytes --> 1536Bytes
[+] Symbol table linked string table index: 27
Adjusting sections offset after .symtab section of target file...
[+] Section .strtab offset: 0x00002628 --> 0x00002640
[+] Section .shstrtab offset: 0x0000282a --> 0x00002842
Searching string table of target file...
[+] String table offset: 0x00002640
[+] String table address: 0x00000000
[+] String table size: 514Bytes --> 520Bytes
Adjusting the sections offset after .strtab section of target file...
[+] Section .shstrtab offset: 0x00002842 --> 0x00002848
Adjusting the section header offset of target file...
[+] Section header: 0x00002928 --> 0x00002946
Adding symbol _write to target file...
[+] Symbol _write, value 0x00000858: 0x00002628
Searching symbol table of target file...
[+] Symbol table offset: 0x00002040
[+] Symbol table address: 0x00000000
[+] Symbol table size: 1536Bytes --> 1560Bytes
[+] Symbol table linked string table index: 27
Adjusting sections offset after .symtab section of target file...
[+] Section .strtab offset: 0x00002640 --> 0x00002658
[+] Section .shstrtab offset: 0x00002848 --> 0x00002860
Searching string table of target file...
[+] String table offset: 0x00002658
[+] String table address: 0x00000000
[+] String table size: 520Bytes --> 527Bytes
Adjusting the sections offset after .strtab section of target file...
[+] Section .shstrtab offset: 0x00002860 --> 0x00002867
Adjusting the section header offset of target file...
[+] Section header: 0x00002946 --> 0x00002965
Adding symbol _strlen to target file...
[+] Symbol _strlen, value 0x00000894: 0x00002640
Searching symbol table of target file...
[+] Symbol table offset: 0x00002040
[+] Symbol table address: 0x00000000
[+] Symbol table size: 1560Bytes --> 1584Bytes
[+] Symbol table linked string table index: 27
Adjusting sections offset after .symtab section of target file...
[+] Section .strtab offset: 0x00002658 --> 0x00002670
[+] Section .shstrtab offset: 0x00002867 --> 0x0000287f
Searching string table of target file...
[+] String table offset: 0x00002670
[+] String table address: 0x00000000
[+] String table size: 527Bytes --> 532Bytes
Adjusting the sections offset after .strtab section of target file...
[+] Section .shstrtab offset: 0x0000287f --> 0x00002884
Adjusting the section header offset of target file...
[+] Section header: 0x00002965 --> 0x00002982
Adding symbol _open to target file...
[+] Symbol _open, value 0x000008c8: 0x00002658
Searching symbol table of target file...
[+] Symbol table offset: 0x00002040
[+] Symbol table address: 0x00000000
[+] Symbol table size: 1584Bytes --> 1608Bytes
[+] Symbol table linked string table index: 27
Adjusting sections offset after .symtab section of target file...
[+] Section .strtab offset: 0x00002670 --> 0x00002688
[+] Section .shstrtab offset: 0x00002884 --> 0x0000289c
Searching string table of target file...
[+] String table offset: 0x00002688
[+] String table address: 0x00000000
[+] String table size: 532Bytes --> 538Bytes
Adjusting the sections offset after .strtab section of target file...
[+] Section .shstrtab offset: 0x0000289c --> 0x000028a2
Adjusting the section header offset of target file...
[+] Section header: 0x00002982 --> 0x000029a0
Adding symbol _close to target file...
[+] Symbol _close, value 0x000008f2: 0x00002670
Searching symbol table of target file...
[+] Symbol table offset: 0x00002040
[+] Symbol table address: 0x00000000
[+] Symbol table size: 1608Bytes --> 1632Bytes
[+] Symbol table linked string table index: 27
Adjusting sections offset after .symtab section of target file...
[+] Section .strtab offset: 0x00002688 --> 0x000026a0
[+] Section .shstrtab offset: 0x000028a2 --> 0x000028ba
Searching string table of target file...
[+] String table offset: 0x000026a0
[+] String table address: 0x00000000
[+] String table size: 538Bytes --> 547Bytes
Adjusting the sections offset after .strtab section of target file...
[+] Section .shstrtab offset: 0x000028ba --> 0x000028c3
Adjusting the section header offset of target file...
[+] Section header: 0x000029a0 --> 0x000029c1
Adding symbol evil_puts to target file...
[+] Symbol evil_puts, value 0x00000908: 0x00002688
```

```
$ ./plthijack host puts 0x908
Searching .rela.plt section and .plt section...
[+] .rela.plt section offset: 0x000004d0
[+] .rela.plt section address: 0x000004d0
[+] .rela.plt section size: 24Bytes
[+] .rela.plt section linked symbol table index: 5
[+] .plt section offset: 0x00000500
[+] .plt section address: 0x00000500
[+] .plt section size: 32Bytes
[+] .plt section entry size: 16Bytes
Searching function puts index in .rela.plt...
[+] Function puts index: 0
Searching function puts plt code...
[+] Function puts plt code offset: 00000510
```

```
$ ./host
I'm the host, please don't hijack me
$ ls
evil_puts.c  headers.h  host.c       inject.c  Makefile   plthijack.c  README.txt  relocate.c  utils.c
evil_puts.o  host       igotyou.txt  inject.o  plthijack  plthijack.o  relocate    relocate.o  utils.o
$ cat igotyou.txt
Hello, I'm JAJ.
```
