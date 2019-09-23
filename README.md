
# ELF64 hijack

Elf64 object file relocation and plt hijack (even target file was striped or not).

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
$ sstrip host
$ host
I'm the host, please don't hijack me.
$ ls
evil_puts.c  headers.h  host.c    inject.o  plthijack    plthijack.o  relocate    relocate.o  utils.o
evil_puts.o  host       inject.c  Makefile  plthijack.c  README.md    relocate.c  utils.c
```

```
$ ./relocate host evil_puts.o
Searching text segment of target file...
[+] Parasite address: 0x00000858
Adjusting the sections address of object file...
[+] Section .text address: 0x00000000 --> 0x00000858
[+] Section .data address: 0x00000000 --> 0x000009a8
[+] Section .rodata address: 0x00000000 --> 0x000009a8
[+] Section .comment address: 0x00000000 --> 0x000009c7
[+] Section .note.GNU-stack address: 0x00000000 --> 0x000009f3
[+] Section .eh_frame address: 0x00000000 --> 0x000009f3
Relocating object file...
[+] Relocation linked section: .text
[+] Symbol linked section .rodata
[+] Position of relocation (P): 0x00000915
[+] Symbol value (S): 0x000009a8
[+] Symbol linked section .rodata
[+] Position of relocation (P): 0x00000920
[+] Symbol value (S): 0x000009a8
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000930
[+] Symbol value (S): 0x00000892
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000944
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .rodata
[+] Position of relocation (P): 0x00000950
[+] Symbol value (S): 0x000009a8
[+] Symbol linked section .text
[+] Position of relocation (P): 0x0000095a
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000970
[+] Symbol value (S): 0x000008c6
[+] Symbol linked section .text
[+] Position of relocation (P): 0x0000097f
[+] Symbol value (S): 0x00000892
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000993
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x0000099d
[+] Symbol value (S): 0x000008f0
[+] Relocation linked section: .eh_frame
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a13
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a33
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a53
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a73
[+] Symbol value (S): 0x00000858
[+] Symbol linked section .text
[+] Position of relocation (P): 0x00000a93
[+] Symbol value (S): 0x00000858
[+] Parasite size: 595 Bytes
Extacting object code from object file...
[+] Section .text: 336Bytes --> Object code
[+] Section .data: 0Bytes --> Object code
[+] Section .rodata: 31Bytes --> Object code
[+] Section .comment: 44Bytes --> Object code
[+] Section .note.GNU-stack: 0Bytes --> Object code
[+] Section .eh_frame: 184Bytes --> Object code
Searching text segment of target file...
[+] Text segment offset: 0x00000000
[+] Text segment address: 0x00000000
[+] Text segment file size: 2136Byte --> 2731Byte
[+] Text segment memory size: 2136Byte --> 2731Byte
Adjuting segments offset after text segment of the target file...
[+] Segment 3 offset: 0x00000db8 --> 0x00001db8
[+] Segment 4 offset: 0x00000dc8 --> 0x00001dc8
[+] Segment 8 offset: 0x00000db8 --> 0x00001db8
Searching symbols in object file...
[+] Symbol _write, value 0x00000858
[+] Symbol _strlen, value 0x00000892
[+] Symbol _open, value 0x000008c6
[+] Symbol _close, value 0x000008f0
[+] Symbol evil_puts, value 0x00000906

Success!
```

```
$ ./plthijack host puts 0x906
Searching .rela.plt section and linked symbol table and string table...
[+] .dynstr section offset: 0x00000360
[+] .dynsym section offset: 0x000002b8
[+] .rela.plt section offset: 0x000004d0
Searching function puts index in .rela.plt...
[+] Function puts index: 0
Searching function puts plt code...
[+] Function puts plt code offset: 00000510

Success!
```

```
$ ./host
I'm the host, please don't hijack me.
$ ls
evil_puts.c  headers.h  host.c       inject.c  Makefile   plthijack.c  README.txt  relocate.c  utils.c
evil_puts.o  host       igotyou.txt  inject.o  plthijack  plthijack.o  relocate    relocate.o  utils.o
$ cat igotyou.txt
Hello, I'm JAJ.
```

# End

Any problems: for_unity@sina.com
