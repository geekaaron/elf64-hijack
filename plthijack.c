
#include "headers.h"
#include <errno.h>

#define PLTENTSZ 0x10

int plthijack(char *tfile, char *name, Elf64_Addr addr)
{
	Elf64_Rela *relaplt;
	Elf64_Sym *symtab;
	Elf64_Addr pltaddr;
	Elf64_Off tmpoff, pltoff;

	elf64_t telf;

	int fd, funcndx;
	size_t relapltsz;

	uint8_t *plt;
	char *strtab;
	char shellcode[] = "\xe9\x00\x00\x00\x00";	// jmpq xxxx

	if (load_elf(tfile, &telf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed\n", RED("[-]"), tfile);
		return -1;									// -->
	}

	printf("Searching .rela.plt section and linked symbol table and string table...\n");
	relaplt = NULL;
	for (int i = 0; telf.dyn[i].d_tag != DT_NULL; i++)
	{
		switch (telf.dyn[i].d_tag)
		{
		case DT_JMPREL:
			/* Based on text segment */
			tmpoff = telf.dyn[i].d_un.d_ptr - telf.textvaddr;
			relaplt = (Elf64_Rela *)&telf.mem[tmpoff];
			printf("%s .rela.plt section offset: 0x%08lx\n", GREEN("[+]"), tmpoff);
			break;
		case DT_PLTRELSZ:
			relapltsz = telf.dyn[i].d_un.d_val;
			break;
		case DT_SYMTAB:
			/* Based on text segment */
			tmpoff = telf.dyn[i].d_un.d_ptr - telf.textvaddr;
			symtab = (Elf64_Sym *)&telf.mem[tmpoff];
			printf("%s .dynsym section offset: 0x%08lx\n", GREEN("[+]"), tmpoff);
			break;
		case DT_STRTAB:
			/* Based on text segment */
			tmpoff = telf.dyn[i].d_un.d_ptr - telf.textvaddr;
			strtab = &telf.mem[tmpoff];
			printf("%s .dynstr section offset: 0x%08lx\n", GREEN("[+]"), tmpoff);
			break;
		}
	}

	if (relaplt == NULL)
	{
		fprintf(stderr, "%s .rela.plt section not found\n", RED("[-]"));
		return -1;									// -->
	}

	printf("Searching function %s index in .rela.plt...\n", name);
	funcndx = -1;
	for (int i = 0; i < relapltsz / sizeof(Elf64_Rela); i++)
	{
		if (!strcmp(&strtab[symtab[ELF64_R_SYM(relaplt[i].r_info)].st_name], name))
		{
			funcndx = i;
			printf("%s Function %s index: %d\n", GREEN("[+]"), name, i);
			break;
		}
	}

	if (funcndx == -1)
	{
		fprintf(stderr, "%s Function %s not found\n", RED("[-]"), name);
		return -1;									// -->
	}

	printf("Searching function %s plt code...\n", name);
	/* Based on data segment */
	pltaddr = *(Elf64_Addr *)&telf.mem[telf.dataoff + (relaplt[funcndx].r_offset - telf.datavaddr)];
	/* Based on text segment */
	pltoff = pltaddr - telf.textvaddr - 6;		// 6 is a length of jump instruction
	plt = &telf.mem[pltoff];
	printf("%s Function %s plt code offset: %08lx\n", GREEN("[+]"), name, pltoff);

	addr -= (pltoff + sizeof(shellcode) - 1);
	*(Elf32_Addr *)&shellcode[1] = *(Elf32_Addr *)&addr;
	memcpy(plt, shellcode, sizeof(shellcode) - 1);

	/* Open file and write the changes */
	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY, telf.mode)) < 0)
	{
		fprintf(stderr, "%s Open file %s failed\n", RED("[-]"), TMP_FILE);
		return -1;									// -->
	}

	if (write(fd, telf.mem, telf.size) != telf.size)
	{
		perror("telf.mem");
		return -1;									// -->
	}

	if (fsync(fd) < 0)
	{
		fprintf(stderr, "[-] Fsync file %s failed\n", TMP_FILE);
		return -1;									// -->
	}

	close(fd);
	unload_elf(&telf);
	unlink(telf.path);
	rename(TMP_FILE, telf.path);

	return 0;
}

int main(int argc, char *argv[])
{
	Elf64_Addr addr;
	char *endptr;

	if (argc != 4)
	{
		printf("Usage: %s <target file> <target function> <new address>\n", argv[0]);
		exit(0);									// -->
	}

	errno = 0;
	addr = strtoul(argv[3], &endptr, 16);
	if (errno == EINVAL)
	{
		fprintf(stderr, "%s Bad address\n", RED("[-]"));
		exit(-1);									// -->
	}

	if (plthijack(argv[1], argv[2], addr) == -1)
	{
		fprintf(stderr, "%s PLT hijack failed\n", RED("[-]"));
		exit(-1);									// -->
	}

	printf("\n%s\n", GREEN("Success!"));

	return 0;
}
