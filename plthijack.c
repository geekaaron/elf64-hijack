
#include "headers.h"
#include <errno.h>

int plthijack(char *tfile, char *name, Elf32_Addr addr)
{
	Elf64_Rela *relaplt;
	Elf64_Sym *symtab;
	Elf32_Off pltoff, funcoff;
	Elf32_Addr tmpaddr;

	elf64_t telf;

	int fd, symndx, funcndx;
	size_t relapltsz, pltsz, pltentsz;

	uint8_t *plt;
	char *shstrtab, *strtab;
	char shellcode[] = "\xe9\x00\x00\x00\x00";	// jmpq xxxx

	if (load_elf(tfile, &telf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed\n", RED("[-]"), tfile);
		return -1;
	}

	shstrtab = &telf.mem[telf.shdr[telf.ehdr->e_shstrndx].sh_offset];
	printf("Searching .rela.plt section and .plt section...\n");
	relaplt = NULL, plt = NULL;
	for (int i = 0; i < telf.ehdr->e_shnum; i++)
	{
		if (!strcmp(&shstrtab[telf.shdr[i].sh_name], ".rela.plt"))
		{
			relaplt = (Elf64_Rela *)&telf.mem[telf.shdr[i].sh_offset];
			relapltsz = telf.shdr[i].sh_size;
			symndx = telf.shdr[i].sh_link;
			printf("%s .rela.plt section offset: 0x%08lx\n", GREEN("[+]"), telf.shdr[i].sh_offset);
			printf("%s .rela.plt section address: 0x%08lx\n", GREEN("[+]"), telf.shdr[i].sh_addr);
			printf("%s .rela.plt section size: %ldBytes\n", GREEN("[+]"), telf.shdr[i].sh_size);
			printf("%s .rela.plt section linked symbol table index: %d\n", GREEN("[+]"), symndx);
		}
		else if (!strcmp(&shstrtab[telf.shdr[i].sh_name], ".plt"))
		{
			plt = &telf.mem[telf.shdr[i].sh_offset];
			pltoff = telf.shdr[i].sh_offset;
			pltentsz = telf.shdr[i].sh_entsize;
			pltsz = telf.shdr[i].sh_size;
			printf("%s .plt section offset: 0x%08lx\n", GREEN("[+]"), telf.shdr[i].sh_offset);
			printf("%s .plt section address: 0x%08lx\n", GREEN("[+]"), telf.shdr[i].sh_addr);
			printf("%s .plt section size: %ldBytes\n", GREEN("[+]"), pltsz);
			printf("%s .plt section entry size: %ldBytes\n", GREEN("[+]"), pltentsz);
		}
	}

	if (relaplt == NULL)
	{
		fprintf(stderr, "%s .rela.plt section not found\n", RED("[-]"));
		return -1;
	}

	if (plt == NULL)
	{
		fprintf(stderr, "%s .plt section not found\n", RED("[-]"));
		return -1;
	}

	symtab = (Elf64_Sym *)&telf.mem[telf.shdr[symndx].sh_offset];
	strtab = &telf.mem[telf.shdr[telf.shdr[symndx].sh_link].sh_offset];
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
		return -1;
	}

	printf("Searching function %s plt code...\n", name);
	tmpaddr = addr;
	for (int i = 0; i < pltsz / pltentsz; i++)
	{
		funcoff = *(Elf32_Off *)&plt[2];
		funcoff += (pltoff + 6);
		if (relaplt[funcndx].r_offset == funcoff)
		{
			printf("%s Function %s plt code offset: %08x\n", GREEN("[+]"), name, pltoff);
			addr -= (pltoff + sizeof(shellcode) - 1);
			*(Elf32_Addr *)&shellcode[1] = addr;
			memcpy(plt, shellcode, sizeof(shellcode) - 1);
		}
		plt += pltentsz;
		pltoff += pltentsz;
	}

	if (addr == tmpaddr)
	{
		fprintf(stderr, "%s Function %s plt code not found\n", RED("[-]"), name);
		return -1;
	}

	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY, telf.mode)) < 0)
	{
		fprintf(stderr, "%s Open file %s failed\n", RED("[-]"), TMP_FILE);
		return -1;
	}

	if (write(fd, telf.mem, telf.size) != telf.size)
	{
		perror("telf.mem");
		return -1;
	}

	if (fsync(fd) < 0)
	{
		fprintf(stderr, "[-] Fsync file %s failed\n", TMP_FILE);
		return -1;
	}

	close(fd);
	unload_elf(&telf);
	unlink(telf.path);
	rename(TMP_FILE, telf.path);

	return 0;
}

int main(int argc, char *argv[])
{
	Elf32_Addr addr;
	char *endptr;

	if (argc != 4)
	{
		printf("Usage: %s <target file> <target function> <new address>\n", argv[0]);
		exit(0);
	}

	errno = 0;
	addr = strtoul(argv[3], &endptr, 16);
	if (errno == EINVAL)
	{
		fprintf(stderr, "%s Bad address\n", RED("[-]"));
		exit(-1);
	}

	if (plthijack(argv[1], argv[2], addr) == -1)
	{
		fprintf(stderr, "%s PLT hijack failed\n", RED("[-]"));
		exit(-1);
	}

	return 0;
}
