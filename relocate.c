
#include "headers.h"

int addsymbol(char *name, Elf64_Sym *sym, elf64_t *telf)
{
	Elf64_Off symoff, stroff, tmpoff;

	int fd, slen, strndx;
	size_t symsize, strstart;
	char *shstrtab, strtab;

	/* Get string table of section header */
	shstrtab = &telf->mem[telf->shdr[telf->ehdr->e_shstrndx].sh_offset];

	/* Get symbol table of target file */
	symsize = sizeof(Elf64_Sym);
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_type == SHT_SYMTAB)
		{
			symoff = telf->shdr[i].sh_offset + telf->shdr[i].sh_size;
			telf->shdr[i].sh_size += symsize;
			strndx = telf->shdr[i].sh_link;
			break;
		}
	}

	/* Adjust the section's offset after symtab section */
	printf("Adjusting the section's offset after .symtab section...\n");
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= symoff)
		{
			tmpoff = telf->shdr[i].sh_offset;
			telf->shdr[i].sh_offset += symsize;
			printf("%s Section %s: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpoff, telf->shdr[i].sh_offset);
		}
	}

	/* Get string table of symbol table of the target file */
	slen = strlen(name);
	stroff = telf->shdr[strndx].sh_offset + telf->shdr[strndx].sh_size;
	if (stroff > symoff) stroff -= symsize;
	strstart = telf->shdr[strndx].sh_size;
	telf->shdr[strndx].sh_size += slen;
	sym->st_name = strstart;

	/* Adjust the section's offset after strtab section */
	printf("Adjusting the section's offset after .strtab section...\n");
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= stroff + symsize)
		{
			tmpoff = telf->shdr[i].sh_offset;
			telf->shdr[i].sh_offset += slen;
			printf("%s Section %s: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpoff, telf->shdr[i].sh_offset);
		}
	}

	/* Adjust section header offset */
	telf->ehdr->e_shoff += (symsize + slen);

	/* Open temp file */
	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY, telf->mode)) < 0)
	{
		fprintf(stderr, "%s Open file %s failed\n", RED("[-]"), TMP_FILE);
		return -1;
	}

	/* Write symbol to temp file */
	if (write(fd, telf->mem, symoff) != symoff)
	{
		perror("telf->mem");
		return -1;
	}

	if (write(fd, sym, symsize) != symsize)
	{
		perror("sym");
		return -1;
	}

	if (write(fd, telf->mem + symoff, stroff - symoff) != stroff - symoff)
	{
		perror("telf->mem + symoff");
		return -1;
	}

	if (write(fd, name, slen) != slen)
	{
		perror("name");
		return -1;
	}

	if (write(fd, telf->mem + stroff, telf->size - stroff) != telf->size - stroff)
	{
		perror("telf->mem + stroff");
		return -1;
	}

	/* Delete the target file and rename the temp file */
	unload_elf(telf);
	unlink(telf->path);
	rename(TMP_FILE, telf->path);
	load_elf(telf->path, telf);

	return 0;
}

int relocate_elf(char *tfile, char *pfile)
{
	elf64_t telf, pelf;
	Elf64_Addr oshaddr;
	Elf64_Rela *rela;
	Elf64_Shdr *tsection;
	Elf64_Sym *symtab, *symbol;
	Elf64_Addr paddr, rvalue, taddress;
	Elf64_Addr *rlocation;
	Elf64_Off symoff;

	size_t psize;
	uint8_t *pcode;
	char *shstrtab, *strtab;

	if (load_elf(tfile, &telf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed\n", RED("[-]"), tfile);
		return -1;								// -->
	}

	if (load_elf(pfile, &pelf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed\n", RED("[-]"), pfile);
		return -1;								// -->
	}

	/* Get the string table of section header */
	shstrtab = &pelf.mem[pelf.shdr[pelf.ehdr->e_shstrndx].sh_offset];

	/* Get the target address where parasite will inject (text padding) */
	for (int i = 0; i < telf.ehdr->e_phnum; i++)
	{
		if (telf.phdr[i].p_type == PT_LOAD && !telf.phdr[i].p_offset)
		{
			paddr = telf.phdr[i].p_vaddr + telf.phdr[i].p_memsz;
			printf("%s Parasite address: 0x%08lx\n", GREEN("[+]"), paddr);
		}
	}

	/* Adjust the parasite file sections that type is SHT_PROGBITS */
	printf("Adjusting the section address of object file...\n");
	psize = 0;
	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_PROGBITS)
		{
			oshaddr = pelf.shdr[i].sh_addr;
			pelf.shdr[i].sh_addr += (paddr + psize);
			psize += pelf.shdr[i].sh_size;
			printf("%s Section %s: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[pelf.shdr[i].sh_name], oshaddr, pelf.shdr[i].sh_addr);
		}
		else if (pelf.shdr[i].sh_type == SHT_STRTAB && i != pelf.ehdr->e_shstrndx)
			strtab = &pelf.mem[pelf.shdr[i].sh_offset];
	}

	printf("%s Parasite size: %ld Bytes\n", GREEN("[+]"), psize);
	if (!(pcode = (uint8_t *)malloc(psize)))
	{
		fprintf(stderr, "%s Malloc parasite code failed\n", RED("[-]"));
		return -1;
	}

	printf("Extacting object code from object file...\n");
	psize = 0;
	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_PROGBITS)
		{
			memcpy(pcode + psize, &pelf.mem[pelf.shdr[i].sh_offset], pelf.shdr[i].sh_size);
			printf("%s Section %s: %ld bytes --> Object code\n", GREEN("[+]"), \
				&shstrtab[pelf.shdr[i].sh_name], pelf.shdr[i].sh_size);
			psize += pelf.shdr[i].sh_size;
		}
	}

	/* Relocate the parasite file */
	printf("Relocating object file...\n");
	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_RELA)
		{
			symoff = pelf.shdr[pelf.shdr[i].sh_link].sh_offset;
			symtab = (Elf64_Sym *)&pelf.mem[symoff];
			rela = (Elf64_Rela *)&pelf.mem[pelf.shdr[i].sh_offset];
			tsection = &pelf.shdr[pelf.shdr[i].sh_info];
			printf("%s Symbol table: 0x%08lx\n", GREEN("[+]"), symoff);
			printf("%s Target section: %s\n", GREEN("[+]"), &shstrtab[tsection->sh_name]);
			for (int j = 0; j < pelf.shdr[i].sh_size / sizeof(Elf64_Rela); j++, rela++)
			{
				/* Get associated symbol */
				symbol = &symtab[ELF64_R_SYM(rela->r_info)];
				symoff += ((char *)symbol - (char *)symtab);
				/* Get symbol value: S */
				rvalue = tsection->sh_addr + symbol->st_value;
				/* Get target address: P */
				taddress = tsection->sh_addr + rela->r_offset;
				/* Get location of relocation in file */
				rlocation = (Elf64_Addr *)&pelf.mem[tsection->sh_offset + rela->r_offset];

				printf("%s Symbol %s: 0x%08lx\n", GREEN("[+]"), &strtab[symbol->st_name], symoff);
				printf("%s Target address: 0x%08lx\n", GREEN("[+]"), taddress);
				printf("%s Relocation value: 0x%08lx\n", GREEN("[+]"), rvalue);

				switch(ELF64_R_TYPE(rela->r_info))
				{
				/* R_X86_64_PC32: S + A - P */
				case R_X86_64_PC32:
					*rlocation += rvalue;
					*rlocation += rela->r_addend;
					*rlocation -= taddress;
					break;
				/* R_X86_64_32: S + A - P */
				case R_X86_64_32:
					*rlocation += rvalue;
					*rlocation += rela->r_addend;
					break;
				}
			}
		}
	}

	if (inject_elf(&telf, pcode, psize) == -1)
	{
		fprintf(stderr, "%s Inject file %s failed\n", RED("[-]"), tfile);
		return -1;
	}

	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_SYMTAB)
		{
			strtab = &pelf.mem[pelf.shdr[pelf.shdr[i].sh_link].sh_offset];
			symbol = (Elf64_Sym *)&pelf.mem[pelf.shdr[i].sh_offset];
			for (int j = 0; j < pelf.shdr[i].sh_size / sizeof(Elf64_Sym); j++, symbol++)
			{
				if (ELF64_ST_TYPE(symbol->st_info) == STT_FUNC || \
					ELF64_ST_TYPE(symbol->st_info) == STT_OBJECT)
				{
					tsection = &pelf.shdr[symbol->st_shndx];
					symbol->st_value += tsection->sh_addr;
					addsymbol(&strtab[symbol->st_name], symbol, &telf);
				}
			}
		}
	}

	free(pcode);
	unload_elf(&telf);
	unload_elf(&pelf);

	return 0;
}

int main(int argc, char *argv[])
{
	if (argc != 3)
	{
		printf("Usage: %s <target file> <object file>\n", argv[0]);
		exit(-1);
	}

	if (relocate_elf(argv[1], argv[2]) == -1)
	{
		fprintf(stderr, "%s Relocate file %s failed\n", RED("[-]"), argv[2]);
		exit(-1);
	}

	return 0;
}
