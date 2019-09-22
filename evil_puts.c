
#include <sys/syscall.h>
#include <sys/types.h>
#include <fcntl.h>

ssize_t _write(int fd, const void *buf, size_t count)
{
	ssize_t ret;

	__asm__ __volatile__ (
		"pushq %%rsi\n\t"
		"syscall\n\t"
		"popq %%rsi"
		: "=a"(ret)
		: "0"(SYS_write), "D"(fd), "S"(buf), "d"(count)
	);

	return ret >= 0? ret: -1;
}

size_t _strlen(const char *s)
{
	size_t ret;

	__asm__ __volatile__ (
		"cld\n\t"
		"repne\n\t"
		"scasb\n\t"
		"notq %0\n\t"
		"decq %0"
		: "=c"(ret)
		: "D"(s), "a"(0), "0"(0xffffffffffffffff)
	);

	return ret;
}

int _open(const char *file, int flags, int mode)
{
	int fd;

	__asm__ __volatile__ (
		"syscall"
		: "=a"(fd)
		: "0"(SYS_open), "D"(file), "S"(flags), "d"(mode)
	);

	return fd;
}

int _close(int fd)
{
	__asm__ __volatile__ (
		"syscall"
		:: "a"(SYS_close), "D"(fd)
	);
}

int evil_puts(const char *s)
{
	char *file = "igotyou.txt";
	char *content = "Hello, I'm JAJ.\n";
	int fd;

	_write(1, s, _strlen(s));
	_write(1, "\n", 1);

	fd = _open(file, O_CREAT | O_WRONLY, 0644);
	_write(fd, content, _strlen(content));
	_close(fd);

	return 0;
}
