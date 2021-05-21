#include "libcflat.h"
#include "vm.h"
#include "vmalloc.h"
#include "alloc.h"

#define BUF_SIZE 0x2000000

int main(int ac, char **av)
{
	u8 *buf;
	int i = 0;

	setup_vm();

	buf = malloc(BUF_SIZE);
	assert(buf != NULL);

	printf("noise happens with buffer size to 0x%x\n", BUF_SIZE);
	while (1) {
		buf[i] = buf[(i + 1) % BUF_SIZE];
		i = (i + 1) % BUF_SIZE;
	}

	return 0;
}