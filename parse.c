/**************************************************************************
 * 
 * Copyright (c) 2020, Jingtang Zhang, Hua Zong.
 * 
 * Used for parsing a binary file to its hexadecimal representation.
 * 
 * @author Mr Dk.
 * @since 2020/04/24
 * 
 * ***********************************************************************/

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>

/**
 * @argv[1] - The file to be HEX dumped. 
 */
int main(int argc , char **argv) {

	int fd = open(argv[1], O_RDONLY);
	unsigned char buf;
	while (read(fd, &buf, sizeof(unsigned char)) > 0) {
		printf("0x%02x,", buf);
	}
	close(fd);

	return 0;
}
