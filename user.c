#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>

int main(){

	printf("pid = %d\n",getpid());
	syscall(333,getpid());
	sleep(1);

	int fp, fp2;
	fp = open("/proc/data_file", O_RDONLY);
	lseek(fp, 0, SEEK_SET);
	char buf[100000] = "";
	read(fp, buf,100000);
	close(fp);
	fp2 = open("data_output_file.csv", O_RDWR | O_CREAT);
	write(fp2, &buf, sizeof(buf));
	printf("%d\n", fp2);
	close(fp2);
	return 0;
}
