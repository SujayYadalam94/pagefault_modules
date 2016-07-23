#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/types.h>

int main(){

	printf("pid = %d\n", getpid());
	FILE* fp, *fp1, *fp2;
	int _iter = 0;
	sleep(10);
	while(_iter < 100){
		fp = fopen("input_file.txt","r");
		fp1 = fopen("somefile_output1.txt","w");
		fp2 = fopen("somefile_output2.txt", "w");
		char* buf=NULL;
		ssize_t length = 0;
		ssize_t read = 0;
		while((read = getline(&buf, &length, fp)) != -1){
			fprintf(fp1, "%s\n", buf);
			fprintf(fp2, "%s\n", buf);
		}

		fclose(fp);
		fclose(fp1);
		fclose(fp2);
		_iter++;
	}
	return 0;
}
