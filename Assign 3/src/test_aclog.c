#include <stdio.h>
#include <string.h>
#include <sys/stat.h>


int main() 
{
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};
        //Read, write, and search or execute permission for users other than the file owner
	//Expecting Action-denied-flag = 1 on those files
        chmod("file_3",S_IRWXO);
        chmod("file_4",S_IRWXO);
	chmod("file_5",S_IRWXO);
	chmod("file_6",S_IRWXO);
	chmod("file_7",S_IRWXO);
	chmod("file_8",S_IRWXO);
	chmod("file_9",S_IRWXO);

        //Expecting modifications in "file_0"
        file=fopen(filenames[0],"a");
        fclose(file);

	for (int i=0;i<10;i++) {
		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("Fopen error %s\n",filenames[i]);
		else {
                        //Write into file is name if it is permitted
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}
	}
}