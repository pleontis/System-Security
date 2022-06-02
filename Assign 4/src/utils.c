#include "utils.h"

/*
 * Prints the hex value of the input
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("%02X ", data[i]);
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_3 -g \n" 
	    "    assign_3 -i in_file -o out_file -k key_file [-d | -e]\n" 
	    "    assign_3 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -k    path    Path to key file\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -g            Generates a keypair and saves to 2 files\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *input_file, char *output_file, char *key_file, int op_mode)
{
	if ((!input_file) && (op_mode != 2)) {
		printf("Error: No input file!\n");
		usage();
	}

	if ((!output_file) && (op_mode != 2)) {
		printf("Error: No output file!\n");
		usage();
	}

	if ((!key_file) && (op_mode != 2)) {
		printf("Error: No user key!\n");
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}

/************************ADDED FUNCTIONS************************/

void
storeKey(const char*path, size_t key1, size_t key2){
	FILE* fp=fopen(path,"w");
    if(fp==NULL){
		printf("Error during opening file %s", path);
		exit(1);
	}
	fwrite(&key1,sizeof(size_t),1,fp);
	fwrite(&key2,sizeof(size_t),1,fp);
	fclose(fp);
}

void readKey(char *key_file,size_t* key1, size_t* key2){

	FILE* key=fopen(key_file,"r");
	if(key==NULL){
		printf("Error during opening file %s", key_file);
		exit(1);
	}
	fread(key1,sizeof(size_t),1,key);
	fseek(key,sizeof(size_t),SEEK_SET);
	fread(key2,sizeof(size_t),1,key);
	fclose(key);
}


int readFile(char* path,unsigned char** context){
	FILE* fp;
	unsigned char* buff;
	double fsize;
	if((fp=fopen(path,"r"))==NULL){
		printf("Could not open file\n");
		exit(1);
	}

	fseek(fp,0,SEEK_END);
	fsize=ftell(fp);
	rewind(fp);

	buff=(unsigned char*)malloc(sizeof(unsigned char)*fsize);
	//Read one character at a time and
	for(int i=0;i<fsize;i++){
		buff[i]=(unsigned char)fgetc(fp);
	}
	fclose(fp);
	*context=buff;
	return fsize;
}
//Not used Function
void writeFile(char* path, unsigned char* buffer,int length){
	FILE* fp;
	if((fp=fopen(path,"w"))==NULL){
		printf("Could not open file\n");
		exit(1);
	}

	for(int i=0;i<length;i++){
		fputc(buffer[i],fp);
	}
	fclose(fp);
	return;
}
