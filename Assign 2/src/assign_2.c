#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>
#include <openssl/sha.h>

#define BLOCK_SIZE 16


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
int encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);

int readFile(char* path, unsigned char**context);
void writeFile(char* path, unsigned char* buffer,int length);


/*
 * Prints the hex value of the input
 * 16 values per line
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
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
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
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}

/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv,
    int bit_mode)
{	
	const EVP_CIPHER *cipher;
	if (bit_mode==128){
		cipher=EVP_aes_128_ecb();
	}else{
		cipher=EVP_aes_256_ecb();
	}
	const EVP_MD* digest=EVP_sha1();
	unsigned char* salt=NULL;
	EVP_BytesToKey(cipher,digest,salt,password,strlen((const char*)password),1,key,iv);
}

/*
 * Encrypts the data and returns ciphertext size
 */
int
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{
	EVP_CIPHER_CTX* ctx;

	if(!(ctx=EVP_CIPHER_CTX_new()) ){
		printf("Could not create CTX");
	}

	int outLength,total=0;
	if (bit_mode==128){
		if(EVP_EncryptInit_ex(ctx,EVP_aes_128_ecb(),NULL,key,iv)==0)
			printf("Error in Encrypt Init\n");
	}else{
		if(EVP_EncryptInit_ex(ctx,EVP_aes_256_ecb(),NULL,key,iv)==0)
			printf("Error in Encrypt Init\n");
	}
	EVP_EncryptUpdate(ctx,ciphertext,&outLength,plaintext,plaintext_len);
	total=outLength;

	EVP_EncryptFinal(ctx,ciphertext+total,&outLength);
	total+=outLength;

	EVP_CIPHER_CTX_free(ctx);

	return total;
}

/*
 * Decrypts the data and returns the plaintext size
 */
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	int plaintext_length=0,outLength=0;

	EVP_CIPHER_CTX* ctx;

	if(!(ctx=EVP_CIPHER_CTX_new()) ){
		printf("Could not create CTX");
	}

	if (bit_mode==128){
		if(EVP_DecryptInit_ex(ctx,EVP_aes_128_ecb(),NULL,key,iv)==0)
			printf("Error in Decrypt Init\n");
	}else{
		if(EVP_DecryptInit_ex(ctx,EVP_aes_256_ecb(),NULL,key,iv)==0)
			printf("Error in Decrypt Init\n");
	}
	EVP_DecryptUpdate(ctx,plaintext,&outLength,ciphertext,ciphertext_len);
	plaintext_length=outLength;

	EVP_DecryptFinal(ctx,plaintext+plaintext_length,&outLength);
	plaintext_length+=outLength;
	
	EVP_CIPHER_CTX_free(ctx);

	return plaintext_length;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{
	CMAC_CTX* ctx=NULL;
	size_t cmac_len;
		if(!(ctx=CMAC_CTX_new())){
		printf("Error during CTX creating\n");
	}
	if (bit_mode==128){
		if(CMAC_Init(ctx,key,16,EVP_aes_128_ecb(),NULL)==0)
			printf("Error in CMAC init\n");
	}else{
		if(CMAC_Init(ctx,key,32,EVP_aes_256_ecb(),NULL)==0)
			printf("Error in CMAC init\n");
	}

	CMAC_Update(ctx,data,data_len);
	CMAC_Final(ctx,cmac,&cmac_len);
	
	CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int
verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{

	for(int i=0;i<BLOCK_SIZE;i++){
		if(cmac1[i]!=cmac2[i]){
			return -1;
		}
	}
	return 0;
}

/* TODO Develop your functions here... */
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

/*
 * Encrypts the input file and stores the ciphertext to the output file
 *
 * Decrypts the input file and stores the plaintext to the output file
 *
 * Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 *
 * Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}
	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	/* Initialize the library */
	ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();

	unsigned char* CMAC_1, *CMAC_2;
	int fLength=0, encLength=0;

	/* Keygen from password */ 
	unsigned char* key=(unsigned char*)malloc(sizeof(unsigned char)*bit_mode);
	unsigned char* iv=NULL;
	keygen(password,key,iv,bit_mode);
	/* Operate on the data according to the mode */
	unsigned char* plaintext=NULL;
	unsigned char* ciphertext=NULL;
	

	switch (op_mode){
	case 0:
		fLength=readFile(input_file,&plaintext);
		ciphertext=(unsigned char*)malloc(sizeof(unsigned char*)*fLength);
		/* encrypt */
		encLength= encrypt(plaintext,fLength,key,iv,ciphertext,bit_mode);
		if(encLength==0){
			printf("Error, encryption was not completed");
		}
		writeFile(output_file,ciphertext,encLength);
		free(ciphertext);
		break;
	case 1: 
		fLength=readFile(input_file,&ciphertext);
		plaintext=(unsigned char*)malloc(sizeof(unsigned char)*fLength);
		/* decrypt */
		encLength=decrypt(ciphertext,fLength,key,iv,plaintext,bit_mode);
		if(encLength==0){
			printf("Error, decryption was not completed");
		}
		writeFile(output_file,plaintext,encLength);
		free(plaintext);
		break;
	case 2: 
		fLength=readFile(input_file,&plaintext);
		ciphertext=(unsigned char*)malloc(sizeof(unsigned char*)*(fLength+BLOCK_SIZE));

		unsigned char* cmac=(unsigned char*)malloc(sizeof(unsigned char)*BLOCK_SIZE);
		
		encrypt(plaintext,strlen((const char*)plaintext),key,iv,ciphertext,bit_mode);
		gen_cmac(plaintext,fLength,key,cmac,bit_mode);
		
		for(int i=encLength;i<fLength+BLOCK_SIZE;i++){
			ciphertext[i]=cmac[i-encLength];
		}
		writeFile(output_file,ciphertext,(encLength+BLOCK_SIZE));
		free(ciphertext);
		free(cmac);
		break;
	case 3:
		fLength=readFile(input_file,&ciphertext);
		plaintext=(unsigned char*)malloc(sizeof(unsigned char)*(fLength-BLOCK_SIZE));
		encLength=decrypt(ciphertext,fLength-BLOCK_SIZE,key,iv,plaintext,bit_mode);
		CMAC_1=(unsigned char*)malloc(sizeof(unsigned char)*BLOCK_SIZE);
		CMAC_2=(unsigned char*)malloc(sizeof(unsigned char)*BLOCK_SIZE);

		for (int i=0;i<BLOCK_SIZE;i++){
			CMAC_1[i]=ciphertext[fLength-BLOCK_SIZE+i];
		}
		if (verify_cmac(CMAC_1,CMAC_2)==-1){
			printf("Not verified file\n");
		}else{
			writeFile(output_file,plaintext,encLength);
		}
		free(plaintext);
		free(CMAC_1);
		free(CMAC_2);
	default:
		break;
	}	

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);

	free(key);
	return 0;
}
