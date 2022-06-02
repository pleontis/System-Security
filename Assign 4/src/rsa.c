#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *
sieve_of_eratosthenes(int limit, int *primes_sz)
{
	//primes_sz=(int*)malloc(sizeof(int));
	size_t* primes=malloc(sizeof(size_t)*limit);
	if (limit>2){	
		size_t array[limit+1];
		//Loading the array with numbers from 1 to n
		for(int i=1;i<=limit;i++){
			array[i] = i;
		}
		//Start with least prime number, which is 2.
		for(int i=2;i*i<=limit;i++){
			if(array[i]!=-1){
			//Mark all the multiples of i as -1.
			for(int j=2*i;j<=limit;j+=i)
				array[j] = -1;
		}
	}
	//Create an array only with prime numbers
	for(int i=2;i<=limit;i++){
		if(array[i]!=-1){
			primes[(*primes_sz)]=array[i];
			(*primes_sz)++;
		}
	}
	}else{
		printf("There are not prime numbers to find within this limit\n");
	}
	return primes;
}

/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	int gcd=1;
	for(int i=1;i<a && i<=b;i++){
		if(a%i==0 && b%i==0)
			gcd=i;
	}
	return gcd;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e=-1;
	int primes_sz=0;
	//size_t * primes=sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&primes_sz);

	while (e==-1){
		e=rand()%1000000;
		if((e%fi_n!=0) && (gcd(e,fi_n)==1)){
			break;
		}else{
			e=-1;
		}
	}
	return e;
}

/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
	a=a%b;
	for( int i=0;i<b;i++){
		if(((a*i)%b)==1)
			return i;
	}
}

/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void
rsa_keygen(void)
{
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	int prime_sz=0;
	size_t* primes=sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&prime_sz);
	
	//Calculate parameters for creating both private and public key
	p=primes[rand()%prime_sz];
	q=primes[rand()%prime_sz];

	n=p*q;

	fi_n=(p-1)*(q-1);
	e=choose_e(fi_n);
	d=mod_inverse(e,fi_n);

	//Store keys to files
	storeKey("public.key",n,e);
	storeKey("private.key",n,d);
}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{	
	//Read plaintext from input file and count characters read
	unsigned char* plaintext;
	int fLength=readFile(input_file,&plaintext);
	
	//Get both parts of public key
	size_t n,e;
	readKey(key_file,&n,&e);

	//Open file for storing ciphertext and then for each character of plaintext
	//do the encryption process and store to file
	FILE* outFile;
	if((outFile=fopen(output_file,"w"))==NULL){
		printf("Could not open file %s\n",output_file);
		exit(1);
	}

	for(int i=0;i<fLength;i++){
		size_t ciph=1;
		
		for (int j=0;j<e;j++){
			ciph=(plaintext[i]*ciph)%n;
		}
		fwrite(&ciph,8,1,outFile);
	}
	fclose(outFile);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{
	//Open input file for reading ciphertext and use ftell to find size
	FILE* inFile;
	if ((inFile=fopen(input_file,"r"))==NULL){
		printf("Could not open file %s",input_file);
		exit(1);
	}
	
	fseek(inFile, 0L, SEEK_END);
	long int fLength = ftell(inFile);
	
	//Get both parts of private key
	size_t n,d;
	readKey(key_file,&n,&d);

	//Open output file for storing decrypted data
	FILE* outFile;
	if((outFile=fopen(output_file,"w"))==NULL){
		printf("Could not open file %s\n",output_file);
		exit(1);
	}
	//Do the decryption process for every 8 bytes of ciphertext
	//Store to file
	size_t buf;
	for (int i=0;i<fLength/8;i++){
		fseek(inFile,sizeof(size_t)*i,SEEK_SET);
		fread(&buf,8,1,inFile);
		size_t plain=1;
		for (int j=0;j<d;j++){
			plain=(plain*buf)%n;
		}
		fwrite(&plain,1,1,outFile);
	}
	fclose(inFile);
	fclose(outFile);
}
