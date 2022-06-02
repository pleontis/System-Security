#ifndef _UTILS_H
#define _UTILS_H

#include <stdio.h>
#include <stdlib.h>


/*
 * Prints the hex value of the input, 16 values per line
 *
 * arg0: data
 * arg1: data len
 */
void
print_hex(unsigned char *, size_t);


/*
 * Prints the input as string
 *
 * arg0: data
 * arg1: data len
 */
void
print_string(unsigned char *, size_t);


/*
 * Prints the usage message
 */
void
usage(void);


/*
 * Checks the validity of the arguments
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 * arg3: operation mode
 */
void
check_args(char *, char *, char *, int);


/************************ADDED FUNCTIONS************************/

/**
 * Prints numbers generated at keygen to files 
 * @param path File's path
 * @param key1_key2 Keys to store
 */
void
storeKey(const char*path,size_t key1, size_t key2);

/*
 * Read key parts n and e from key file and pass by reference to variables
*/
void readKey(char *key_file,size_t* key1, size_t* key2);

/**
 * Read contents of file and use pointer to get plaintext
 * 
 * @returns file's size
 */
int readFile(char* path,unsigned char** context);

/**
 * Stores content of bufer into file which path is given
 */
void writeFile(char* path, unsigned char* buffer,int length);

#endif /* _UTILS_H */
