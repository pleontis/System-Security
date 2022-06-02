#include<stdio.h>
#include <string.h>
#include "simple_crypto.h"


int main(int argc, char const *argv[])
{   
    char input[100], vigeneres_key[100];
    int ceasars_key;
    
    //Otp Encryption
    printf("[OTP] input: ");
    gets(input);
    char* otp_plaintext=otp_encrypt(input);
    otp_decrypt(otp_plaintext);

    //Ceasars Encryption 
    printf("[Ceasars] input: ");
    gets(input);
    printf("[Ceasars] key: ");
    scanf("%d", &ceasars_key);
    getc(stdin);
    char* ceasars_plaintext=ceasars_encrypt(input,ceasars_key);
    ceasars_decrypt(ceasars_plaintext,ceasars_key);

    //Vigeneres Encryption
    printf("[Vigeneres] input: ");
    gets(input);
    printf("[Vigeneres] key: ");
    gets(vigeneres_key);
    
    char* modifiedVigenKey=modifyVigeneresKey(strlen(input),vigeneres_key);
    char* vigeneres_plaintext=vigeneres_encrypt(input,modifiedVigenKey);
    vigeneres_decrypt(vigeneres_plaintext,modifiedVigenKey);
    
    return 0;
}