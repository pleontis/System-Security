#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <fcntl.h>
#include "simple_crypto.h"

//Global variable for usage between functions
char otp_key [100];

char* otp_encrypt(char plaintext[]){
    int j=0;
    char editStr[100], cipher[100];
    //Check for each character of user's text if it belongs into wanted range
    //Create editStr array with only wanted characters
    for (int i=0,j=0;i<plaintext[i]!='\0';i++){
        if(plaintext[i]>='0' && plaintext[i]<='9' || plaintext[i]>='A' && plaintext[i]<='Z' || plaintext[i]>='a' && plaintext[i]<='z'){
            editStr[j]=plaintext[i];
            j++;
        }
    }
    //Create random key
    createOtpKey(plaintext);
    //Xor each character of plaintext with key
    for (int i = 0; i <strlen(editStr); i++){
        plaintext[i]=editStr[i]^otp_key[i];
    }
    //Print results and return encrypted msg
    printf("[OTP] encrypted: ");
    checkIfPrintable(plaintext);

    return plaintext;
}
void otp_decrypt(char plaintext[]){
    char decrypted[100];
    //XOR each character of encrypted msg with each key character
    for (int i=0;i<strlen(plaintext);i++){
        decrypted[i]=plaintext[i]^otp_key[i];
    }
    decrypted[strlen(plaintext)]='\0';
    //Print results
    printf("[OTP] decrypted: ");
    checkIfPrintable(decrypted);
}
void checkIfPrintable(char txt[]){
    for (int i=0;i<strlen(txt);i++){
        //Dec numbers of ASCII printable characters
        if(txt[i]>33 && txt[i]<126){
            printf("%c", txt[i]);
        }
        else{
            //Print as hex
            printf("%x", txt[i]);
        }
    }
    printf("\n");
}
void createOtpKey(char plaintext[]){
    int data = open("/dev/urandom", O_RDONLY);
    int otp_keySize=strlen(plaintext);
    if (data<0){
        printf("Error occured while opening urandom");
    }
    else{
        char key [otp_keySize];
        ssize_t res = read(data,key,sizeof(key));
        if (res<0){
            printf("Could not generate a random key");
        }
        for (int i = 0; i<otp_keySize; i++){
            otp_key[i]=key[i];
        }
        otp_key[otp_keySize]='\0';
    }
}
char* ceasars_encrypt(char plaintext[], int key){
    char character;
    //Read each character of plaintext and check if it is 0-9 or a-z or A-Z
    //If encrypted value gets out or range then move cyclic ex. 'z'+2='b'  '8'+'3'='1'
    for (int i=0;plaintext[i]!='\0';++i){
        character=plaintext[i];
        if (character>='0' && character<='9'){
            character=character+key;
            if (character>'9'){
                character=character-'9'+'0'-1;
            }
            plaintext[i]=character;
        }
        else if (character>='a' && character<='z'){
            character=character+key;
            if (character>'z'){
                character=character-'z'+'a'-1;
            }
            plaintext[i]=character;
        }
        else if (character>='A' && character<='Z'){
            character=character+key;
            if (character>'Z'){
                character=character-'Z'+'A'-1;
            }
            plaintext[i]=character;
        }
    }
    //Print results and return encrypted msg
    printf("[Ceasars] encrypted: %s\n", plaintext);
    return plaintext;
}
void ceasars_decrypt(char plaintext[], int key){
    char character;
    //For each character of plain text subtract key and calculate origin value 
    //doing opossite of encryption process
    for(int i=0; plaintext[i]!='\0';i++){
        character=plaintext[i];
        if (character>='0' && character<='9'){
            character=character-key;
            if (character<'0'){
                character=character+'9'-'0'+1;
            }
            plaintext[i]=character;
        }
        else if (character>='a' && character<='z'){
            character=character-key;
            if (character<'a'){
                character=character+'z'-'a'+1;
            }
            plaintext[i]=character;       
        }
        else if (character>='A' && character<='Z'){
            character=character-key;
            if (character<'A'){
                character=character+'Z'-'A'+1;
            }
            plaintext[i]=character;
        }
    }
    printf("[Ceasars] decrypted: %s\n", plaintext);
}
char* vigeneres_encrypt(char plaintext[], char key[]){
    int sizeOfText=0;
    char editStr[strlen(plaintext)];
    //Check if there is a char 'a'-'z' and convert into capital letter
    for (int i=0;plaintext[i]!='\0';i++){
        if(plaintext[i]>='A' && plaintext[i]<='Z' || plaintext[i]>='a' && plaintext[i]<='z'){
            editStr[i]=toupper(plaintext[i]);
            sizeOfText++;
        }
    }
    //Encrypt array with wanted characters        
    for (int i = 0; i <sizeOfText; i++){
        plaintext[i]=((editStr[i]+key[i])%26 )+'A';
    }
    //Print results and return encrypted msg
    plaintext[strlen(editStr)]='\0';
    printf("[Vigeneres] encrypted: %s\n", plaintext);
    return plaintext;
}
void vigeneres_decrypt(char plaintext[], char key []){
    char decrypMsg[strlen(plaintext)+1];
    //Decrypt based on encryption implementation and print decrypted msg
    for (int i=0;i<strlen(plaintext);i++){
        decrypMsg[i]=(plaintext[i]-key[i]+26)%26 +'A';
    }
    decrypMsg[strlen(plaintext)]='\0';
    printf("[Vigeneres] decrypted: %s\n", decrypMsg);
}
char* modifyVigeneresKey(int textLength, char key[]){
    char *modifiedKey=malloc(sizeof(char)*textLength);
    for (int i=0;i <textLength;i++)
    {
        if (textLength>strlen(key)){
            //Keep writing the same key at the end of array until reaching
            //plaintext's length
            modifiedKey[i]=key[i%strlen(key)];
        }
        else{
            modifiedKey[i]=key[i];
        }   
    }
    return modifiedKey;
}