#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>
#include <sys/param.h>

/*Function for splitting array into parts using token*/
void split_array(char* array,char token[],char* parts[]);

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char* time; /* file access time */
	char* date;

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */
};

struct mods {
	int userID;
	int modifications;
};

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"

		   //Added functionality from Project 3 to Project 5
		   "-v, <number of files>, Prints the total number of files created in the last 20 minutes\n"
		   "-e, Prints all the files that were encrypted by the ransomware\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	size_t size = 0;
	ssize_t length = 0;
	char* line = NULL;
	int userID;
	int action_denied = 0;
	//Buffers for storing unecessary info from lines
	char buf1[20],buf2[20];
	char  filepath[255];
	int users[1000],malicious[1000];
	//Initialize array
	for(int i = 0 ; i < 100; i++) {
		users[i] = -1;
		malicious[i] = -1;
	}
	int numOfEntries = 0;
	int exists;
	struct entry en[100];  
	
length = getline(&line,&size,log);
while(length>=0) {

	if(strncmp(line,"User id", 7)==0)
		sscanf(line,"%s %s %d ", buf1,buf2,&userID);

	if(strncmp(line,"File path", 9)==0)
		sscanf(line,"%s %s %s ", buf1,buf2,filepath);

	if(strncmp(line,"Action-denied-flag", 18)==0) {
		if(line[20] == '1') {
			action_denied = 1;
			en[numOfEntries].uid = userID;

			//fill users array with possible malicious users
			if(users[0] == -1) { //if array is empty
				users[0] = userID;
			}else {
				exists = 0;
				for(int y = 0; users[y] != -1; y++) { //check if user already exists in array
					if(users[y] == userID) {
						exists = 1;
					}
				}

				if(exists == 0) { //if user does not exist, add him
					int index = 0;
					while(users[index]!=-1)
						index++;
					users[index]=userID;
				}
			}
			en[numOfEntries].file = strdup(filepath);
			numOfEntries++;	
		}
	}
	length = getline(&line,&size,log);
}

//check entry file for duplicates(same file accesed by same user)
for(int i = 0; i < numOfEntries; i++) {
	for(int j = i+1; j < numOfEntries; j++) {
		if( en[i].uid==en[j].uid && strcmp(en[i].file,en[j].file)==0) {
			en[j].uid = -1;
		}
	}
}

int numOfMalicious = 0;
//count malicious attempts
for(int i = 0; users[i]!=-1 ; i++) {
	int tries = 0;
	for(int j = 0; j < numOfEntries; j++){
		if((users[i]==en[j].uid) && (en[i].uid!=-1) ) {
			tries++;
			if(tries>=7) {
				malicious[numOfMalicious] = en[j].uid;
				numOfMalicious++;
				tries = 0;
			}
		}
		
	}
}

//print malicious users
int j=0;
for(int i=0;malicious[i]!=-1;i++){
	for (j=0;j<i; j++){
		if (malicious[i]==malicious[j])
			break;
	}
	if(i==j)
		printf("Malicious user with id: %d\n",malicious[i]);
}

free(line);
return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	size_t size = 0;
	ssize_t length = 0;
	char* line = NULL;
	int userID;
	//Buffers for storing unecessary info from lines
	char buf1[10],buf2[10];
	char filepath[255],fingerprint[20];
	struct entry en[1000];
	struct mods mod[1000];
	int users[100];
	//Initialize array
	for(int i=0;i< 100;i++) {
		users[i] = -1;
	}
	int numOfEntries = 0;
	int exists = 0;

	length = getline(&line,&size,log);

	while(length>=0) {

		if(strncmp(line,"User id", 7)==0)
			sscanf(line,"%s %s %d ", buf1,buf2,&userID);

		if(strncmp(line,"File path", 9)==0)
			sscanf(line,"%s %s %s ", buf1,buf2,filepath);


		if(strncmp(line,"Fingerprint", 11)==0 && strcmp(filepath,file_to_scan)==0) {
			sscanf(line,"%s %s", buf1,fingerprint);

			if(users[0] == -1) { //if array is empty
				users[0] = userID;
			}else{
				exists = 0;
				for(int i = 0; users[i] != -1; i++) { //check if user already exists in array
					if(users[i] == userID)
						exists = 1;
				}
				if(exists==0) { //if user does not exist, add him
					int index = 0;

					while(users[index]!=-1)
						index++;

					users[index] = userID;
				}
			}
			en[numOfEntries].fingerprint = strdup(fingerprint);
			en[numOfEntries].uid = userID;
			en[numOfEntries].file = strdup(filepath);
			numOfEntries++;
		}
		length = getline(&line,&size,log);
	}
	//If fingerprints are the same mark it
	for(int i=0; i<numOfEntries;i++) {
		for(int j=i+1;j< numOfEntries;j++) {
			if((en[i].fingerprint,en[j].fingerprint)==0){
				en[j].fingerprint = "DUPLICATE";
			}
		}
	}
	int numOfModUsrs=0;
	for(int i=0;users[i]!=-1;i++) {
		int modifications = 0;
		for(int j=1;j< numOfEntries;j++) {
			//If there is a different Fingerprint then consider as a modification
			if((en[j].uid==users[i]) && strcmp(en[j].fingerprint,"DUPLICATE")!=0) {
				mod[numOfModUsrs].userID = users[i];
				mod[numOfModUsrs].modifications++;
			}
		}
		numOfModUsrs++;
	}
	//Print users who have done modifications on file
	for(int i=0;i<numOfModUsrs;i++) {
		if(mod[i].modifications!= 0)
		printf("User with ID: %d Modifications made: %d\n",mod[i].userID,mod[i].modifications);
	}
	return;
}

void print_ransomware_encrypted(FILE* log){
	char* line=NULL;
	size_t n=0;
	ssize_t length=getline(&line,&n,log);
	int counter=0;
	char *path[2],buf1[10],buf2[10];
	
	//For each line in file_logging.log
	while (length>=0){
		if(strncmp(line,"File path",9)==0){
			char *buf_line=malloc(sizeof(char)*strlen(line));
			strcpy(buf_line,(const char*)line);
			//Split line in 2 elements. Second element is file's path
			split_array(buf_line,":",path);
		}
		if(strncmp(line,"Access type",11)==0){
			if(line[13]=='0'){
				char *typeOfFile[3]={0};

				char* buf_line=malloc(sizeof(char)*strlen(line));
				strcpy(buf_line,(const char*)path[1]);
				
				//Get only extension of file. Skip its name
				split_array(buf_line,".",typeOfFile);

				if(typeOfFile[2]!=NULL){
					//File extension is .encrypt so it was created by ransomware
					//Count it as a file creation
					if (strcmp(typeOfFile[2],"encrypt\n")==0){
						counter+=1;
						printf("%s\n",path[1]);
					}
				}
			}
		}
		//Read next line
		length=getline(&line,&n,log);
	}
	printf("Number of files encrypted: %d\n",counter);
}

void split_array(char* array,char token[],char* parts[]){
	char *p = strtok (array, token);
	int i=0;
	while(p!=NULL){
		parts[i++]=p;
		p=strtok(NULL,token);
	}
}

// Check if more than (flagship) files were created
void file_creation_check(FILE* log,int flagship){
	
	time_t current_time= time(NULL);
	struct tm tm = *localtime(&current_time);

	char* stamp[3];
	int day,month,year,hours,minutes;
	char buf1[10];

	char*line=NULL;
	size_t n=0;
	ssize_t length=getline(&line,&n,log);

	int counter=0;
	//For each line in file_logging.log
	while (length>=0){
		if(strncmp(line,"Time",4)==0){
			//Get hours and minutes difference between file creation and present
			split_array(line,":",stamp);
			hours=tm.tm_hour-atoi(stamp[1]);
			minutes=tm.tm_min-atoi(stamp[2]);
		}
		if(strncmp(line,"Date",4)==0){
			char *buffer[2];
			split_array(line,":",buffer);
			split_array(buffer[1],"/",stamp);
			//Get day month and year for comparison
			day=atoi(stamp[0]);
			month=atoi(stamp[1]);
			year=atoi(stamp[2]);
		}
		if(strncmp(line,"Access type",11)==0){
			if(line[13]=='0'){
				//If file was created in the last 20 minutes increase counter
				if(year==tm.tm_year+1900 && month==tm.tm_mon+1 && day==tm.tm_mday){
					if ( (hours==0 && minutes<=20) || (minutes<=-40 && hours==1))
						counter+=1;
				}
			}
		}
		//Read next line
		length=getline(&line,&n,log);
	}	
	if(counter>=flagship)
		printf("There were created more than %d files. (%d Files)\n",flagship,counter);
	else
		printf("There were created less than %d files. (%d Files)\n",flagship,counter);
}

int 
main(int argc, char *argv[])
{
	int ch;
	char* flag;
	FILE *log;
	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}
	while ((ch = getopt(argc, argv, "himev")) != -1) {
		switch (ch) {		
		case 'i':
			printf("_____FILE MODIFICATIONS ON FILE '%s' ____\n",optarg);
			list_file_modifications(log,optarg);
			break;
		case 'm':
			printf("_____MALICIOUS USERS_____\n");
			list_unauthorized_accesses(log);
			break;
		case 'v':
			flag=argv[2];
			int flag_to_num=atoi(flag);
			printf("CHECK IF MORE THAN %d FILES WERE CREATED IN THE LAST 20 MINUTES\n",flag_to_num);
			file_creation_check(log,flag_to_num);
			break;
		case 'e':
			printf(" FILES THAT WERE ENCRYPTED BY THE RANSOMWARE\n");
			print_ransomware_encrypted(log);
			break;
		default:
			usage();
		}
	}
	fclose(log);
	argc -= optind;
	argv += optind;	
	return 0;
}