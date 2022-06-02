#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>
#include <sys/fsuid.h>
#include <sys/param.h>

/*Function for writting stats into "file_logging.log"*/
void printLog(int uid, const char* path,struct tm tstamp, int access_type,int action_denied,FILE* log, unsigned char* md);

FILE *
fopen(const char *path, const char *mode) 
{
	//Check for file's existance
	int acc = access(path, F_OK); 

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);

	FILE* log ;
	if((log=original_fopen("./file_logging.log", "a"))==NULL) {
		printf("Error during Log File opening\n");
		exit(1);
	}

	int uid= getuid();
	
	time_t current_time= time(NULL);
	struct tm tm = *localtime(&current_time);
	
	int access_type;
	int action_denied = 0;
	unsigned char* md5 = NULL;

	if(errno==EACCES) { //file exists but we have no access
		action_denied = 1;
		access_type = 1;
		printLog(uid,path,tm,access_type,action_denied,log,md5);
	}

	if((acc!= -1)&&(action_denied==0)){ //file exists and we have access

		long length;
		unsigned char * buf = 0;

		FILE* fp ;
		if((fp=original_fopen(path,"r"))!=NULL){
		
			fseek (fp, 0, SEEK_END);
  			length = ftell (fp);
			fseek (fp, 0, SEEK_SET);
			
			buf = malloc (length);
  			if (buf)
    			fread (buf,1,length, fp);
  			
  			fclose (fp);
			//Create fingerprint
			md5 = MD5(buf,length,md5); 
		}
		access_type = 1;
		printLog(uid,path,tm,access_type,action_denied,log,md5);
		free(buf);
	}else{
		if(errno==ENOENT && (strcmp(mode,"w")==0||strcmp(mode,"wb")==0||strcmp(mode,"a")==0||strcmp(mode,"ab")==0)){
			//File does not exist but it gets created due to the mode
			access_type = 0;
			printLog(uid,path,tm,access_type,action_denied,log,md5);
		}
	}
	fclose(log);
	return original_fopen_ret;
}

size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	// call the original fwrite function 
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	FILE *log;
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	if((log=(original_fopen)("./file_logging.log", "a"))==NULL) {
		printf("Error during Log File opening\n");
		exit(1);
	}

	int uid = getuid();
	time_t current_time=time(NULL);
	struct tm tm = *localtime(&current_time);
	int access_type = 2;
	int action_denied = 0;

	char buf[MAXPATHLEN];
	//Fill with 0
    char filepath[MAXPATHLEN]={0};

	//Create Fingerprint
	unsigned char* md5= NULL;
	md5=MD5(ptr,nmemb,md5);
    //Get file descriptor and then get path
	int fd = fileno(stream); 
	sprintf(buf, "/proc/self/fd/%d", fd);
    readlink(buf, filepath, sizeof(filepath)-1);
	
	//Split string using token "/"
   	char *token,*fname;
   	token = strtok(filepath, "/");

    while( token != NULL ) {
	  fname = token;
      token = strtok(NULL, "/");
   	}

	printLog(uid,fname,tm,access_type,action_denied,log,md5);
	fclose(log);
	return original_fwrite_ret;
}

void printLog(int uid, const char* path,struct tm tstamp, int access_type,int action_denied,FILE* log, unsigned char* md) {
	char* fing = "Fingerprint ";
	fprintf(log,"User id: %d\n",uid);
	fprintf(log,"File path: %s\n",path);
	fprintf(log,"Date: %d/%d/%d\n",tstamp.tm_mday,tstamp.tm_mon+1,tstamp.tm_year+1900);
	fprintf(log,"Time: %d",tstamp.tm_hour);
	if(tstamp.tm_min<10)
		fprintf(log,":0%d\n",tstamp.tm_min);
	else
		fprintf(log,":%d\n",tstamp.tm_min);		
	fprintf(log,"Access type: %d\n",access_type);
	fprintf(log,"Action-denied-flag: %d\n", action_denied);
	fprintf(log,"%s",fing);
	if(md!=NULL) {
		for(int i = 0 ; i < sizeof(md);i++){
			fprintf(log,"%x", md[i]);
		}
	}else{
		fprintf(log,"0");
	}
	fprintf(log,"\n");
}