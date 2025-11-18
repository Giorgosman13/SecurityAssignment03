#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/evp.h> //install the required package

#define LOG_FILE_LOCATION "/tmp/access_audit.log"

void sha256_hashing(const char *filename, char* rt_hash){
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	
	int *(*original_fclose)(FILE*);
	/* call the original fclose function */
	original_fclose = dlsym(RTLD_NEXT, "fclose");
	
	memset(rt_hash, '0', EVP_MAX_MD_SIZE*2);
	rt_hash[EVP_MAX_MD_SIZE*2]= '\0';

	FILE* hashableFile = (*original_fopen)(filename, "rb");
	if(hashableFile==NULL){
		return;
	}

	EVP_MD_CTX* evp_ctx = EVP_MD_CTX_new();
	const EVP_MD *md = EVP_sha256();

	unsigned char buf[4096];
	size_t bytes_read;
	unsigned char hash[EVP_MAX_MD_SIZE];
	unsigned int hash_l=0;

	EVP_DigestInit_ex(evp_ctx, md, NULL);

	while ((bytes_read = fread(buf, 1, 4096, hashableFile)) > 0) {
        if (EVP_DigestUpdate(evp_ctx, buf, bytes_read) != 1) {
            handle_openssl_errors();
        }
    }

	EVP_DigestFinal_ex(evp_ctx, hash, &hash_l);

	// Convert binary hash to hexadecimal string (64 characters)
    for (unsigned int i = 0; i < hash_l; i++) {
        sprintf(&rt_hash[i * 2], "%02x", hash[i]);
    }

    EVP_MD_CTX_free(evp_ctx);
    (*original_fclose)(hashableFile);
}

char* getPathFromFile(FILE* fp){
	char fd_path[PATH_MAX];
	int fd = fileno(fp);
	if(fd<0){
		printf("File doesnt exist");
		return NULL;
	}

	snprintf(fd_path, PATH_MAX, "/proc/self/fd/%d", fd);

	char* filename = (char *)malloc(PATH_MAX);
    if (filename == NULL) {
        perror("malloc failed");
        return NULL;
    }

    int n = readlink(fd_path, filename, PATH_MAX - 1);
    if (n < 0) {
        perror("readlink failed");
        free(filename);
        return NULL;
    }
    
    filename[n] = '\0';
    return filename;
}

void log_event(const char *path, int operation, int denied_flag, const char* hash){
	FILE *(*original_fopen)(const char*, const char*);

	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");

	size_t *(*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	
	int *(*original_fclose)(FILE*);
	/* call the original fclose function */
	original_fclose = dlsym(RTLD_NEXT, "fclose");

	FILE* audit_log = (*original_fopen)(LOG_FILE_LOCATION, "a");
	if(audit_log==NULL){
		return;
	}

	uid_t uid = getuid();
	pid_t pid = getpid();

	char absolute_path[PATH_MAX];
	if(realpath(path, absolute_path)==NULL){
		strncpy(absolute_path, path, PATH_MAX-1);
		absolute_path[PATH_MAX]= '\0';
	}

    time_t now = time(NULL);
    struct tm *t = gmtime(&now); 
    char date_buf[11];
    char time_buf[9];
    strftime(date_buf, sizeof(date_buf), "%Y-%m-%d", t);
    strftime(time_buf, sizeof(time_buf), "%H:%M:%S", t);

	char log_entry[PATH_MAX + EVP_MAX_MD_SIZE*2 + 200];
	int len = snprintf(log_entry, sizeof(log_entry), 
                       "%d,%d,\"%s\",%s,%s,%d,%d,%s\n", 
                       uid, pid, absolute_path, date_buf, time_buf, 
                       operation, denied_flag, hash);

    original_fwrite(log_entry, 1, len, audit_log);
    original_fclose(audit_log);
}

FILE *
fopen(const char *path, const char *mode) 
{
	char hash[EVP_MAX_MD_SIZE*2+1];
	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);

	sha256_hashing(path, hash);
	int operation = 0;
	struct stat st;

	int file_exists = stat(path,&st)==0;
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	/* add your code here */
	int denied = 0;

	if(original_fopen_ret == NULL){
		denied = 1; 
	}else{
		if(file_exists == 0){
			operation = 1;
		}else{
			operation = 0;
		}
		denied = 0;
	}
	
  
    log_event(path, operation, denied, hash);


	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	char* path = getPathFromFile(stream);

	char buf[EVP_MAX_MD_SIZE*2 + 1];
    memset(buf, '0', EVP_MAX_MD_SIZE*2);
    buf[EVP_MAX_MD_SIZE*2+1] = '\0';

	/* add your code here */
	int denied = (original_fwrite_ret < size*nmemb);

	log_event(path, 2 ,denied, buf);

	free(path);
	//in fwrite we dont keep hash log since it hits performance hard
	return original_fwrite_ret;
}


int 
fclose(FILE *stream)
{

	int original_fclose_ret;
	int (*original_fclose)(FILE*);

	char *path= getPathFromFile(stream);
	char hash[EVP_MAX_MD_SIZE*2+1];
	sha256_hashing(path, hash);

	/* call the original fclose function */
	original_fclose = dlsym(RTLD_NEXT, "fclose");
	original_fclose_ret = (*original_fclose)(stream);


	/* add your code here */
	if(original_fclose_ret==0){
		log_event(path, 3, 0, hash);
	}else{
		log_event(path, 3, 1, hash);
		printf("closing failed");
	}
	free(path);
	return original_fclose_ret;
}