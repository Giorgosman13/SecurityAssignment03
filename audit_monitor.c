#define _POSIX_C_SOURCE 200809L

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <linux/limits.h>

#define MAX_LOGS 256
#define HASH_LEN 65
#define LOG_LINE 2048
#define SUSPICIOUS_DENIED 5
#define MAX_FILES_DENIED 25
#define MAX_USERS 256
#define LOG_FILE_PATH "/tmp/access_audit.log" 

typedef struct{
	int uid;
	int num_denied;
	char* files_denied[MAX_FILES_DENIED];
	int num_modify;
}User;

typedef struct{

	int uid; /* user id (positive integer) */
	pid_t pid; /* process id (positive integer) */

	char file[PATH_MAX]; /* filename (string) */

	char date[32]; /* file access date - utc*/
	char time[32]; /* file access time - utc*/

	int operation; /* access type values [0-3] */
	int action_denied; /* is action denied values [0-1] */

	char filehash[HASH_LEN]; /* file hash - sha256 - evp */

}log_entry;

//returns the number of logs put in the array in the 2nd parameter
int parse_log_file(FILE* log, log_entry* log_array){
	int num=0;
	char line[LOG_LINE];
	char file_buf[PATH_MAX];
	char date_buf[32];
    char time_buf[32];
    char hash_buf[128];

	rewind(log);

	while(fgets(line, sizeof(line), log)!=NULL){
		int check = sscanf(line, "%d,%d,\"%[^\"]\",%[^,],%[^,],%d,%d,%s", 
            &log_array[num].uid, 
            &log_array[num].pid, 
            file_buf,      // Read into temp buffer
            date_buf,      // Read into temp buffer
            time_buf,      // Read into temp buffer
            &log_array[num].operation, 
            &log_array[num].action_denied, 
            hash_buf       // Read into temp buffer
        );
		if (check<8){
			printf("Line #%d is malformed, %d\n", num+1, check);
		}
		strcpy(log_array[num].file, file_buf);
		strcpy(log_array[num].date, date_buf);
		strcpy(log_array[num].time, time_buf);
		strcpy(log_array[num].filehash, hash_buf);

		num++;
	}
	return num;
}

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./audit_monitor \n"
		   "Options:\n"
		   "-s, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	log_entry log_array[MAX_LOGS];
	int num_of_Logs = parse_log_file(log, log_array);
	User denied_users[MAX_USERS];
	memset(denied_users, 0, sizeof(denied_users));
	int current_denied_users=0;
	int flag,exists=0;

	for(int i = 0; i < num_of_Logs;i++){
		if(log_array[i].action_denied==1){
			for(int j=0; j< current_denied_users;j++){
				if(denied_users[j].uid==log_array[i].uid){
					exists = 1;
					for(int z=0; z<denied_users[j].num_denied;z++){
						if(strcmp(log_array[i].file, denied_users[j].files_denied[z])==0){
							flag=1;
							break;
						}
					}
					if(flag == 0){
						denied_users[j].num_denied ++;
						denied_users[j].files_denied[denied_users[j].num_denied-1]= log_array[i].file;
						break;
					}else{
						flag=0;
						break;
					}
				}
			}
			if(exists==0){
				denied_users[current_denied_users].uid = log_array[i].uid;
				denied_users[current_denied_users].num_denied =1;
				denied_users[current_denied_users].files_denied[denied_users[current_denied_users].num_denied-1]= log_array[i].file;
				current_denied_users++;
			}else{
				exists==0;
			}
		}
	}
	
	if(current_denied_users>0){
		for(int i=0; i<current_denied_users;i++){
			if(denied_users[i].num_denied>SUSPICIOUS_DENIED){
				printf("%d\n", denied_users[i].uid);
			}
		}
	}
	return;
}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	log_entry log_array[MAX_LOGS];
	int num_of_Logs = parse_log_file(log, log_array);
	User user_list[MAX_USERS];
	memset(user_list, 0, sizeof(user_list));
	int current_users=0;
	int user_exists = 0;
	
	for(int i=0; i< num_of_Logs;i++){
		char* filename = basename(strdup(log_array[i].file));
		if(strcmp(file_to_scan, filename)==0 && log_array->action_denied ==0){
			user_exists=0;
			for(int j=0;j< current_users;j++){
				if(user_list[j].uid==log_array[i].uid){
					user_exists=1;
					if(log_array[i].operation==2){
						user_list[j].num_modify++;
					}
					break;
				}
			}
			if(user_exists==0){
				user_list[current_users].uid= log_array[i].uid;
				if(log_array[i].operation == 2){
					user_list[current_users].num_modify = 1;
				}else{
					user_list[current_users].num_modify = 0;
				}
				current_users++;
			}	
		}
	}
	if(current_users>0){
		printf("Uid's || Num of accesses\n");
		for(int i=0;i<current_users;i++){
			printf("%d    ||%d\n",user_list[i].uid,user_list[i].num_modify);
		}
	}else {
		printf("No mods found!!\n");
	}

	return;

}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen(LOG_FILE_PATH, "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./access_audit.log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:s")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 's':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
