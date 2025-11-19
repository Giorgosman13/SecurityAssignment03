#include <stdio.h>
#include <string.h>


int main() 
{

	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};



	/* example source code */
    printf("\n--- 1. Creating files and then closing them ---\n");   
	for (i = 0; i < 10; i++) {
		file = fopen(filenames[i], "w+");
		fclose(file);
	}

    printf("\n--- 2. Modifying files under various conditions ---\n");

    // Append to file_0
    printf("Appending to file_0...\n");
    file = fopen("file_0", "a");
    if (file) {
        fwrite("...appending new data.", 1, 21, file);
        fclose(file);
    }

    // Read from file_1 (no writing)
    printf("Reading from file_1...\n");
    file = fopen("file_1", "r");
    if (file) {
        // We don't need to actually read, just log the open/close
        fclose(file);
    }

    /* --- 3. Attempt to open files without permissions --- */
    printf("\n--- 3. Forcing 'Denied' actions ---\n");

    // a) Try to read a non-existent file
    printf("Attempting to read 'non_existent_file.txt'...\n");
    file = fopen("non_existent_file.txt", "r");
    if (file == NULL) {
        printf("...Success (fopen failed as expected).\n");
    }

    // b) Try to write to a protected directory (e.g., /root)
    printf("Attempting to write to '/root/protected_test.txt'...\n");
    file = fopen("/root/protected_test.txt", "w");
    if (file == NULL) {
        printf("...Success (fopen failed as expected).\n");
    }

    printf("Attempting a denied action 4 times to create a suspicious user\n");
    char protected_files[6][64] = {
        "/etc/shadow_denied_1",
        "/etc/shadow_denied_2",
        "/etc/shadow_denied_3",
        "/root/secret_denied_4",
        "/root/secret_denied_5",
        "/proc/kcore_denied_6" // Total 6 unique denied accesses for the current user
    };
    for(int i=0 ; i<5 ; i++){
        file = fopen(protected_files[i], "r");
        if (file == NULL) {
            printf("...Success (fopen failed as expected).\n");
        }
    }
    /* --- 4. Final Cleanup --- */
    printf("\n--- 4. Cleaning up test files ---\n");
    for (i = 0; i < 10; i++) {
        remove(filenames[i]);
    }
    printf("Test complete. Check '/tmp/access_audit.log'.\n");

    return 0;
}
