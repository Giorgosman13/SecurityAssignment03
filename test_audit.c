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

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(filenames[i], strlen(filenames[i]), 1, file);
			fclose(file);
		}

	}


	/* add your code here */
/* --- 2. Open and modify under various conditions --- */
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
        printf("...Success (fopen failed as expected).\m");
    }

    // c) Create a file and remove its permissions
    printf("Attempting to access 'no_perms_file.txt'...\n");
    file = fopen("no_perms_file.txt", "w");
    if (file) {
        fwrite("data", 1, 4, file);
        fclose(file);
        
        // Remove all permissions (read/write/execute)
        chmod("no_perms_file.txt", 0000); // Mode 000
        printf("  (Set permissions for 'no_perms_file.txt' to 000)\n");

        // Attempt to read (should be denied)
        file = fopen("no_perms_file.txt", "r");
        if (file == NULL) {
            printf("...Success (read denied as expected).\n");
        }

        // Clean up: restore permissions so we can delete it
        chmod("no_perms_file.txt", 0644);
    }

    /* --- 4. Final Cleanup --- */
    printf("\n--- 4. Cleaning up test files ---\n");
    for (i = 0; i < 10; i++) {
        remove(filenames[i]);
    }
    remove("no_perms_file.txt");
    printf("Test complete. Check '/tmp/access_audit.log'.\n");

    return 0;
}
