Assignment 03 - Access Control Logging 

Students : Giorgos Vassalos 2022030052
           Asterios Agiannis 2022030164

To run this assignment type "make all" on the terminal then LD_PRELOAD=./audit_logger.so ./test_audit.
Finally use the audit_monitor functions and see the results : 

./audit_monitor -s should print on the terminal: 1000 (current user id).

./audit_monitor -i file_0 should print : Uid's || Num of accesses
                                         1000  ||1

./audit_monitor -i file_1 should print : Uid's || Num of accesses
                                         1000  ||0

So let's start talking about each step and how it is implemented:

Step 1: Audit Logging Library 

In this step we need to make overriden functions for fopen(), fwrite() and fclose().

To do that we use the LD_PRELOAD mechanism and we write the code for each in audit_logger.c. Here we create helper functions such as a function that does the hash of the file,
a function that gets the full path by giving it just the file pointer and finally a function that writes the log giving it the path of the file we open/ write/ close, the 
operation we do, if it was denied and the hash of the file.

In fopen before we use the original opening function we check if the file existed to be able to differentiate from creation and opening of the file. We also use the return value
of the original fopen to know if the fopen was denied. Then we pass each of these values to the log_event function which writes the txt file. We return the pointer at the end.

In fwrite we create a hash of zeros since many times fwrite is called more than once and creating a hash for each char we send would be pointless and hit performance hard.
So we create this buffer hash and find out if writing was denied by comparing the return of the original fwrite with the size of the data that should've been written.

In fclose we create the hash of the file before we close it and then pass the hash of the file in the log_event. We put the operation as 3 and depending on the return value of
the original fclose we decide if it was denied or not.

Step 2: Audit Log Analyzer

This file contains 2 functions the list_unauthiruzed_accesses and list_file_modifications. To them we add 2 structs the User struct and the log_entry struct.
The user struct is helpful to keep for every uid the times it's denied or has modified a file as well as the names of the file it has been denied from.
The Log_entry struct contains the parameters of a log parsed in different variables.

We also made a helper function parse_log_file which reads each log line and parses the data into a struct array of log_entries

For list unauthorized accesses we just need to check every log entry and find out which users with a certain uid have been denied access to more than 5 different files
They are deemed suspicious and their ids are printed on the screen with the usage of ./audit_monitor -same


For listing file modifications we just need to check every log entry to find which users and how many times have they modified a file with the name given as a parameter.
Each user having interaction with the file will have their uids displayed and each will have a number next to them being how many times they have used fwrite on the file.
The command we use is ./audit_monitor -i <filename>

Step 3: Testing the Audit System

In this step we created 9 files and then we do various modifications to them e.g. we write in file_0, we open file_1 
Then we force denied actions. We try to open non-existant files and then we try to open files in root which should be inaccessible from our ptogram and finally we try to open
more files that are protected. Finally we delete all the files we created running the file.