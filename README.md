# mew
mewtwo was a rust scanner with more features but this one is in c because everything uses c and c kernels have the vulns

Explanation:
Malware Signatures:

The malware_signatures array contains example byte patterns that the scanner will search for in memory. These signatures represent potential malware like NOP sleds, shellcode, and other malicious patterns.
Stack Canary:

A stack canary (STACK_CANARY) is used to detect stack overflow. Before and after significant operations (like scanning for malware), the canary is checked to ensure it hasn't been overwritten, which would indicate a stack overflow.
Memory Scanning:

The scan_for_malware function iterates through a given memory space, checking for the presence of any of the known malware signatures. If a match is found, it prints out the location of the detected signature.
Main Function:

The main function sets up a mock memory space and simulates the presence of a malware signature. It then checks for stack overflows, scans for malware, and checks the stack again after scanning.

Steps to Compile and Run the C File
Save the Code:

Create a new file named malware_scanner.c.
Copy and paste the C code provided into this file.
Compile the C Code:

Use a C compiler like gcc to compile the file. Open a terminal and navigate to the directory where the file is saved.
Run the following command to compile the code:
bash
Copy code
gcc -o mew mew.c
This command tells gcc to compile malware_scanner.c and output an executable named malware_scanner.
Run the Executable:

After compilation, run the executable by typing:
bash
Copy code
./mew
The program will then execute, performing the stack overflow check, scanning the simulated memory for malware, and printing the results to the terminal.
Summary:
File Name: mew.c
Compilation Command: gcc -o mew mew.c
Run Command: ./mew
This process will compile and execute the malware scanner in a C environment.
