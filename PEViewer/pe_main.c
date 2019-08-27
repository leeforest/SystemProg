#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <stdlib.h>
#include "pe_structure.h"

int main(int argc, char *argv[])
{
	int machine;
	char* option = argv[1];
	char* file_name = argv[2];

	// Option Check
	if (argc < 2 || (strcmp(option, "-p") == 1 && strcmp(option, "-f") == 1))
	{
		printf("Usage: PEVIEW.exe -[p/f] [filename]\n");
		exit(1);
	}
	printf("******************************************************************************************\n\n");
	printf("******************************************************************************************\n");
	printf("*                                     PEVIEW                                             *\n");
	printf("*                                                                                        *\n");
	printf("*  Usage: PEVIEW.exe -[p/f] [filename]                                                   *\n");
	printf("*  -p: Print in console                                                                  *\n");
	printf("*  -f: Store in file                                                                     *\n");
	printf("******************************************************************************************\n\n");
	printf("[-] File Name: %s\n", file_name);

	machine=check_exe(file_name);

	if (machine == 32 && strcmp(option,"-p")==0)
	{
		pe_print_32(file_name, option);
	}
	if (machine == 32 && strcmp(option, "-f") == 0)
	{
		pe_store_32(file_name, option);
	}
	if (machine == 64 && strcmp(option, "-p") == 0)
	{
		pe_print_64(file_name, option);
	}
	if (machine == 64 && strcmp(option, "-f") == 0)
	{
		pe_store_64(file_name, option);
	}
	
	system("pause");
	//pe_store(file_name);

	return 0;
}