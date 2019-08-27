#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include <fcntl.h>
#include "pe_structure.h"

int check_exe(char* file)
{
	FILE* pfile_= "";
	FILE* pfile = "";
	size_t result;
	int machine;
	long file_size;
	int fd;
	unsigned char* buffer;

	pfile = fopen(file, "rb");
	if (pfile == NULL)
	{
		fputs("File open error\n", stderr);
		exit(1);
	}
	fseek(pfile, 0, SEEK_END);
	file_size = ftell(pfile);
	rewind(pfile);
	buffer = malloc(file_size);
	if (buffer == NULL)
	{
		fputs("Memory Allocation Error", stderr);
		exit(1);
	}
	result = fread(buffer, sizeof(char), file_size, pfile);
	

	// 파일을 읽어들일 buffer에 파일 사이즈만큼 메모리를 할당함
	/*
	buffer = malloc(file_size);
	if (buffer == NULL)
	{
		fputs("Memory Allocation Error", stderr);
		exit(1);
	}
	result = fread(buffer, sizeof(char), file_size, pfile);
	*/
	// x32 x64 확인
	struct _MY_IMAGE_DOS_HEADER *idh = malloc(sizeof(struct _MY_IMAGE_DOS_HEADER));
	idh = buffer;

	struct _MY_IMAGE_FILE_HEADER *ifh = malloc(sizeof(struct _MY_IMAGE_FILE_HEADER));
	ifh = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE);

	struct TMP *tmp = malloc(sizeof(struct TMP));
	tmp->tmp_1 = 0x14c;
	tmp->tmp_2 = 0x8664;
	tmp->tmp_3 = 0x200;

	if ((int)ifh->Machine>500)
	{
		printf("[-] Architecture: x64\n");
		machine=64;
	}
	else
	{
		printf("[-] Architecture: x32\n");
		machine = 32;
	}

	fclose(pfile);

	pfile = fopen(file, "rb");
	if (pfile == NULL)
	{
		fputs("File open error\n", stderr);
		exit(1);
	}
	fseek(pfile, 0, SEEK_END);
	file_size = ftell(pfile);
	rewind(pfile);

	// memory alloc
	char* mz_signature = malloc(2);
	if (mz_signature == NULL) 
	{ 
		fputs("Memory error", stderr); 
		exit(1); 
	}

	// file read check
	result = fread(mz_signature, 1, 2, pfile);
	if (result != 2) 
	{ 
		fputs("Reading error\n", stderr); 
		exit(1); 
	}

	// PE check(MZ)
	char* exetension = strrchr(file, '.');
	if (memcmp(mz_signature, "MZ", 2))
	{
		printf("[-] PE Check: invalid\n");
		exit(1);
	}
	else
	{
		printf("[-] PE Check: valid\n");
	}

	fclose(pfile);
	free(mz_signature);
	
	return machine;
}
