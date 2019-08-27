#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include "pe_structure.h"

// 32 exe store option _ check v
int pe_store_32(char* file, char* option)
{
	int i = 0;
	int j = 0;
	int k = 0;
	int tmp_1;
	int tmp_2;
	int tmp_3;
	int min = 0;
	int res = 0;
	int import_count = 0;
	int eat_section = 0;
	int iat_section = 0;
	int arr_num;
	int index = 0;
	char *tmp;
	long file_size;
	long *file_offset;
	unsigned char *buffer;
	FILE* pfile;
	FILE* wfile;
	FILE* wfile_;
	size_t result;

	// 파일을 'rb' 모드로 열기
	pfile = fopen(file, "rb");
	if (pfile == NULL)
	{
		fputs("File open error\n", stderr);
		exit(1);
	}
	fseek(pfile, 0, SEEK_END);
	file_size = ftell(pfile);
	rewind(pfile);

	// 파일을 읽어들일 buffer에 파일 사이즈만큼 메모리를 할당함
	buffer = malloc(file_size);
	if (buffer == NULL)
	{
		fputs("Memory Allocation Error", stderr);
		exit(1);
	}

	printf("\n[-] PE Parsing Start...\n");

	// 입력으로 들어온 실행파일을 읽어서 buffer에 저장함(buffer가 가리키는 곳에 파일 데이터가 있는 것)
	result = fread(buffer, sizeof(char), file_size, pfile);
	fclose(pfile);

	/* 구조체 포인터 변수 선언 */
	/* 각 헤더 구조체의 포인터 변수를 선언하고 buffer를 기점으로 (buffer + ~) 헤더 시작 위치를 파악함 */
	// IMAGE_DOS_HEADER
	struct _MY_IMAGE_DOS_HEADER *idh = malloc(sizeof(struct _MY_IMAGE_DOS_HEADER));
	idh = buffer;

	// IMAGE_NT_HEADERS // Signature
	// IMAGE_NT_HEADERS의 시작주소는 IMAGE_DOS_HEADER의 e_lfanew에 저장되어 있음(=IMAGE_NT_HEADERS.Signature의 시작주소)
	struct _MY_SIGNATURE *sgt = malloc(sizeof(struct _MY_SIGNATURE));
	sgt = buffer + (idh->e_lfanew);

	// IMAGE_NT_HEADERS // IMAGE_FILE_HEADER
	// IMAGE_FILE_EHADER는 Signature가 끝나고 시작됨
	struct _MY_IMAGE_FILE_HEADER *ifh = malloc(sizeof(struct _MY_IMAGE_FILE_HEADER));
	ifh = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE);

	// IMAGE_NT_HEADERS // IMAGE_OPTIONAL_HEADER
	// IMAGE_OPTIONAL_HEADER는 IMAGE_FILE_EHADE가 끝나고 시작됨
	struct _MY_IMAGE_OPTIONAL_HEADER *ioh = malloc(sizeof(struct _MY_IMAGE_OPTIONAL_HEADER));
	ioh = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER);
	arr_num = ioh->DataDirectory[1].Size / sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR);

	// IMGAE_SECTION_HEADER
	// IMGAE_SECTION_HEADER는 하나 이상이므로 배열을 쓰기 위해 이중 포인터로 선언
	// IMAGE_SECTION_HEADER * 섹션 수(ifh->NumberOfSections) 만큼 메모리를 할당함
	struct  _MY_IMAGE_SECTION_HEADER **ish = malloc(sizeof(struct _MY_IMAGE_SECTION_HEADER)*(ifh->NumberOfSections));
	for (i = 0; i < (ifh->NumberOfSections); i++)
	{
		if (i == 0)
		{
			file_offset = (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader);
			ish[i] = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader);
		}
		else
		{
			file_offset = (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader) + sizeof(struct _MY_IMAGE_SECTION_HEADER) * i;
			ish[i] = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader) + sizeof(struct _MY_IMAGE_SECTION_HEADER) * i;
		}
	}

	// EXPORT Table
	struct _MY_IMAGE_EXPORT_DIRECTORY *ied = malloc(sizeof(struct _MY_IMAGE_EXPORT_DIRECTORY));

	// IMAGE_IMPORT_DESCRIPTOR
	// ioh->DataDirectory[1].Size 만큼 메모리를 할당함
	struct _MY_IMAGE_IMPORT_DESCRIPTOR **iid = malloc(ioh->DataDirectory[1].Size);

	// IMPORT_NAME_TABLE
	struct _MY_IMAGE_THUNK_DATA32 **itd = malloc(sizeof(struct _MY_IMAGE_THUNK_DATA32)*ioh->DataDirectory[1].Size);


	printf("[-] Store in file(\\result)...\n\n");

	// 결과를 저장할 디렉토리 생성
	if (access("result", 0) == -1)
	{
		if (mkdir("result", 0776) == -1)
		{
			printf("Directory Create error\n");
		}
	}

	// IMAGE_DOS_HEADER
	wfile = fopen("result\\00 IMAGE_DOS_HEADER.txt", "w");
	if (wfile == NULL){
		fputs("IMAGE_DOS_HEADER.txt open error\n", stderr); exit(1);
	}
	else{
		fputs("- result\\00 IMAGE_DOS_HEADER.txt\n", stderr);
	}
	fprintf(wfile, "- e_magic : %02X\n", idh->e_magic);
	fprintf(wfile, "- e_cblp : %02X\n", idh->e_cblp);
	fprintf(wfile, "- e_cp : %02X\n", idh->e_cp);
	fprintf(wfile, "- e_crlc : %02X\n", idh->e_crlc);
	fprintf(wfile, "- e_cparhdr : %02X\n", idh->e_cparhdr);
	fprintf(wfile, "- e_minalloc : %02X\n", idh->e_minalloc);
	fprintf(wfile, "- e_maxalloc : %02X\n", idh->e_maxalloc);
	fprintf(wfile, "- e_ss : %02X\n", idh->e_ss);
	fprintf(wfile, "- e_sp : %02X\n", idh->e_sp);
	fprintf(wfile, "- e_csum : %02X\n", idh->e_csum);
	fprintf(wfile, "- e_ip : %02X\n", idh->e_ip);
	fprintf(wfile, "- e_cs : %02X\n", idh->e_cs);
	fprintf(wfile, "- e_lfarlc : %02X\n", idh->e_lfarlc);
	fprintf(wfile, "- e_ovno : %02X\n", idh->e_ovno);
	for (i = 0; i < 4; i++)
	{
		fprintf(wfile, "- e_res[%d] : %02X\n", i, idh->e_res[i]);
	}
	fprintf(wfile, "- e_oemid : %02X\n", idh->e_oemid);
	fprintf(wfile, "- e_oeminfo : %02X\n", idh->e_oeminfo);
	for (i = 0; i < 10; i++)
	{
		fprintf(wfile, "- e_res2[%d] : %02X\n", i, idh->e_res2[i]);
	}
	fprintf(wfile, "- e_lfanew : %08X\n", idh->e_lfanew);
	fclose(wfile);

	// IMAGE_NT_HEADERS // Signature
	wfile = fopen("result\\01 IMAGE_NT_HEADERS.Signature.txt", "w");
	if (wfile == NULL){
		fputs("IMAGE_NT_HEADERS.Signature.txt open error\n", stderr); exit(1);
	}
	else{
		fputs("- result\\01 IMAGE_NT_HEADERS.Signature.txt\n", stderr);
	}
	fprintf(wfile, "- Signature: %08X\n", sgt->Signature);
	fclose(wfile);

	// IMAGE_NT_HEADERS // IMAGE_FILE_HEADER
	wfile = fopen("result\\02 IMAGE_NT_HEADERS.IMAGE_FILE_HEADER.txt", "w");
	if (wfile == NULL){
		fputs("IMAGE_NT_HEADERS.IMAGE_FILE_HEADER.txt open error\n", stderr); exit(1);
	}
	else{
		fputs("- result\\02 IMAGE_NT_HEADERS.IMAGE_FILE_HEADER.txt\n", stderr);
	}
	fprintf(wfile, "- Machine: %02X\n", ifh->Machine);
	fprintf(wfile, "- NumberOfSections: %02X\n", ifh->NumberOfSections);
	fprintf(wfile, "- TimeDateStamp: %04X\n", ifh->TimeDateStamp);
	fprintf(wfile, "- PointerToSymbolTables: %04X\n", ifh->PointerToSymbolTable);
	fprintf(wfile, "- NumberOfSymbols: %04X\n", ifh->NumberOfSymbols);
	fprintf(wfile, "- SizeOfOptionalHeader: %02X\n", ifh->SizeOfOptionalHeader);
	fprintf(wfile, "- Characteristics: %02X\n", ifh->Characteristics);
	fclose(wfile);

	// IMAGE_NT_HEADERS // IMAGE_OPTIONAL_HEADER
	wfile = fopen("result\\03 IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.txt", "w");
	if (wfile == NULL){
		fputs("IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.txt open error\n", stderr); exit(1);
	}
	else{
		fputs("- result\\03 IMAGE_NT_HEADERS.IMAGE_OPTIONAL_HEADER.txt\n", stderr);
	}
	fprintf(wfile, "- Magic: %02X\n", ioh->Magic);
	fprintf(wfile, "- MajorLinkerVersion: %01X\n", ioh->MajorLinkerVersion);
	fprintf(wfile, "- MinorLinkerVersion: %01X\n", ioh->MinorLinkerVersion);
	fprintf(wfile, "-  SizeOfCode: %04X\n", ioh->SizeOfCode);
	fprintf(wfile, "- SizeOfInitializedData: %04X\n", ioh->SizeOfInitializedData);
	fprintf(wfile, "- SizeOfUninitializedData: %04X\n", ioh->SizeOfUninitializedData);
	fprintf(wfile, "- AddressOfEntryPoint: %04X\n", ioh->AddressOfEntryPoint);
	fprintf(wfile, "- BaseOfCode: %04X\n", ioh->BaseOfCode);
	fprintf(wfile, "- BaseOfData: %04X\n", ioh->BaseOfData);
	fprintf(wfile, "- ImageBase: %04X\n", ioh->ImageBase);
	fprintf(wfile, "- SectionAlignment: %04X\n", ioh->SectionAlignment);
	fprintf(wfile, "- FileAlignment: %04X\n", ioh->FileAlignment);
	fprintf(wfile, "- MajorOperatingSystemVersion: %02X\n", ioh->MajorOperatingSystemVersion);
	fprintf(wfile, "- MinorOperatingSystemVersion: %02X\n", ioh->MinorOperatingSystemVersion);
	fprintf(wfile, "- MajorImageVersion: %02X\n", ioh->MajorImageVersion);
	fprintf(wfile, "- MinorImageVersion: %02X\n", ioh->MinorImageVersion);
	fprintf(wfile, "- MajorSubsystemVersion: %02X\n", ioh->MajorSubsystemVersion);
	fprintf(wfile, "- MinorSubsystemVersion: %02X\n", ioh->MinorSubsystemVersion);
	fprintf(wfile, "- Win32VersionValue: %04X\n", ioh->Win32VersionValue);
	fprintf(wfile, "- SizeOfImage: %04X\n", ioh->SizeOfImage);
	fprintf(wfile, "- SizeOfHeaders: %04X\n", ioh->SizeOfHeaders);
	fprintf(wfile, "- CheckSum: %04X\n", ioh->CheckSum);
	fprintf(wfile, "- Subsystem: %02X\n", ioh->Subsystem);
	fprintf(wfile, "- DllCharacteristics: %02X\n", ioh->DllCharacteristics);
	fprintf(wfile, "- SizeOfStackReserve: %04X\n", ioh->SizeOfStackReserve);
	fprintf(wfile, "- SizeOfStackCommit: %04X\n", ioh->SizeOfStackCommit);
	fprintf(wfile, "- SizeOfHeapReserve: %04X\n", ioh->SizeOfHeapReserve);
	fprintf(wfile, "- SizeOfHeapCommit: %04X\n", ioh->SizeOfHeapCommit);
	fprintf(wfile, "- LoaderFlags: %04X\n", ioh->LoaderFlags);
	fprintf(wfile, "- NumberOfRvaAndSizes: %04X\n", ioh->NumberOfRvaAndSizes);
	fclose(wfile);

	// IMAGE_NT_HEADERS // Data Directory Table
	wfile = fopen("result\\04 IMAGE_NT_HEADERS.Data_Directory_Table.txt", "w");
	if (wfile == NULL){
		fputs("wfile File open error\n", stderr); exit(1);
	}
	else{
		fputs("- result\\04 IMAGE_NT_HEADERS.Data_Directory_Table.txt\n", stderr);
	}
	fseek(wfile, 0, SEEK_END);
	rewind(wfile);

	for (i = 0; i < (ioh->NumberOfRvaAndSizes); i++)
	{
		fprintf(wfile, "- DataDirectory[%d]: %04X\n", i, ioh->DataDirectory[i].VirtualAddress);
	}
	fclose(wfile);
	index = 5;

	// IMAGE_SECTION_HEADER
	tmp = malloc(50);
	for (i = 0; i < (ifh->NumberOfSections); i++)
	{
		if (index > 9)
		{
			sprintf(tmp, "%s%d%s%s%s", "result\\", 5 + i, " IMAGE_SECTION_HEADER", ish[i]->Name, ".txt");
		}
		else
		{
			sprintf(tmp, "%s%d%s%s%s", "result\\0", 5 + i, " IMAGE_SECTION_HEADER", ish[i]->Name, ".txt");
		}
		wfile = fopen(tmp, "w");
		if (wfile == NULL){
			fputs("wfile File open error\n", stderr); exit(1);
		}
		else{
			printf("- %s\n", tmp);
		}
		fseek(wfile, 0, SEEK_END);
		rewind(wfile);
		if (i == 0)
		{
			file_offset = (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader);
		}
		else
		{
			file_offset = (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader) + sizeof(struct _MY_IMAGE_SECTION_HEADER) * i;
		}

		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: Name\n", file_offset, ish[i]->Name);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: VirtualAddress\n", file_offset + 1, ish[i]->VirtualAddress);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description:SizeOfRawData\n", file_offset + 2, ish[i]->SizeOfRawData);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: PointerToRawData\n", file_offset + 3, ish[i]->PointerToRawData);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: PointerToRelocations\n", file_offset + 4, ish[i]->PointerToRelocations);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: PointerToLinenumbers\n", file_offset + 5, ish[i]->PointerToLinenumbers);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: NumberOfRelocations\n", file_offset + 6, ish[i]->NumberOfRelocations);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: NumberOfLinenumbers\n", file_offset + 7, ish[i]->NumberOfLinenumbers);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: Characteristics\n\n", file_offset + 8, ish[i]->Characteristics);

		min = 1000000000;
		tmp_1 = (int)ish[i]->VirtualAddress;
		//tmp_2 = (int)ish[i + 1]->VirtualAddress;
		tmp_3 = (int)ioh->DataDirectory[0].VirtualAddress;
		if (tmp_3 >= tmp_1)
		{
			res = tmp_3 - tmp_1;
			if (res < min)
			{
				min = res;
				eat_section = i;
			}
		}
		index++;
		fclose(wfile);
	}

	for (i = 0; i < (ifh->NumberOfSections); i++)
	{
		min = 1000000000;
		tmp_1 = (int)ish[i]->VirtualAddress;
		tmp_3 = (int)ioh->DataDirectory[1].VirtualAddress;
		if (tmp_3 >= tmp_1)
		{
			res = tmp_3 - tmp_1;
			if (res < min)
			{
				min = res;
				iat_section = i;
			}
		}
	}

	if (ioh->DataDirectory[0].Size != 0)
	{
		// IMAGE_EXPORT_DIRECTORY
		sprintf(tmp, "%s%02d%s", "result\\", index, " IMAGE_EXPORT_DIRECTORY.txt");
		wfile = fopen(tmp, "w");
		if (wfile == NULL){
			fputs("wfile File open error\n", stderr); exit(1);
		}
		else{
			printf("- %s\n", tmp);
		}

		file_offset = ioh->DataDirectory[0].VirtualAddress - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;
		ied = buffer + ioh->DataDirectory[0].VirtualAddress - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;

		fprintf(wfile, "- Characteristics: %04X\n", ied->Characteristics);
		fprintf(wfile, "- TimeDataStamp: %04X\n", ied->TimeDateStamp);
		fprintf(wfile, "- MajorVersion: %04X\n", ied->MajorVersion);
		fprintf(wfile, "- Name: %04X\n", ied->Name);
		fprintf(wfile, "- Base: %04X\n", ied->Base);
		fprintf(wfile, "- NumberOfFunctions: %04X\n", ied->NumberOfFunctions);
		fprintf(wfile, "- NumberOfNames: %04X\n", ied->NumberOfNames);
		fprintf(wfile, "- AddressOfFunctions: %04X\n", ied->AddressOfFunctions);
		fprintf(wfile, "- AddressOfNames: %04X\n", ied->AddressOfNames);
		fprintf(wfile, "- AddressOfNameOrdinals: %04X\n", ied->AddressOfNameOrdinals);
		index++;
		fclose(wfile);

		// EXPORT Address Table
		sprintf(tmp, "%s%02d%s", "result\\", index, " EXPORT Address Table.txt");
		wfile = fopen(tmp, "w");
		if (wfile == NULL){
			fputs("wfile File open error\n", stderr); exit(1);
		}
		else{
			printf("- %s\n", tmp);
		}
		for (i = 0; i < ied->NumberOfFunctions; i++)
		{
			// RAW = RVA - VirtualAddress + PointerToRawData
			// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
			file_offset = buffer + ied->AddressOfFunctions - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;

			//pfile: (file_offset + j) / data: *(file_offset + j)
			fprintf(wfile, "-pFile: %04X | Data: %04X | Description: Function RVA\n", (ied->AddressOfFunctions - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + 4 * i), *(file_offset + i));

		}
		index++;
		fclose(wfile);

		if ((int)ied->AddressOfNames != 0)
		{
			// EXPORT Name Table
			sprintf(tmp, "%s%02d%s", "result\\", index, " EXPORT Name Table.txt");
			wfile = fopen(tmp, "w");
			if (wfile == NULL){
				fputs("wfile File open error\n", stderr); exit(1);
			}
			else{
				printf("- %s\n", tmp);
			}
			for (i = 0; i < ied->NumberOfFunctions; i++)
			{
				// RAW = RVA - VirtualAddress + PointerToRawData
				// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
				file_offset = buffer + ied->AddressOfNames - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;

				//pfile: (file_offset + j) / data: *(file_offset + j)
				fprintf(wfile, "%04X\n", ied->AddressOfNames);
				fprintf(wfile, "%04X\n", ish[eat_section]->VirtualAddress);
				fprintf(wfile, "%04X\n", ish[eat_section]->PointerToRawData);
				fprintf(wfile, "%04X\n", ish[eat_section]->PointerToRawData);
				fprintf(wfile, "-pFile: %04X | Data: %04X | Description: Function Name RVA | Value: ", (ied->AddressOfNames - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + 4 * i), *(file_offset + i));

				// Value 값 처리
				for (j = 2; j < 50; j++)
				{
					// data인 *(file_offset + j)는 RVA이기 때문에 RAW로 변환한 후 해당 RVA의 값인 함수명을 추출
					fprintf(wfile, "%c", *(buffer + *(file_offset + i) - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + j));

					// NULL이 나올때까지 추출
					if (*(buffer + *(file_offset + i) - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + j) == NULL){
						fprintf(wfile, "\n");
						break;
					}
				}
			}
			index++;
			fclose(wfile);
		}
	}

	// IMPORT Directory Table
	sprintf(tmp, "%s%02d%s", "result\\", index, " IMPORT_Directory_Table.txt");
	wfile = fopen(tmp, "w");
	if (wfile == NULL){
		fputs("wfile File open error\n", stderr); exit(1);
	}
	else{
		printf("- %s\n", tmp);
	}

	arr_num = ioh->DataDirectory[1].Size / sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR);
	for (i = 0; i < arr_num; i++)
	{

		// buffer를 베이스주소로, iid의 각 배열의 시작 주소를 정의함
		if (i == 0)
		{
			file_offset = ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
			iid[i] = buffer + ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
		}
		// iid의 각 배열은 _IMAGE_IMPORT_DESCRIPTOR 구조체 크기만큼 시작주소가 뒤로가게 됨
		else
		{
			file_offset = ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR) * i;
			iid[i] = buffer + ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR) * i;
		}

		//printf("- %04X\n",iid[i]->OriginalFirstThunk);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: OriginalFirstThunk\n", file_offset, iid[i]->OriginalFirstThunk);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: TimeDataStamp\n", file_offset + 1, iid[i]->TimeDataStamp);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: ForwarderChain\n", file_offset + 2, iid[i]->ForwarderChain);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: FirstThunk\n", file_offset + 3, iid[i]->FirstThunk);
		fprintf(wfile, "- pFile: %04X | Data: %04X | Description: Name | Value: ", file_offset + 4, iid[i]->Name);

		if ((int)iid[i]->OriginalFirstThunk == 0 && (int)iid[i]->TimeDataStamp == 0 && (int)iid[i]->ForwarderChain == 0 && (int)iid[i]->FirstThunk == 0 && (int)iid[i]->Name == 0)
		{
			import_count = k;
			break;
		}
		// iid[i]->Name은 로드하는 dll의 이름을 가리키고 있는 RVA 주소이므로, RAW로 변경한 후 값을 읽어 dll 이름을 추출함
		for (j = 0; j < 50; j++)
		{
			fprintf(wfile, "%c", *(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + j));
			if (*(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + j) == NULL){
				fprintf(wfile, "\n");
				break;
			}
		}
		k++;
		fprintf(wfile, "-----------------------------------------------------------------------------------------------------------------\n");
	}
	k = 0;
	index++;
	fclose(wfile);

	// IMPORT Address Table
	sprintf(tmp, "%s%02d%s", "result\\", index, " IMPORT_Address_Table.txt");
	wfile = fopen(tmp, "w");
	if (wfile == NULL){
		fputs("wfile File open error\n", stderr); exit(1);
	}
	else{
		printf("- %s\n", tmp);
	}

	for (i = 0; i < import_count; i++)
	{
		//printf("%d %d\n", arr_num, i);
		// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
		file_offset = buffer + iid[i]->FirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
		for (j = 0; j < 50; j++) //50으로 변경 
		{
			//pfile: (file_offset + j) / data: *(file_offset + j)
			fprintf(wfile, "-pFile: %04X | Data: %04X | Description: ", (iid[i]->FirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + 4 * j), *(file_offset + j));

			// Ordinal 처리
			if (*(file_offset + j) > 0x80000000)
			{
				fprintf(wfile, "\(Ordinal\)\n");
				continue;
			}
			else if (*(file_offset + j) == 0x0)
			{
				fprintf(wfile, "End of Imports | Value: ");
			}
			else
			{
				fprintf(wfile, "Hint/Name RVA | Value: ");
			}

			for (k = 2; k < 50; k++)
			{
				//data인 *(file_offset + j)가 0x0이라면 아래 함수명 추출을 수행하지 않기위해 break -> 아래 if문 수행
				if (*(file_offset + j) == 0x0){
					break;
				}
				// data인 *(file_offset + j)는 RVA이기 때문에 RAW로 변환한 후 해당 RVA의 값인 함수명을 추출
				fprintf(wfile, "%c", *(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
				if (*(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
					fprintf(wfile, "\n");
					break;
				}
			}
			// data가 0x0이 나온 경우
			if (*(file_offset + j) == 0x0)
			{
				// data 부분에 dll 명을 추출
				for (k = 0; k < 50; k++)
				{
					//// iid[i]->Name은 로드하는 dll의 이름을 가리키고 있는 RVA 주소이므로, RAW로 변경한 후 값을 읽어 dll 이름을 추출함
					fprintf(wfile, "%c", *(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
					if (*(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
						fprintf(wfile, "\n");
						break;
					}
				}
				break;
			}

		}

		fprintf(wfile, "-----------------------------------------------------------------------------------------------------------------\n");
	}
	index++;

	// IMPORT Name Table
	sprintf(tmp, "%s%02d%s", "result\\", index, " IMPORT_Name_Table.txt");
	wfile = fopen(tmp, "w");
	if (wfile == NULL){
		fputs("wfile File open error\n", stderr); exit(1);
	}
	else{
		printf("- %s\n", tmp);
	}

	for (i = 0; i < import_count; i++)
	{
		//printf("%d %d\n", arr_num, i);
		// iid[i]->OriginalFirstThunk(INT 배열)를 RAW로 변환
		file_offset = buffer + iid[i]->OriginalFirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
		for (j = 0; j < 50; j++) //50으로 변경 
		{
			//pfile: (file_offset + j) / data: *(file_offset + j)
			fprintf(wfile, "-pFile: %04X | Data: %04X | Description: ", (iid[i]->OriginalFirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + 4 * j), *(file_offset + j));

			// Ordinal 처리
			if (*(file_offset + j) > 0x80000000)
			{
				fprintf(wfile, "\(Ordinal\)\n");
				continue;
			}
			else if (*(file_offset + j) == 0x0)
			{
				fprintf(wfile, "End of Imports | Value: ");
			}
			else
			{
				fprintf(wfile, "Hint/Name RVA | Value: ");
			}

			for (k = 2; k < 50; k++)
			{
				//data인 *(file_offset + j)가 0x0이라면 아래 함수명 추출을 수행하지 않기위해 break -> 아래 if문 수행
				if (*(file_offset + j) == 0x0){
					break;
				}
				// data인 *(file_offset + j)는 RVA이기 때문에 RAW로 변환한 후 해당 RVA의 값인 함수명을 추출
				fprintf(wfile, "%c", *(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
				if (*(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
					fprintf(wfile, "\n");
					break;
				}
			}
			// data가 0x0이 나온 경우
			if (*(file_offset + j) == 0x0)
			{
				// data 부분에 dll 명을 추출
				for (k = 0; k < 50; k++)
				{
					//// iid[i]->Name은 로드하는 dll의 이름을 가리키고 있는 RVA 주소이므로, RAW로 변경한 후 값을 읽어 dll 이름을 추출함
					fprintf(wfile, "%c", *(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
					if (*(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
						fprintf(wfile, "\n");
						break;
					}
				}
				break;
			}

		}
		fprintf(wfile, "-----------------------------------------------------------------------------------------------------------------\n");
	}

	printf("\n[-] PE Parsing End...\n\n");
	printf("**************************************************************\n\n");

	fclose(pfile);
	free(buffer);

	return 0;
}
