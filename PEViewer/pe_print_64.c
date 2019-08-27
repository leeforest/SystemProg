#include <stdio.h>
#include <string.h>
#include <Windows.h>
#include "pe_structure.h"

// 64 exe print option _ check v
int pe_print_64(char* file, char* option)
{
	int i = 0;
	int j = 0;
	int k = 0;
	int import_count = 0;
	int iat_section = 0;
	int eat_section = 0;
	int min = 0;
	int res = 0;
	int arr_num;
	char *tmp;
	int tmp_1;
	int tmp_2;
	int tmp_3;
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
	struct _MY_IMAGE_OPTIONAL_HEADER64 *ioh = malloc(sizeof(struct _MY_IMAGE_OPTIONAL_HEADER64));
	ioh = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER);

	struct _MY_IMAGE_DATA_DIRECTORY **idd = malloc(sizeof(struct _MY_IMAGE_DATA_DIRECTORY));
	idd = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) - (IMAGE_NUMBEROF_DIRECTORY_ENTRIES*(sizeof(struct _MY_IMAGE_DATA_DIRECTORY)));

	//printf("%d\n\n\n", IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	// IMGAE_SECTION_HEADER
	// IMGAE_SECTION_HEADER는 하나 이상이므로 배열을 쓰기 위해 이중 포인터로 선언
	// IMAGE_SECTION_HEADER * 섹션 수(ifh->NumberOfSections) 만큼 메모리를 할당함
	struct  _MY_IMAGE_SECTION_HEADER **ish = malloc(sizeof(struct _MY_IMAGE_SECTION_HEADER)*(ifh->NumberOfSections));

	// EXPORT Table
	struct _MY_IMAGE_EXPORT_DIRECTORY *ied = malloc(sizeof(struct _MY_IMAGE_EXPORT_DIRECTORY));

	// IMAGE_IMPORT_DESCRIPTOR
	// ioh->DataDirectory[1].Size 만큼 메모리를 할당함
	struct _MY_IMAGE_IMPORT_DESCRIPTOR **iid = malloc(ioh->DataDirectory[1].Size);

	// IMPORT_NAME_TABLE
	struct _MY_IMAGE_THUNK_DATA32 **itd = malloc(sizeof(struct _MY_IMAGE_THUNK_DATA32)*ioh->DataDirectory[1].Size);


	printf("[-] Print in console...\n\n");
	// IMAGE_DOS_HEADER
	printf("********************************* [IMAGE_DOS_HEADER] ************************************\n\n");
	printf("- e_magic : %02X\n", idh->e_magic);
	printf("- e_cblp : %02X\n", idh->e_cblp);
	printf("- e_cp : %02X\n", idh->e_cp);
	printf("- e_crlc : %02X\n", idh->e_crlc);
	printf("- e_cparhdr : %02X\n", idh->e_cparhdr);
	printf("- e_minalloc : %02X\n", idh->e_minalloc);
	printf("- e_maxalloc : %02X\n", idh->e_maxalloc);
	printf("- e_ss : %02X\n", idh->e_ss);
	printf("- e_sp : %02X\n", idh->e_sp);
	printf("- e_csum : %02X\n", idh->e_csum);
	printf("- e_ip : %02X\n", idh->e_ip);
	printf("- e_cs : %02X\n", idh->e_cs);
	printf("- e_lfarlc : %02X\n", idh->e_lfarlc);
	printf("- e_ovno : %02X\n", idh->e_ovno);
	for (i = 0; i < 4; i++)
	{
		printf("- e_res[i] : %02X\n", i, idh->e_res[i]);
	}
	printf("- e_oemid : %02X\n", idh->e_oemid);
	printf("- e_oeminfo : %02X\n", idh->e_oeminfo);
	for (i = 0; i < 10; i++)
	{
		printf("- e_res2[i] : %02X\n", idh->e_res2[i]);
	}
	printf("- e_lfanew : %08X\n\n", i, idh->e_lfanew);

	// IMAGE_NT_HEADERS // Structure
	printf("***************************** [IMAGE_NT_HEADER.Signature] ***********************************\n\n");
	printf("- Signature: %08X\n\n", sgt->Signature);

	// IMAGE_NT_HEADERS // IMAGE_FILE_HEADER
	printf("************************* [IMAGE_NT_HEADER.IMAGE_FILE_HEADER] *******************************\n\n");
	printf("- Machine: %02X\n", ifh->Machine);
	printf("- NumberOfSections: %02X\n", ifh->NumberOfSections);
	printf("- TimeDateStamp: %04X\n", ifh->TimeDateStamp);
	printf("- PointerToSymbolTables: %04X\n", ifh->PointerToSymbolTable);
	printf("- NumberOfSymbols: %04X\n", ifh->NumberOfSymbols);
	printf("- SizeOfOptionalHeader: %02X\n", ifh->SizeOfOptionalHeader);
	printf("- Characteristics: %02X\n\n", ifh->Characteristics);


	// IMAGE_NT_HEADERS // IMAGE_OPTIONAL_HEADER
	printf("*********************** [IMAGE_NT_HEADER.IMAGE_OPTIONAL_HEADER] *****************************\n\n");
	printf("- Magic: %02X\n", ioh->Magic);
	printf("- MajorLinkerVersion: %01X\n", ioh->MajorLinkerVersion);
	printf("- MinorLinkerVersion: %01X\n", ioh->MinorLinkerVersion);
	printf("-  SizeOfCode: %04X\n", ioh->SizeOfCode);
	printf("- SizeOfInitializedData: %04X\n", ioh->SizeOfInitializedData);
	printf("- SizeOfUninitializedData: %04X\n", ioh->SizeOfUninitializedData);
	printf("- AddressOfEntryPoint: %04X\n", ioh->AddressOfEntryPoint);
	printf("- BaseOfCode: %04X\n", ioh->BaseOfCode);
	printf("- ImageBase: %04X\n", ioh->ImageBase);
	printf("- SectionAlignment: %04X\n", ioh->SectionAlignment);
	printf("- FileAlignment: %04X\n", ioh->FileAlignment);
	printf("- MajorOperatingSystemVersion: %02X\n", ioh->MajorOperatingSystemVersion);
	printf("- MinorOperatingSystemVersion: %02X\n", ioh->MinorOperatingSystemVersion);
	printf("- MajorImageVersion: %02X\n", ioh->MajorImageVersion);
	printf("- MinorImageVersion: %02X\n", ioh->MinorImageVersion);
	printf("- MajorSubsystemVersion: %02X\n", ioh->MajorSubsystemVersion);
	printf("- MinorSubsystemVersion: %02X\n", ioh->MinorSubsystemVersion);
	printf("- Win32VersionValue: %04X\n", ioh->Win32VersionValue);
	printf("- SizeOfImage: %04X\n", ioh->SizeOfImage);
	printf("- SizeOfHeaders: %04X\n", ioh->SizeOfHeaders);
	printf("- CheckSum: %04X\n", ioh->CheckSum);
	printf("- Subsystem: %02X\n", ioh->Subsystem);
	printf("- DllCharacteristics: %02X\n", ioh->DllCharacteristics);
	printf("- SizeOfStackReserve: %04X\n", ioh->SizeOfStackReserve);
	printf("- SizeOfStackCommit: %04X\n", ioh->SizeOfStackCommit);
	printf("- SizeOfHeapReserve: %04X\n", ioh->SizeOfHeapReserve);
	printf("- SizeOfHeapCommit: %04X\n", ioh->SizeOfHeapCommit);
	printf("- LoaderFlags: %04X\n", ioh->LoaderFlags);
	printf("- NumberOfRvaAndSizes: %04X\n\n", ioh->NumberOfRvaAndSizes);

	// IMAGE_NT_HEADERS // Data Directory Table
	printf("******************************** [Data Directory Table] *************************************\n\n");

	for (i = 0; i < IMAGE_NUMBEROF_DIRECTORY_ENTRIES; i++)
	{
		printf("- DataDirectory[%d]: %04X\n", i, ioh->DataDirectory[i].VirtualAddress);
	}
	printf("\n");

	// IMGAE_SECTION_HEADER
	printf("************************************ [IMAGE_SECTION_HEADER] *********************************\n\n");
	// 섹션의 수만큼 반복
	for (i = 0; i < (ifh->NumberOfSections); i++)
	{
		// IMAGE_SECTION_HEADER 구조체 각 배열의 시작 주소를 정의함
		// 첫번째 배열: ~ + (ifh->SizeOfOptionalHeader)
		if (i == 0)
		{
			file_offset = (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader);
			ish[i] = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader);
		}
		// 두번째 배열부터: ~ + (ifh->SizeOfOptionalHeader) + (IMAGE_SECTION_HEADER 구조체 크기 * i)
		else
		{
			file_offset = (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader) + sizeof(struct _MY_IMAGE_SECTION_HEADER) * i;
			ish[i] = buffer + (idh->e_lfanew) + sizeof(struct _MY_SIGNATURE) + sizeof(struct _MY_IMAGE_FILE_HEADER) + (ifh->SizeOfOptionalHeader) + sizeof(struct _MY_IMAGE_SECTION_HEADER) * i;
		}

		printf("************************************** [SECTION %s] **************************************\n\n", ish[i]->Name);
		printf("- pFile: %04X | Data: %04X | Description: Name\n", file_offset, ish[i]->Name);
		printf("- pFile: %04X | Data: %04X | Description: VirtualAddress\n", file_offset + 1, ish[i]->VirtualAddress);
		printf("- pFile: %04X | Data: %04X | Description:SizeOfRawData\n", file_offset + 2, ish[i]->SizeOfRawData);
		printf("- pFile: %04X | Data: %04X | Description: PointerToRawData\n", file_offset + 3, ish[i]->PointerToRawData);
		printf("- pFile: %04X | Data: %04X | Description: PointerToRelocations\n", file_offset + 4, ish[i]->PointerToRelocations);
		printf("- pFile: %04X | Data: %04X | Description: PointerToLinenumbers\n", file_offset + 5, ish[i]->PointerToLinenumbers);
		printf("- pFile: %04X | Data: %04X | Description: NumberOfRelocations\n", file_offset + 6, ish[i]->NumberOfRelocations);
		printf("- pFile: %04X | Data: %04X | Description: NumberOfLinenumbers\n", file_offset + 7, ish[i]->NumberOfLinenumbers);
		printf("- pFile: %04X | Data: %04X | Description: Characteristics\n\n", file_offset + 8, ish[i]->Characteristics);

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
	}

	for (i = 0; i < (ifh->NumberOfSections); i++)
	{
		min = 1000000000;
		tmp_1 = (int)ish[i]->VirtualAddress;
		//tmp_2 = (int)ish[i + 1]->VirtualAddress;
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

	// RAW = RVA - VirtualAddress + PointerToRawData
	if (ioh->DataDirectory[0].Size != 0)
	{

		printf("**************************** [IMAGE_EXPORT_DIRECTORY] ************************************\n\n");
		file_offset = ioh->DataDirectory[0].VirtualAddress - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;
		ied = buffer + ioh->DataDirectory[0].VirtualAddress - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;

		printf("- Characteristics: %04X\n", ied->Characteristics);
		printf("- TimeDataStamp: %04X\n", ied->TimeDateStamp);
		printf("- MajorVersion: %04X\n", ied->MajorVersion);
		printf("- Name: %04X\n", ied->Name);
		printf("- Base: %04X\n", ied->Base);
		printf("- NumberOfFunctions: %04X\n", ied->NumberOfFunctions);
		printf("- NumberOfNames: %04X\n", ied->NumberOfNames);
		printf("- AddressOfFunctions: %04X\n", ied->AddressOfFunctions);
		printf("- AddressOfNames: %04X\n", ied->AddressOfNames);
		printf("- AddressOfNameOrdinals: %04X\n", ied->AddressOfNameOrdinals);

		printf("******************************* [EXPORT Address Table] ************************************\n\n");
		for (i = 0; i < ied->NumberOfFunctions; i++)
		{
			// RAW = RVA - VirtualAddress + PointerToRawData
			// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
			file_offset = buffer + ied->AddressOfFunctions - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;

			//pfile: (file_offset + j) / data: *(file_offset + j)
			printf("-pFile: %04X | Data: %04X | Description: Function RVA\n", (ied->AddressOfFunctions - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + 4 * i), *(file_offset + i));

		}

		if ((int)ied->AddressOfNames != 0)
		{
			printf("******************************** [EXPORT Name Table] ************************************\n\n");
			//for (i = 0; i < ied->NumberOfFunctions; i++)
			for (i = 0; i < ied->NumberOfFunctions; i++)
			{
				// RAW = RVA - VirtualAddress + PointerToRawData
				// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
				file_offset = buffer + ied->AddressOfNames - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData;

				//pfile: (file_offset + j) / data: *(file_offset + j)
				printf("-pFile: %04X | Data: %04X | Description: Function Name RVA | Value: ", (ied->AddressOfNames - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + 4 * i), *(file_offset + i));

				// Value 값 처리
				for (j = 2; j < 50; j++)
				{
					// data인 *(file_offset + j)는 RVA이기 때문에 RAW로 변환한 후 해당 RVA의 값인 함수명을 추출
					printf("%c", *(buffer + *(file_offset + i) - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + j));

					// NULL이 나올때까지 추출
					if (*(buffer + *(file_offset + i) - ish[eat_section]->VirtualAddress + ish[eat_section]->PointerToRawData + j) == NULL){
						printf("\n");
						break;
					}
				}
			}
			printf("\n");
		}
	}

	// IMPORT Directory Table
	// IMAGE_IMPORT_DESCRIPTOR = IMPORT Directory Table (어떤 라이브러리를 임포트하고 있는지 명시한 테이블, 안에 IAT, INT가 존재함)
	printf("**************************** [IMPORT Directory Table] ************************************\n\n");

	// arr_num은 IMPORT Directory Table의 배열 수로 IMPORT Directory Table를 _IMAGE_IMPORT_DESCRIPTOR 구조체의 크기로 나눈 것
	arr_num = ioh->DataDirectory[1].Size / sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR);
	for (i = 0; i < arr_num; i++)
	{
		// // RAW = RVA - VirtualAddress + PointerToRawData
		// 첫번째 배열: (ioh->DataDirectory[1].VirtualAddress(RVA)) -> RAW로 변환
		if (i == 0)
		{
			file_offset = ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
			iid[i] = buffer + ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
		}
		// 두번째 배열부터: ~ + (IMAGE_IMPORT_DESCRIPTOR 구조체 크기 * i)
		else
		{
			file_offset = ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR) * i;
			iid[i] = buffer + ioh->DataDirectory[1].VirtualAddress - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + sizeof(struct _MY_IMAGE_IMPORT_DESCRIPTOR) * i;
		}
		//printf("- %04X\n",iid[i]->OriginalFirstThunk);
		printf("- pFile: %04X | Data: %04X | Description: OriginalFirstThunk\n", file_offset, iid[i]->OriginalFirstThunk);
		printf("- pFile: %04X | Data: %04X | Description: TimeDataStamp\n", file_offset + 1, iid[i]->TimeDataStamp);
		printf("- pFile: %04X | Data: %04X | Description: ForwarderChain\n", file_offset + 2, iid[i]->ForwarderChain);
		printf("- pFile: %04X | Data: %04X | Description: FirstThunk\n", file_offset + 3, iid[i]->FirstThunk);
		printf("- pFile: %04X | Data: %04X | Description: Name | Value: ", file_offset + 4, iid[i]->Name);

		if ((int)iid[i]->OriginalFirstThunk == 0 && (int)iid[i]->TimeDataStamp == 0 && (int)iid[i]->ForwarderChain == 0 && (int)iid[i]->FirstThunk == 0 && (int)iid[i]->Name == 0)
		{
			printf("End of Import Table\n");
			import_count = k;
			printf("------------------------------------------------------------------------------------------\n\n");
			break;
		}

		// iid[i]->Name은 로드하는 dll의 이름을 가리키고 있는 RVA 주소이므로, RAW로 변경한 후 값을 읽어 dll 이름을 추출함
		for (j = 0; j < 50; j++)
		{
			printf("%c", *(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + j));
			// NULL이 나오기 전까지 dll 이름을 추출함
			if (*(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + j) == NULL){
				printf("\n");
				break;
			}
		}
		k++;
		printf("------------------------------------------------------------------------------------------\n");
	}
	k = 0;

	printf("***************************** [IMPORT Address Table] *************************************\n\n");
	for (i = 0; i < import_count; i++)
	{
		// RAW = RVA - VirtualAddress + PointerToRawData
		// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
		file_offset = buffer + iid[i]->FirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
		for (j = 0; j < 50; j++) //50으로 변경
		{
			//pfile: (file_offset + j) / data: *(file_offset + j)
			printf("-pFile: %04X | Data: %04X | Description: ", (iid[i]->FirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + 4 * j), *(file_offset + j));

			// Description 처리
			// Data가 0x80000000보다 크다면 Ordinal 변수로 사용된 것
			if (*(file_offset + j) > 0x80000000)
			{
				printf("\(Ordinal\)\n");
				continue;
			}
			// Data가 0x0이라면 배열이 끝난 것
			else if (*(file_offset + j) == 0x0)
			{
				printf("End of Imports | Value: ");
			}
			// 그 외는, 함수 이름을 담고 있는 RVA 값(정상)
			else
			{
				printf("Hint/Name RVA | Value: ");
			}

			// Value 값 처리
			for (k = 2; k < 50; k++)
			{
				//Data인 *(file_offset + j)가 0x0이라면 아래 함수명 추출을 수행하지 않기위해 break -> 아래 if문 수행
				if (*(file_offset + j) == 0x0){
					break;
				}
				// data인 *(file_offset + j)는 RVA이기 때문에 RAW로 변환한 후 해당 RVA의 값인 함수명을 추출
				printf("%c", *(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
				// NULL이 나올때까지 추출
				if (*(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
					printf("\n");
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
					printf("%c", *(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
					if (*(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
						printf("\n");
						break;
					}
				}
				break;
			}

		}
		printf("------------------------------------------------------------------------------------------\n");
		if (i == import_count - 1)
		{
			printf("\n");
		}
	}

	printf("******************************* [IMPORT Name Table] **************************************\n\n");
	for (i = 0; i < import_count; i++)
	{
		// RAW = RVA - VirtualAddress + PointerToRawData
		// iid[i]->FirstThunk(IAT 배열)를 RAW로 변환
		file_offset = buffer + iid[i]->OriginalFirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData;
		for (j = 0; j < 50; j++) //50으로 변경
		{
			//pfile: (file_offset + j) / data: *(file_offset + j)
			printf("-pFile: %04X | Data: %04X | Description: ", (iid[i]->OriginalFirstThunk - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + 4 * j), *(file_offset + j));

			// Description 처리
			// Data가 0x80000000보다 크다면 Ordinal 변수로 사용된 것
			if (*(file_offset + j) > 0x80000000)
			{
				printf("\(Ordinal\)\n");
				continue;
			}
			// Data가 0x0이라면 배열이 끝난 것
			else if (*(file_offset + j) == 0x0)
			{
				printf("End of Imports | Value: ");
			}
			// 그 외는, 함수 이름을 담고 있는 RVA 값(정상)
			else
			{
				printf("Hint/Name RVA | Value: ");
			}

			// Value 값 처리
			for (k = 2; k < 50; k++)
			{
				//Data인 *(file_offset + j)가 0x0이라면 아래 함수명 추출을 수행하지 않기위해 break -> 아래 if문 수행
				if (*(file_offset + j) == 0x0){
					break;
				}
				// data인 *(file_offset + j)는 RVA이기 때문에 RAW로 변환한 후 해당 RVA의 값인 함수명을 추출
				printf("%c", *(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
				// NULL이 나올때까지 추출
				if (*(buffer + *(file_offset + j) - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
					printf("\n");
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
					printf("%c", *(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k));
					if (*(buffer + iid[i]->Name - ish[iat_section]->VirtualAddress + ish[iat_section]->PointerToRawData + k) == NULL){
						printf("\n");
						break;
					}
				}
				break;
			}

		}
		printf("------------------------------------------------------------------------------------------\n");
		if (i == import_count - 1)
		{
			printf("\n");
		}
	}

	printf("[-] PE Parsing End...\n\n");
	printf("******************************************************************************************\n\n");

	fclose(pfile);
	free(buffer);

	return 0;
}
