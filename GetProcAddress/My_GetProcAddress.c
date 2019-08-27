#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdlib.h>
#include <ctype.h>

// DLL에서 EXPORT한 함수의 번지를 찾아 그 함수를 사용할 수 있도록 포인터를 리턴
// 두번째 인자인 name은 함수이름이 넘어올 수도 있고 DWORD 값(서수를 의미)이 넘어올 수도 있음(name이 문자열인지 아닌지를 체크하면 됨)
FARPROC My_GetProcAddress(HMODULE handle, LPCSTR funcName)
{
	int i = 0;
	int error = 0;
	int type = 0;
	int cal = 0;
	int ordinal = 0;
	int machine = 0;
	PDWORD funcAddr;
	PDWORD funcNameAddr;
	PDWORD ordBase = 0;
	PWORD ordNameAddr;
	PCSTR funcNamePointer;
	DWORD index = 0;
	WORD orIndex = 0;
	FARPROC *result;

	PIMAGE_DOS_HEADER idh = (PBYTE)handle;
	PIMAGE_NT_HEADERS inh = (PBYTE)handle + idh->e_lfanew;
	PIMAGE_FILE_HEADER ifh = (PBYTE)handle + idh->e_lfanew + 4;
	PIMAGE_OPTIONAL_HEADER ioh = (PBYTE)handle + idh->e_lfanew + 4 + sizeof(struct _IMAGE_FILE_HEADER);
	PIMAGE_EXPORT_DIRECTORY ied = (PBYTE)handle + ioh->DataDirectory[0].VirtualAddress;

	// 32/64 확인
	if ((int)ifh->Machine > 500) machine = 64;
	else machine = 32;

	// PE 시그니쳐 확인
	if (idh->e_magic == IMAGE_DOS_SIGNATURE)
		if (inh->Signature == IMAGE_NT_SIGNATURE)
			printf("[-] PE Check: Valid\n\n");
		else{
			printf("[-] PE Check: Invalid\n");
			exit(1);
		}
	else{
		printf("[-] PE Check: Invalid\n");
		exit(1);
	}

	// 서수와 문자열인 경우를 구분
	if (strstr(funcName, "0x") - funcName == 0) type = 1;
	else{
		if (atoi(funcName))	type = 2;
		else type = 3;
	}

	// EXPORT Address Table, Name Pointer Table, Ordinal Table에 접근
	funcAddr = (PDWORD)((PBYTE)handle + ied->AddressOfFunctions);
	funcNameAddr = (PDWORD)((PBYTE)handle + ied->AddressOfNames);
	ordNameAddr = (PWORD)((PBYTE)handle + ied->AddressOfNameOrdinals);

	if (ied->AddressOfFunctions == 0){
		printf("Error) No EXPORT Address Table\n");
		return NULL;
	}

	/* 서수인 경우와 아닌 경우를 나눠야 함 */
	// 서수가 입력된 경우
	if (type == 1){
		// Base: AddressOfNameOrdinals의 시작 서수로 AddressOfNameOrdinals 값은 Base 값을 뺀 형태로 저장됨
		// AddressOfNameOrdinals: Ordinal 배열의 위치로 실제 해당 함수의 서수는 Base 값을 더해주어야 함
		//0x형태의 문자열을 16진수로 변환
		ordinal = strtol(funcName, NULL, 16); // ex) ordinal = 30 (DbgPrint)
		ordBase = (PDWORD)ied->Base;

		// 입력으로 들어온 ordinal 값이 ordinal base보다 작은 경우 에러처리
		if ((int)ordinal < (int)ordBase)
		{
			printf("Error) Min Ordinal Vaule is: 0x%x(Ordinal Base)\n", ordBase);
			return NULL;
		}
		ordinal = ordinal - (int)ordBase;

		// 입력으로 들어온 ordinal 값이 최대 ordinal 값보다 큰 경우 에러처리
		if ((int)ordinal >= (int)ied->NumberOfFunctions){
			printf("Error) Max Ordinal Vaule is: 0x%x\n", ied->NumberOfFunctions);
			return NULL;
		}
		result = (PBYTE)handle + funcAddr[ordinal];
		// printf("%d %x", ordinal, ordinal); 40, 28
		return result;
	}
	// 10진수가 입력된 경우
	else if (type == 2){
		// 10진수 문자열을 정수로 변환
		ordinal = (int)atoi(funcName);
		ordBase = (PDWORD)ied->Base;

		// 입력으로 들어온 ordinal 값이 ordinal base보다 작은 경우 에러처리
		if ((int)ordinal < (int)ordBase)
		{
			printf("Error) Min Ordinal Vaule is: 0x%x(Ordinal Base)\n", ordBase);
			return NULL;
		}
		ordinal = ordinal - (int)ordBase;

		// 입력으로 들어온 ordinal 값이 최대 ordinal 값보다 큰 경우 에러처리
		if ((int)ordinal >= (int)ied->NumberOfFunctions){
			printf("Error) Max Ordinal Vaule is: 0x%x\n", ied->NumberOfFunctions);
			return NULL;
		}
		result = (PBYTE)handle + funcAddr[ordinal];
		return result;
	}
	// 함수 이름인 경우
	else{
		char* forward;
		char* forward_function;
		char* forward_dll;
		int dll_size;
		wchar_t* forward_dll_;

		for (index = 0; index < ied->NumberOfFunctions; index++){
			funcNamePointer = (PBYTE)handle + funcNameAddr[index];

			// 같은 함수 이름을 찾았을 경우
			// ordNameAddr[index]: EXPORT Ordinal Table의 Data가 나옴
			if (strcmp(funcNamePointer, funcName) == 0){
				orIndex = ordNameAddr[index];
				
				// Export 포워딩 처리를 위한 영역 검사
				if (funcAddr[orIndex] > ioh->DataDirectory[0].VirtualAddress && ioh->DataDirectory[0].VirtualAddress + ioh->DataDirectory[0].Size)
				{
					//printf("funcName: %s\n", funcNamePointer);
					//printf("DataDirectory[0].VirtualAddress: %x\n", ioh->DataDirectory[0].VirtualAddress);

					// 포워딩인 경우에 대하여 export_dll 및 함수 이름을 파싱함
					// FuncnamePointer에서 문자열 길이+1(null)만큼 포인터 이동
					forward = funcNamePointer + strlen(funcName) + 1;
					forward_function = strstr(forward, ".") + 1;

					//printf("forward: %s\n", forward); //NTDLL.RtlInterlockedPushListSList
					//printf("forward_function: %s\n", forward_function); //RtlInterlockedPushListSList

					// forward_function 주소에서 forward 주소를 빼서 dll 부분의 길이를 구함
					dll_size = (int)forward_function - (int)forward;
					// dll 길이만큼 할당함
					forward_dll = malloc(dll_size - 1);

					for (i = 0; i < dll_size - 1; i++){
						forward_dll[i] = tolower(*(forward + i)); //소문자로 저장
					}
					// .dll 추가
					forward_dll[dll_size - 1] = '.';
					forward_dll[dll_size - 0] = 'd';
					forward_dll[dll_size + 1] = 'l';
					forward_dll[dll_size + 2] = 'l';
					// dll 이름 마지막에 NULL 삽입하여 끝내기
					forward_dll[dll_size + 3] = NULL;
					//printf("%s\n", forward_dll); // ex) ntdll.dll 나옴

					// dll 로드 시도!, 와이드캐릭터로 형변환
					forward_dll_ = (wchar_t*)malloc(sizeof(wchar_t)*strlen(forward_dll));
					mbstowcs(forward_dll_, forward_dll, sizeof(wchar_t)*strlen(forward_dll));
					handle = LoadLibrary((wchar_t*)forward_dll_);
					//printf("handle: %x\n", handle);
					// 로드도 실패
					if (handle == NULL){
						error = GetLastError();
						printf("\nError) Forward DLL LoadLibrary Error Code: %d\n", error);
						exit(1);
					}
					else {
						printf("-----------------------------------[Forward Name RSA Prosessing]------------------------------------\n");
						printf("[-] Forward DLL: %s\n", forward_dll);
						printf("[-] Forward function: %s\n", forward_function);
						printf("[-] Load Forward DLL(%s) Success\n", forward_dll);
						printf("----------------------------------------------------------------------------------------------------\n");
					}
					printf("\n");
					
					result = My_GetProcAddress(handle, forward_function);
					//printf("Forward result: %x\n", forward_function);
					return result;
				}
				else{
					result = (PBYTE)handle + funcAddr[orIndex];
					//printf("DataDirectory[0].VirtualAddress: %x\n", ioh->DataDirectory[0].VirtualAddress);
					//printf("funcAddr[orIndex]: %x\n", funcAddr[orIndex]);
				return result;
				}
			}
		}
	}

	// 매개변수에 지정된 함수가 없으면 NULL을 반환
	return NULL;
}