#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdlib.h>

/* 서수를 통한 함수 주소 얻기*/
// 1) 함수 이름으로 함수 주소 찾기
//   1.1) AddressOfNames를 사용해 검색하면 찾으려고 하는 함수 이름이 어느 인덱스에 위치하는지 알 수 있음(index)
//   1.2) 찾은 인덱스로 AddressOfNameOrdinals에 접근하면 해당 함수 이름의 서수가 얼마인지 알 수 있음(이때의 서수는 실제 서수값에서 Base가 빼진 상태)(AddressOfNameOrdinals[index])
//   1.3) 찾은 서수값으로 AddressOfFunctions에 접근하면 해당 함수가 존재하는 주소를 알 수 있음(AddressOfFunctions[AddressOfNameOrdinals[index]])
// 2) 서수로 함수 주소 찾기
//   2.1) AddressOfFunctions의 함수 주소 인덱스는 서수에서 Base를 뺀 서수값이므로 입력으로 들어온 서수값에 Base를 빼서 AddressOfFunctions에 접근하면 됨

// main문에서는 넘어온 PE File이 실행중인 프로세스일 경우 OpenProcess를 통해 handle을 얻고 실행중인 프로세스가 아니라면 LoadLibrary를 통해 로드를 시도합니다.
int main(int argc, char *argv[])
{
	int i = 0;
	int type = 0;
	int error = 0;
	int ordinal = 0;
	int count = 0;
	HWND hwnd;
	DWORD pid, tid;
	HMODULE handle = 0;
	FARPROC funcAddr;
	LPCSTR funcName;
	wchar_t* dllName = (wchar_t*)malloc(sizeof(wchar_t)*strlen(argv[1]));

	printf("GetProcAddress 구현 과제입니다.\n");
	printf("main문에서 파일에 대한 핸들을 얻고, 'MyGetProcAddress(HMODULE hmodule, LPCSTR lpProcName)'을 호출합니다.\n\n");
	printf("----------------------------------------------------------------------------------------------------\n");
	printf(" Usage: GetProcAddress.exe [handle을 얻을 PE 파일] [함수명 OR 서수값(16진수인 경우 0x로 표기)]\n");
	printf(" Ex - 1) GetProcAddress.exe C:\\Windows\\System32\\ntdll.dll DbgPrint\n");
	printf(" Ex - 2) GetProcAddress.exe C:\\Windows\\System32\\ntdll.dll 0x30\n");
	printf(" Ex - 1) GetProcAddress.exe C:\\Windows\\System32\\ntdll.dll 48\n");
	printf("----------------------------------------------------------------------------------------------------\n\n");

	if (argc < 3) {
		printf("Error) Check Usage...\n\n");
		exit(1);
	}

	funcName = argv[2];

	// 멀티바이트 스트링(argv[1])을 와이드 문자 스트링으로 변환(dllName)
	mbstowcs(dllName, argv[1], sizeof(wchar_t)*strlen(argv[1]));

	// 서수와 문자열인 경우를 구분
	if (strstr(funcName, "0x") - funcName == 0) type = 1;
	else{
		if (atoi(funcName))	type = 2;
		else type = 3;
	}

	// PE 파일을 로드시킴, 메모리에 올라가게 됨
	printf("[-] PE File: ");
	for (i = 0; i < strlen(argv[1]); i++) printf("%c", *(dllName + i));
	if (type == 3) printf("\n[-] lpProcName Type: Function Name(%s)\n", funcName);
	else printf("\n[-] Function Type: Ordinal(%s)\n", funcName);

	// LoadLibrary를 사용해 PE File 로드를 시도
	printf("[-] FindWindow Failed.. Try Load PE File...\n");
	printf("\n[-] Load PE File...\n");
	// PE File 로드
	handle = LoadLibrary(dllName);
	// 로드도 실패
	if (handle == NULL){
		error = GetLastError();
		printf("\nError) LoadLibrary Error Code: %d\n", error);
		exit(1);
	}

	// My_GetProcAddress 호출
	funcAddr = My_GetProcAddress(handle, funcName);
	if (funcAddr == 0) {
		printf("Error) My_GetProcAddress Failure\n\n");
		//exit(1);
	}
	printf("-------------------------------------[GetProcAddress Result]----------------------------------------\n");
	printf("[*] My_GetProcAddress :%X\n", funcAddr);
	if (type == 1) {
		//0x 형태의 문자열을 16진수로 변환
		ordinal = strtol(funcName, NULL, 16);
		printf("[*] GetProcAddress    :%X\n", GetProcAddress(handle, ordinal));
	}
	else if (type == 2) {
		// 문자열을 10진수로 변환
		ordinal = (int)atoi(funcName);
		printf("[*] GetProcAddress    :%X\n", GetProcAddress(handle, ordinal));
	}
	else printf("[*] GetProcAddress    :%X\n", GetProcAddress(handle, funcName));
	printf("----------------------------------------------------------------------------------------------------\n\n");

	system("pause");
	return 0;
}
