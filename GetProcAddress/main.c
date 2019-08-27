#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdlib.h>

/* ������ ���� �Լ� �ּ� ���*/
// 1) �Լ� �̸����� �Լ� �ּ� ã��
//   1.1) AddressOfNames�� ����� �˻��ϸ� ã������ �ϴ� �Լ� �̸��� ��� �ε����� ��ġ�ϴ��� �� �� ����(index)
//   1.2) ã�� �ε����� AddressOfNameOrdinals�� �����ϸ� �ش� �Լ� �̸��� ������ ������ �� �� ����(�̶��� ������ ���� ���������� Base�� ���� ����)(AddressOfNameOrdinals[index])
//   1.3) ã�� ���������� AddressOfFunctions�� �����ϸ� �ش� �Լ��� �����ϴ� �ּҸ� �� �� ����(AddressOfFunctions[AddressOfNameOrdinals[index]])
// 2) ������ �Լ� �ּ� ã��
//   2.1) AddressOfFunctions�� �Լ� �ּ� �ε����� �������� Base�� �� �������̹Ƿ� �Է����� ���� �������� Base�� ���� AddressOfFunctions�� �����ϸ� ��

// main�������� �Ѿ�� PE File�� �������� ���μ����� ��� OpenProcess�� ���� handle�� ��� �������� ���μ����� �ƴ϶�� LoadLibrary�� ���� �ε带 �õ��մϴ�.
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

	printf("GetProcAddress ���� �����Դϴ�.\n");
	printf("main������ ���Ͽ� ���� �ڵ��� ���, 'MyGetProcAddress(HMODULE hmodule, LPCSTR lpProcName)'�� ȣ���մϴ�.\n\n");
	printf("----------------------------------------------------------------------------------------------------\n");
	printf(" Usage: GetProcAddress.exe [handle�� ���� PE ����] [�Լ��� OR ������(16������ ��� 0x�� ǥ��)]\n");
	printf(" Ex - 1) GetProcAddress.exe C:\\Windows\\System32\\ntdll.dll DbgPrint\n");
	printf(" Ex - 2) GetProcAddress.exe C:\\Windows\\System32\\ntdll.dll 0x30\n");
	printf(" Ex - 1) GetProcAddress.exe C:\\Windows\\System32\\ntdll.dll 48\n");
	printf("----------------------------------------------------------------------------------------------------\n\n");

	if (argc < 3) {
		printf("Error) Check Usage...\n\n");
		exit(1);
	}

	funcName = argv[2];

	// ��Ƽ����Ʈ ��Ʈ��(argv[1])�� ���̵� ���� ��Ʈ������ ��ȯ(dllName)
	mbstowcs(dllName, argv[1], sizeof(wchar_t)*strlen(argv[1]));

	// ������ ���ڿ��� ��츦 ����
	if (strstr(funcName, "0x") - funcName == 0) type = 1;
	else{
		if (atoi(funcName))	type = 2;
		else type = 3;
	}

	// PE ������ �ε��Ŵ, �޸𸮿� �ö󰡰� ��
	printf("[-] PE File: ");
	for (i = 0; i < strlen(argv[1]); i++) printf("%c", *(dllName + i));
	if (type == 3) printf("\n[-] lpProcName Type: Function Name(%s)\n", funcName);
	else printf("\n[-] Function Type: Ordinal(%s)\n", funcName);

	// LoadLibrary�� ����� PE File �ε带 �õ�
	printf("[-] FindWindow Failed.. Try Load PE File...\n");
	printf("\n[-] Load PE File...\n");
	// PE File �ε�
	handle = LoadLibrary(dllName);
	// �ε嵵 ����
	if (handle == NULL){
		error = GetLastError();
		printf("\nError) LoadLibrary Error Code: %d\n", error);
		exit(1);
	}

	// My_GetProcAddress ȣ��
	funcAddr = My_GetProcAddress(handle, funcName);
	if (funcAddr == 0) {
		printf("Error) My_GetProcAddress Failure\n\n");
		//exit(1);
	}
	printf("-------------------------------------[GetProcAddress Result]----------------------------------------\n");
	printf("[*] My_GetProcAddress :%X\n", funcAddr);
	if (type == 1) {
		//0x ������ ���ڿ��� 16������ ��ȯ
		ordinal = strtol(funcName, NULL, 16);
		printf("[*] GetProcAddress    :%X\n", GetProcAddress(handle, ordinal));
	}
	else if (type == 2) {
		// ���ڿ��� 10������ ��ȯ
		ordinal = (int)atoi(funcName);
		printf("[*] GetProcAddress    :%X\n", GetProcAddress(handle, ordinal));
	}
	else printf("[*] GetProcAddress    :%X\n", GetProcAddress(handle, funcName));
	printf("----------------------------------------------------------------------------------------------------\n\n");

	system("pause");
	return 0;
}
