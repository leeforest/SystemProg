#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include <stdlib.h>
#include <ctype.h>

// DLL���� EXPORT�� �Լ��� ������ ã�� �� �Լ��� ����� �� �ֵ��� �����͸� ����
// �ι�° ������ name�� �Լ��̸��� �Ѿ�� ���� �ְ� DWORD ��(������ �ǹ�)�� �Ѿ�� ���� ����(name�� ���ڿ����� �ƴ����� üũ�ϸ� ��)
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

	// 32/64 Ȯ��
	if ((int)ifh->Machine > 500) machine = 64;
	else machine = 32;

	// PE �ñ״��� Ȯ��
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

	// ������ ���ڿ��� ��츦 ����
	if (strstr(funcName, "0x") - funcName == 0) type = 1;
	else{
		if (atoi(funcName))	type = 2;
		else type = 3;
	}

	// EXPORT Address Table, Name Pointer Table, Ordinal Table�� ����
	funcAddr = (PDWORD)((PBYTE)handle + ied->AddressOfFunctions);
	funcNameAddr = (PDWORD)((PBYTE)handle + ied->AddressOfNames);
	ordNameAddr = (PWORD)((PBYTE)handle + ied->AddressOfNameOrdinals);

	if (ied->AddressOfFunctions == 0){
		printf("Error) No EXPORT Address Table\n");
		return NULL;
	}

	/* ������ ���� �ƴ� ��츦 ������ �� */
	// ������ �Էµ� ���
	if (type == 1){
		// Base: AddressOfNameOrdinals�� ���� ������ AddressOfNameOrdinals ���� Base ���� �� ���·� �����
		// AddressOfNameOrdinals: Ordinal �迭�� ��ġ�� ���� �ش� �Լ��� ������ Base ���� �����־�� ��
		//0x������ ���ڿ��� 16������ ��ȯ
		ordinal = strtol(funcName, NULL, 16); // ex) ordinal = 30 (DbgPrint)
		ordBase = (PDWORD)ied->Base;

		// �Է����� ���� ordinal ���� ordinal base���� ���� ��� ����ó��
		if ((int)ordinal < (int)ordBase)
		{
			printf("Error) Min Ordinal Vaule is: 0x%x(Ordinal Base)\n", ordBase);
			return NULL;
		}
		ordinal = ordinal - (int)ordBase;

		// �Է����� ���� ordinal ���� �ִ� ordinal ������ ū ��� ����ó��
		if ((int)ordinal >= (int)ied->NumberOfFunctions){
			printf("Error) Max Ordinal Vaule is: 0x%x\n", ied->NumberOfFunctions);
			return NULL;
		}
		result = (PBYTE)handle + funcAddr[ordinal];
		// printf("%d %x", ordinal, ordinal); 40, 28
		return result;
	}
	// 10������ �Էµ� ���
	else if (type == 2){
		// 10���� ���ڿ��� ������ ��ȯ
		ordinal = (int)atoi(funcName);
		ordBase = (PDWORD)ied->Base;

		// �Է����� ���� ordinal ���� ordinal base���� ���� ��� ����ó��
		if ((int)ordinal < (int)ordBase)
		{
			printf("Error) Min Ordinal Vaule is: 0x%x(Ordinal Base)\n", ordBase);
			return NULL;
		}
		ordinal = ordinal - (int)ordBase;

		// �Է����� ���� ordinal ���� �ִ� ordinal ������ ū ��� ����ó��
		if ((int)ordinal >= (int)ied->NumberOfFunctions){
			printf("Error) Max Ordinal Vaule is: 0x%x\n", ied->NumberOfFunctions);
			return NULL;
		}
		result = (PBYTE)handle + funcAddr[ordinal];
		return result;
	}
	// �Լ� �̸��� ���
	else{
		char* forward;
		char* forward_function;
		char* forward_dll;
		int dll_size;
		wchar_t* forward_dll_;

		for (index = 0; index < ied->NumberOfFunctions; index++){
			funcNamePointer = (PBYTE)handle + funcNameAddr[index];

			// ���� �Լ� �̸��� ã���� ���
			// ordNameAddr[index]: EXPORT Ordinal Table�� Data�� ����
			if (strcmp(funcNamePointer, funcName) == 0){
				orIndex = ordNameAddr[index];
				
				// Export ������ ó���� ���� ���� �˻�
				if (funcAddr[orIndex] > ioh->DataDirectory[0].VirtualAddress && ioh->DataDirectory[0].VirtualAddress + ioh->DataDirectory[0].Size)
				{
					//printf("funcName: %s\n", funcNamePointer);
					//printf("DataDirectory[0].VirtualAddress: %x\n", ioh->DataDirectory[0].VirtualAddress);

					// �������� ��쿡 ���Ͽ� export_dll �� �Լ� �̸��� �Ľ���
					// FuncnamePointer���� ���ڿ� ����+1(null)��ŭ ������ �̵�
					forward = funcNamePointer + strlen(funcName) + 1;
					forward_function = strstr(forward, ".") + 1;

					//printf("forward: %s\n", forward); //NTDLL.RtlInterlockedPushListSList
					//printf("forward_function: %s\n", forward_function); //RtlInterlockedPushListSList

					// forward_function �ּҿ��� forward �ּҸ� ���� dll �κ��� ���̸� ����
					dll_size = (int)forward_function - (int)forward;
					// dll ���̸�ŭ �Ҵ���
					forward_dll = malloc(dll_size - 1);

					for (i = 0; i < dll_size - 1; i++){
						forward_dll[i] = tolower(*(forward + i)); //�ҹ��ڷ� ����
					}
					// .dll �߰�
					forward_dll[dll_size - 1] = '.';
					forward_dll[dll_size - 0] = 'd';
					forward_dll[dll_size + 1] = 'l';
					forward_dll[dll_size + 2] = 'l';
					// dll �̸� �������� NULL �����Ͽ� ������
					forward_dll[dll_size + 3] = NULL;
					//printf("%s\n", forward_dll); // ex) ntdll.dll ����

					// dll �ε� �õ�!, ���̵�ĳ���ͷ� ����ȯ
					forward_dll_ = (wchar_t*)malloc(sizeof(wchar_t)*strlen(forward_dll));
					mbstowcs(forward_dll_, forward_dll, sizeof(wchar_t)*strlen(forward_dll));
					handle = LoadLibrary((wchar_t*)forward_dll_);
					//printf("handle: %x\n", handle);
					// �ε嵵 ����
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

	// �Ű������� ������ �Լ��� ������ NULL�� ��ȯ
	return NULL;
}