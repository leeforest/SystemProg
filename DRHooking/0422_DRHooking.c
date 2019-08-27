#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <Windows.h>
#include <TlHelp32.h>
#include <wchar.h>

int main(int argc, char *argv[])
{
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	DWORD processID;
	wchar_t processname[] = { 0, };
	mbstowcs(processname, argv[1], sizeof(wchar_t)*strlen(argv[1])); //��ǥ ���μ���

	LPCSTR Address = argv[2]; //������ DR �ּ�
	int MyAddress = strtol(Address, NULL, 16);

	//���μ��� ������ ���� ����ü
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//������ ������ ���� ����ü
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	//������ Context�� ���� ����ü
	CONTEXT ctx;
	//ctx.ContextFlags = CONTEXT_CONTROL;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	//��ǥ ���μ����� ã�� �� PID�� ����
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hProcess == INVALID_HANDLE_VALUE)
	{
		printf("CreateToolhelp32Snapshot Failed\n");
		exit(1);
	}
	else{
		if (Process32First(hProcess, &pe32)){
			while (Process32Next(hProcess, &pe32)){
				if (lstrcmpW(pe32.szExeFile, processname) == 0){
					printf("[*] Find process: ");
					wprintf(_T("%s\n"), pe32.szExeFile);
					printf("[*] Get PID: ");
					wprintf(_T("%d\n\n"), pe32.th32ProcessID);
					processID = pe32.th32ProcessID;
				}
			}
		}
	}
	CloseHandle(hProcess);

	//������ ������ ����
	//printf("[*] Current Debug Register\n");
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hProcess, &te32)){
		do{
			//��ǥ ���μ��� PID�� ���� ���μ����� �������� ���, �� �������� �ڵ�� ���ؽ�Ʈ�� ����
			if (te32.th32OwnerProcessID == processID){
				//printf("- ThreadID: %X / ", te32.th32ThreadID);
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				
				SuspendThread(hThread);
				GetThreadContext(hThread, &ctx);
				//printf("Dr0: %08X\n", ctx.Dr0);

				//DR0(ù��° Hardware BP) ����
				ctx.Dr0 = MyAddress;

				//DR7(Debug Control Register) ����
				//ex) 0x30001 = 00000000 00000011 00000000 00000001 (L0 ����, RW0 ����)
				ctx.Dr7 = (DWORD)0x30001;

				//������ ������ ���ؽ�Ʈ ����
				SetThreadContext(hThread, &ctx);
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hProcess, &te32));
	}
	CloseHandle(hProcess);

	//����� ����Ǿ����� Ȯ��
	printf("[*] Changed Debug Register\n");
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hProcess, &te32)){
		do{
			//��ǥ ���μ��� PID�� ���� �������� ��� ��ǥ ���μ��� ���� �� �������� �ڵ�� ���ؽ�Ʈ�� ����
			if (te32.th32OwnerProcessID == processID){
				printf("- ThreadID: %X / ", te32.th32ThreadID);
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

				SuspendThread(hThread);
				GetThreadContext(hThread, &ctx);
				printf("Dr0: %08X", ctx.Dr0);
				printf("\n");

				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hProcess, &te32));
	}
	CloseHandle(hProcess);
	system("pause");

	return 0;
}