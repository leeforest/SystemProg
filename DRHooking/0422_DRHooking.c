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
	mbstowcs(processname, argv[1], sizeof(wchar_t)*strlen(argv[1])); //목표 프로세스

	LPCSTR Address = argv[2]; //변경할 DR 주소
	int MyAddress = strtol(Address, NULL, 16);

	//프로세스 정보를 담을 구조체
	PROCESSENTRY32 pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32);

	//스레드 정보를 담을 구조체
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	//스레드 Context를 담을 구조체
	CONTEXT ctx;
	//ctx.ContextFlags = CONTEXT_CONTROL;
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

	//목표 프로세스를 찾은 후 PID를 얻음
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

	//스레드 정보를 얻음
	//printf("[*] Current Debug Register\n");
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hProcess, &te32)){
		do{
			//목표 프로세스 PID와 같은 프로세스의 스레드일 경우, 각 스레드의 핸들과 콘텍스트를 얻음
			if (te32.th32OwnerProcessID == processID){
				//printf("- ThreadID: %X / ", te32.th32ThreadID);
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				
				SuspendThread(hThread);
				GetThreadContext(hThread, &ctx);
				//printf("Dr0: %08X\n", ctx.Dr0);

				//DR0(첫번째 Hardware BP) 변경
				ctx.Dr0 = MyAddress;

				//DR7(Debug Control Register) 설정
				//ex) 0x30001 = 00000000 00000011 00000000 00000001 (L0 설정, RW0 설정)
				ctx.Dr7 = (DWORD)0x30001;

				//변경한 스레드 콘텍스트 설정
				SetThreadContext(hThread, &ctx);
				ResumeThread(hThread);
				CloseHandle(hThread);
			}
		} while (Thread32Next(hProcess, &te32));
	}
	CloseHandle(hProcess);

	//제대로 변경되었는지 확인
	printf("[*] Changed Debug Register\n");
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hProcess, &te32)){
		do{
			//목표 프로세스 PID와 같은 스레드일 경우 목표 프로세스 내의 각 스레드의 핸들과 콘텍스트를 얻음
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