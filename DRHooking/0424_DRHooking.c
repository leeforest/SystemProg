#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <tchar.h>
#include <TlHelp32.h>
#include <wchar.h>
#define ThreadQuerySetWin32StartAddress 9  

typedef NTSTATUS(WINAPI *NtQueryInformationThreadT)(HANDLE ThreadHandle, ULONG ThreadInformationClass, 
	PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

CONTEXT ctx;
HANDLE hThread_backup;
PVOID EntryPoint;

VOID EIPModify()
{
	printf("EIP Modified\n");
	return 0;
}

DWORD WINAPI DebugHookHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	printf("[*] In VEH Handler, DR Hooking Success\n");
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;
	SuspendThread(hThread_backup);
	GetThreadContext(hThread_backup, &ctx);
	
	//EIP를 스레드 시작 주소로 다시 변경함
	ctx.Eip = EntryPoint;
	SetThreadContext(hThread_backup, &ctx);
	ResumeThread(hThread_backup);
}

DWORD WINAPI ThreadFunction(LPVOID pvoid)
{
	while (1)
	{
		Sleep(500);
		printf("Wait for DR Hooking\n"); //얘를 안나오게!
	}
	return 0;
}

DWORD WINAPI DRHooking(LPVOID pvoid)
{
	int pid = 0;
	int count = 0;
	char *string = "EIP Modified\n";
	//CONTEXT ctx;
	HANDLE hProcess = NULL;
	HANDLE hThread = NULL;
	FARPROC funcAddr = NULL;
	PVOID startaddr = NULL;
	LONG status;
	BOOL result;
	unsigned char* mem=malloc(100);
	CHAR Buffer[0x100];

	int i = 0;
	funcAddr = GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "Sleep");

	//스레드 정보를 담을 구조체
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	//현재 프로세스의 PID를 얻음
	pid = getpid();
	printf("[-] Current Process PID: %X\n", pid);

	//ContextFlag를 설정함
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

	//스레드 정보를 얻음
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hProcess, &te32)){
		do{
			//목표 프로세스 PID와 같은 프로세스의 스레드일 경우, 각 스레드의 핸들과 콘텍스트를 얻음
			if (te32.th32OwnerProcessID == pid){

				//스레드 시작 주소를 구함
				GetThreadStartAddress(te32.th32ThreadID, &EntryPoint);
				printf("Thread EntryPoint: %X\n", EntryPoint);
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				if (hThread == NULL)
				{
					printf("OpenThread Failed\n");
					exit(1);
				}

				printf("\n[-] Current Debug Register Info\n");
				Sleep(1000);
				SuspendThread(hThread);
				GetThreadContext(hThread, &ctx);
				printf("Dr0: %08X\n", ctx.Dr0);
				printf("Dr7: %08X\n", ctx.Dr7);

				//Dr0, Dr7 조작
				ctx.Dr0 = funcAddr;
				ctx.Dr7 |= 0x00000001;
				hThread_backup = hThread;
				printf("\n[*] Changed Debug Register Info\n");
				printf("Dr0: %08X\n", ctx.Dr0);
				printf("Dr7: %08X\n", ctx.Dr7);
				SetThreadContext(hThread, &ctx);
				ResumeThread(hThread);
			}
		} while (Thread32Next(hProcess, &te32));
	}
	CloseHandle(hProcess);
}

BOOL GetThreadStartAddress(DWORD tid, PVOID *EntryPoint)
{
	PVOID ThreadInfo;
	ULONG ThreadInfoLength;
	PULONG ReturnLength;

	//NtQueryInformationThread 함수를 사용하여 스레드 시작 주소를 얻음
	NtQueryInformationThreadT NtQueryInformationThread = (NtQueryInformationThreadT)GetProcAddress(GetModuleHandle(TEXT("ntdll")), "NtQueryInformationThread");

	if (!NtQueryInformationThread)
	{
		printf("Get NtQueryInformationThread Failed\n");
		exit(0);
	}

	/* if NtQueryInformationThread's THREADINFOCALSS is a ThreadQurtySetWin32StartAddress, return start address of thread */
	HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, 0, tid);
	NTSTATUS NtStat = NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &ThreadInfo, sizeof(ThreadInfo), NULL);

	*EntryPoint = ThreadInfo;
}

int main(void)
{
	HANDLE hThread = NULL;
	HANDLE hThread_ = NULL;

	//VEH 예외 핸들러 등록 
	//하드웨어 브레이크 예외가 발생 시, VEH 예외 핸들러가 실행됨
	AddVectoredExceptionHandler(0, DebugHookHandler);

	//테스트 스레드
	hThread = CreateThread(NULL, 0, ThreadFunction, NULL, 0, NULL);
	if (hThread == NULL)
	{
		printf("[-] CreateThrad Failed\n");
		exit(1);
	}

	//hThread를 쓰지 않고 직접 스레드를 찾게 하는 방식으로 수정함
	//DR 조작을 수행하는 스레드
	hThread_ = CreateThread(NULL, 0, DRHooking, NULL, 0, NULL);
	if (hThread_ == NULL)
	{
		printf("[-] CreateThrad Failed\n");
		exit(1);
	}

	WaitForSingleObject(hThread, INFINITE);
	WaitForSingleObject(hThread_, INFINITE);

	system("pause");

	return 0;
}