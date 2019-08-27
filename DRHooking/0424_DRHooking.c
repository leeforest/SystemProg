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
	
	//EIP�� ������ ���� �ּҷ� �ٽ� ������
	ctx.Eip = EntryPoint;
	SetThreadContext(hThread_backup, &ctx);
	ResumeThread(hThread_backup);
}

DWORD WINAPI ThreadFunction(LPVOID pvoid)
{
	while (1)
	{
		Sleep(500);
		printf("Wait for DR Hooking\n"); //�긦 �ȳ�����!
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

	//������ ������ ���� ����ü
	THREADENTRY32 te32 = { 0 };
	te32.dwSize = sizeof(THREADENTRY32);

	//���� ���μ����� PID�� ����
	pid = getpid();
	printf("[-] Current Process PID: %X\n", pid);

	//ContextFlag�� ������
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS | CONTEXT_CONTROL;

	//������ ������ ����
	hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (Thread32First(hProcess, &te32)){
		do{
			//��ǥ ���μ��� PID�� ���� ���μ����� �������� ���, �� �������� �ڵ�� ���ؽ�Ʈ�� ����
			if (te32.th32OwnerProcessID == pid){

				//������ ���� �ּҸ� ����
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

				//Dr0, Dr7 ����
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

	//NtQueryInformationThread �Լ��� ����Ͽ� ������ ���� �ּҸ� ����
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

	//VEH ���� �ڵ鷯 ��� 
	//�ϵ���� �극��ũ ���ܰ� �߻� ��, VEH ���� �ڵ鷯�� �����
	AddVectoredExceptionHandler(0, DebugHookHandler);

	//�׽�Ʈ ������
	hThread = CreateThread(NULL, 0, ThreadFunction, NULL, 0, NULL);
	if (hThread == NULL)
	{
		printf("[-] CreateThrad Failed\n");
		exit(1);
	}

	//hThread�� ���� �ʰ� ���� �����带 ã�� �ϴ� ������� ������
	//DR ������ �����ϴ� ������
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