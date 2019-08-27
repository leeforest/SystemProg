#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>

HANDLE hThread = NULL;

DWORD WINAPI DebugHookHandler(PEXCEPTION_POINTERS ExceptionInfo)
{
	MessageBox(NULL, L"DR Hooking Success !!\n", L"In VEH Handler!!!", MB_OK);
	return 0;
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
	CONTEXT ctx;
	int EIP_backup;
	int res;

	//조작할 DR 주소를 얻기 위한 EIP 백업
	ctx.ContextFlags = CONTEXT_CONTROL;
	Sleep(1000);
	SuspendThread(hThread);
	GetThreadContext(hThread, &ctx);
	EIP_backup = ctx.Eip;
	printf("\n[-] EIP Backup: %X\n", EIP_backup);
	ResumeThread(hThread);

	//DR0, DR7 조작
	ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
	Sleep(1000);
	SuspendThread(hThread);
	printf("Thread Stop...............\n");
	GetThreadContext(hThread, &ctx);

	printf("\n[-] Current Debug Register Info\n");
	printf("- Dr0: %X\n", ctx.Dr0);
	printf("- Dr7: %X\n", ctx.Dr7);

	printf("\n[*] Changed Debug Register Info\n");
	ctx.Dr0 = EIP_backup;
	ctx.Dr7 |= 0x00000001;
	printf("- EIP: %X\n", ctx.Eip);
	printf("- Dr0: %X\n", ctx.Dr0);
	printf("- Dr7: %X\n", ctx.Dr7);
	SetThreadContext(hThread, &ctx);
	ResumeThread(hThread);
}

int main(void)
{
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
	
	//DR을 조작할 스레드
	hThread_ = CreateThread(NULL, 0, DRHooking, NULL, 0, NULL);
	if (hThread_ == NULL)
	{
		printf("[-] CreateThrad Failed\n");
		exit(1);
	}
	printf("[-] ThreadID: %X\n", hThread);
	
	WaitForSingleObject(hThread, INFINITE);
	WaitForSingleObject(hThread_, INFINITE);

	system("pause");

	return 0;
}