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
		printf("Wait for DR Hooking\n"); //�긦 �ȳ�����!
	}
	return 0;
}

DWORD WINAPI DRHooking(LPVOID pvoid)
{
	CONTEXT ctx;
	int EIP_backup;
	int res;

	//������ DR �ּҸ� ��� ���� EIP ���
	ctx.ContextFlags = CONTEXT_CONTROL;
	Sleep(1000);
	SuspendThread(hThread);
	GetThreadContext(hThread, &ctx);
	EIP_backup = ctx.Eip;
	printf("\n[-] EIP Backup: %X\n", EIP_backup);
	ResumeThread(hThread);

	//DR0, DR7 ����
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
	
	//DR�� ������ ������
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