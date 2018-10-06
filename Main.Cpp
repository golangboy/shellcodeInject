#include <Windows.h>
#include <iostream>
#include <tchar.h>
using namespace std;
#define ShellCode长度  18
#pragma comment(lib,"Advapi32.lib")
BOOL GetDebugPrivilege();
BOOL ShellCode注入(char *szDllPath, DWORD 进程ID)
{
	/* 打开进程 */
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, 进程ID);

	/* 分配地址 代码[17]*/
	DWORD 旧的访问权限 = 0;
	LPVOID pVoidAdd = 0;
	pVoidAdd = VirtualAllocEx(hProcess, NULL, ShellCode长度, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	/*分配dllPath */
	UINT dllPathLength = lstrlenA(szDllPath) + 1;
	LPVOID dllPath = 0;
	dllPath = VirtualAllocEx(hProcess, NULL, dllPathLength, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	/* 写入DLL路径 */
	WriteProcessMemory(hProcess, dllPath, szDllPath, dllPathLength, NULL);

	/* 构造ShellCode */
	UCHAR ShellCode[ShellCode长度] = { 0x55 ,0x8B ,0xEC, 0x68 ,00 ,0x00 ,0x0C ,0x03 ,0xE8 ,0x92 ,0x49 ,0x9E ,0x72 ,0x8B ,0xE5 ,0x5D ,0xC3 ,0x90 };

	/* DLL路径部分 */
	CHAR Temp[4] = { 0 };
	memcpy(Temp, &dllPath, 4);
	ShellCode[4] = Temp[0];
	ShellCode[5] = Temp[1];
	ShellCode[6] = Temp[2];
	ShellCode[7] = Temp[3];

	/* call部分 */
	LPVOID LoadLibrary地址 = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	UINT callOffset = (int)LoadLibrary地址 - ((int)pVoidAdd + 6) - 2 - 5;
	memcpy(Temp, &callOffset, 4);
	ShellCode[9] = Temp[0];
	ShellCode[10] = Temp[1];
	ShellCode[11] = Temp[2];
	ShellCode[12] = Temp[3];

	/* 写入CODE */
	WriteProcessMemory(hProcess, pVoidAdd, ShellCode, ShellCode长度, NULL);
	DWORD 线程ID = 0;
	CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pVoidAdd, NULL, 0, &线程ID);

	/* 关闭句柄 */
	CloseHandle(hProcess);

	return true;
}

//提升进程权限
BOOL GetDebugPrivilege()
{
	HANDLE hToken;
	DWORD Ret = FALSE;
	TOKEN_PRIVILEGES TP;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		//printf("[-] Error in GetDebugPrivilege OpenProcessToken: %u\n", GetLastError());

		goto bye;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &TP.Privileges[0].Luid))
	{
		//printf("[-] Error in GetDebugPrivilege LookupPrivilegeValue: %u\n", GetLastError());

		goto bye;

	}

	TP.PrivilegeCount = 1;
	TP.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken,
		FALSE,
		&TP,
		0,
		NULL,
		NULL))
	{
		//printf("[-] Error in GetDebugPrivilege with  AdjustTokenPrivileges: %u\n", GetLastError());

		goto bye;
	}

	Ret = TRUE;
bye:
	CloseHandle(hToken);

	return Ret;
}
int _tmain(int argc, _TCHAR* argv[])
{

	GetDebugPrivilege();

	//进程PID
	DWORD dwPid = 0;
	cout << "Process ID:";
	cin >> dwPid;

	//Dll路径
	char szDll[MAX_PATH] = { 0 };
	cout << "Dll Path:";
	cin >> szDll;

	ShellCode注入(szDll, dwPid);
	return 0;
}
