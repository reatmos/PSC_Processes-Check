/*
Script to check Process with Virustotal API
Made by Reamos
Github : reatmos
Twitter : @Pa1ath
Blog : https://re-atmosphere.tistory.com/
*/

#include <windows.h>
#include <stdio.h>
#include <tchar.h>
#include <psapi.h>
#include <fstream>
#include <iostream>
#include <TlHelp32.h>
#include <sqlite3.h>
#include <direct.h>
#include <Python.h>
#include <openssl/sha.h>

using namespace std;

#ifdef _UNICODE
#define tcout wcout
#define tcerr wcerr
#else
#define tcout cout
#define tcerr cerr
#endif

PROCESSENTRY32 pe32 = { 0, };
const char* db = "C:\\PS\\Process.db";
TCHAR pPath[MAX_PATH];
char pHash[MAX_PATH];
int stop = 0;

int AnsiToUTF8(char* szSrc, char* strDest, int destSize)
{
    setlocale(LC_ALL, "");
    WCHAR szUnicode[255];
    char szUTF8code[255];

    int nUnicodeSize = MultiByteToWideChar(CP_ACP, 0, szSrc, (int)strlen(szSrc), szUnicode, sizeof(szUnicode));
    int nUTF8codeSize = WideCharToMultiByte(CP_UTF8, 0, szUnicode, nUnicodeSize, szUTF8code, sizeof(szUTF8code), NULL, NULL);
    assert(destSize > nUTF8codeSize);
    memcpy(strDest, szUTF8code, nUTF8codeSize);
    strDest[nUTF8codeSize] = 0;
    return nUTF8codeSize;
}

// Insert values to DB
int insertData(const char* s)
{
    sqlite3* DB;
    char* messaggeError;

    int exit = sqlite3_open(s, &DB);
    setlocale(LC_ALL, "");
    char sql[MAX_PATH];
    // Encoding UTF-8 for Sqlite3
    char cPath[MAX_PATH];
    char szPath[MAX_PATH];
    WideCharToMultiByte(CP_ACP, 0, pPath, MAX_PATH, cPath, MAX_PATH, NULL, NULL);
    AnsiToUTF8(cPath, szPath, MAX_PATH);
    sprintf(sql, "INSERT INTO PROCESS(Process_Name, PID, Process_Path) VALUES('%S', '%d', '%s');", pe32.szExeFile, pe32.th32ProcessID, szPath);

    exit = sqlite3_exec(DB, sql, NULL, 0, &messaggeError);
    if (exit != SQLITE_OK) {
        cerr << "\nError : Invalid DB Value" << endl;
        sqlite3_free(messaggeError);
    }

    return 0;
}

// SHA256 Check Script
void PyProCheck()
{
    PyObject* pName, * pModule, * pFunc, * pValue;

    Py_Initialize();
    PyRun_SimpleString("import os, sys");
    PyRun_SimpleString("sys.path.append(os.getcwd() + '\\Scripts')");
    pName = PyUnicode_FromString("PyProCheck");
    pModule = PyImport_Import(pName);
    pFunc = PyObject_GetAttrString(pModule, "CheckVT");
    pValue = PyObject_CallObject(pFunc, NULL);
    Py_Finalize();
}

// Load Process List
void PyCallPDB()
{
    PyObject* pName, * pModule, * pFunc, * pValue;

    Py_Initialize();
    PyRun_SimpleString("import os, sys");
    PyRun_SimpleString("sys.path.append(os.getcwd() + '\\Scripts')");
    pName = PyUnicode_FromString("OutputPDB");
    pModule = PyImport_Import(pName);
    pFunc = PyObject_GetAttrString(pModule, "OutDB");
    pValue = PyObject_CallObject(pFunc, NULL);
    Py_Finalize();
}

int Calc_SHA256(WCHAR* tpath, char* toutput)
{
    setlocale(LC_ALL, "");
    std::ofstream fout;

    FILE* file = _wfopen(tpath, L"rb");
    if (!file)return -1;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    const int bufSize = 32768;
    unsigned char* buffer = (unsigned char*)malloc(bufSize);
    SHA256_CTX sha256;
    int bytesRead = 0;

    if (!buffer)return -2;

    SHA256_Init(&sha256);

    while ((bytesRead = fread(buffer, 1, bufSize, file))) {
        SHA256_Update(&sha256, buffer, bytesRead);
    }

    SHA256_Final(hash, &sha256);
    int i = 0;
    for (i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        sprintf(toutput + (i * 2), "%02x", hash[i]);
    }
    // Output SHA256 to file
    fout.open("C:\\PS\\Temp\\Hash.txt", std::ios_base::out | std::ios_base::app);
    fout << toutput << endl;
    fout.close();
    toutput = 0;
    fclose(file);

    return 0;
}

// Process Resume and Suspend
BOOL PauseResumeThreadList(const wchar_t* exe, int resume)
{
    HANDLE        hThreadSnap = NULL;
    BOOL          bRet = FALSE;
    THREADENTRY32 te32 = { 0 };
    DWORD dwOwnerPID = pe32.th32ProcessID;

    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE)
        return (FALSE); 

    te32.dwSize = sizeof(THREADENTRY32);

    if (Thread32First(hThreadSnap, &te32))
    {
        do
        {
            if (te32.th32OwnerProcessID == dwOwnerPID)
            {
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                // Process resume
                if (resume == 1)
                {
                    ResumeThread(hThread);
                }
                // Process suspend
                else if (resume == 0)
                {
                    SuspendThread(hThread);
                }
                CloseHandle(hThread);
            }
        } while (Thread32Next(hThreadSnap, &te32));
        bRet = TRUE;
    }
    else
        bRet = FALSE;

    CloseHandle(hThreadSnap);

    return (bRet);
}

// Get Process Path
int GetPath(DWORD p)
{
    HANDLE processHandle = NULL;
    setlocale(LC_ALL, "");

    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p);
    if (processHandle != NULL) {
        if (GetModuleFileNameEx(processHandle, NULL, pPath, MAX_PATH) == 0) {
            tcerr << "Failed to get module filename." << endl;
        }
        CloseHandle(processHandle);
    }

    return 0;
}

// Check Bundle Process
BOOL bundlecheck(const char* ms)
{
    char wname[MAX_PATH];
    sprintf(wname, "%S", pPath);
    char* wtr = strstr(wname, ms);
    if (wtr)
    {
        return TRUE;
    }
    else
    {
        return FALSE;
    }
}

int ProcessSnapshot()
{
    setlocale(LC_ALL, "");
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    int resume = 0;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hProcessSnap, &pe32))
    {
        _tprintf(_T("Process32First Error! \n"));
        CloseHandle(hProcessSnap);
        return -1;
    }

    do
    {
        int find = 0;
        char line[MAX_PATH];
        // Check there is process in Process list
        ifstream fin("C:\\PS\\Temp\\Temp.txt");
        if (fin.is_open())
        {
            while (fin.getline(line, sizeof(line)))
            {
                char pname[MAX_PATH];
                sprintf(pname, "%ws", pe32.szExeFile);
                char* ptr = strstr(line, pname);

                if (ptr != NULL)
                {
                    find = 1;
                    break;
                }
            }
            fin.close();
        }

        // If process isn't exsit in Process list
        if (find != 1)
        {
            GetPath(pe32.th32ProcessID);
            // If process is bundle process
            if (bundlecheck("Windows") || bundlecheck("Microsoft") || bundlecheck("OneDrive"))
            {
                insertData(db);
            }
            else if (bundlecheck("Process") || bundlecheck("PSC"))
            {
                insertData(db);
            }
            // If process isn't bundle process
            else
            {
                _tprintf(_T("\n%s : %d\n\n"), pe32.szExeFile, pe32.th32ProcessID);
                PauseResumeThreadList(pe32.szExeFile, 0);
                Calc_SHA256(pPath, pHash);
                PyProCheck();
                ifstream pResult("C:\\PS\\Temp\\Result.txt");
                // Result of SHA256 Check Script
                int pSafe = 0;
                if (pResult.is_open())
                {
                    pResult >> pSafe;
                    pResult.close();
                }

                // if process has not result
                if (pSafe == 0)
                {
                    printf("I don't know that this process is safe...\nDo you want to resume?\nIf you resume this process, Program is stop\nYes = 1, No = 2 : ");
                    scanf("%d", &resume);
                    // Process resume, Program stop
                    if (resume == 1)
                    {
                        PauseResumeThreadList(pe32.szExeFile, 1);
                        printf("\nIt's resume\n");
                        stop = 1;
                    }
                    // Process stop
                    else if (resume == 2)
                    {
                        DWORD dwExitCode = 0;
                        HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pe32.th32ProcessID);
                        if (TerminateProcess(hHandle, 0))
                        {
                            GetExitCodeProcess(hHandle, &dwExitCode);
                            printf("\nIt's kill\n\n=========================================\n\n");
                        }
                    }
                    // Keep process suspend
                    else
                    {
                        printf("\nOK, Skip\n\n=========================================\n\n");
                    }
                }
                // If process is safe
                else if (pSafe == 1)
                {
                    PauseResumeThreadList(pe32.szExeFile, 1);
                    insertData(db);
                    printf("\nIt's safe so resume and inesrt Database :)\n\n=========================================\n\n");
                }
                // If process is dangerous
                else if (pSafe == 2)
                {
                    DWORD dwExitCode = 0;
                    HANDLE hHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pe32.th32ProcessID);
                    if (TerminateProcess(hHandle, 0))
                    {
                        GetExitCodeProcess(hHandle, &dwExitCode);
                        printf("\nIt's so dangerous. So kill process\n\n=========================================\n\n");
                    }
                }
                // Other(ex. Error)
                else
                {
                    PauseResumeThreadList(pe32.szExeFile, 1);
                    printf("\nWTF? Error!!\n\n=========================================\n\n");
                }
            }
            
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return 0;
}

int main(void)
{
    char ptemp[MAX_PATH] = "C:\\PS\\Temp\\Temp.txt";
    if (_access(ptemp, 0) != -1)
        int result = remove(ptemp);

    system("chcp 949");
    
    printf("\nChecking Process\n\nExit : Ctrl + C\n\n=========================================\n");

    stop = 0;

    while (1)
    {
        PyCallPDB();
        ProcessSnapshot();

        char rtemp[MAX_PATH] = "C:\\PS\\Temp\\Result.txt";
        if (_access(rtemp, 0) != -1)
            int result = remove(rtemp);

        char htemp[MAX_PATH] = "C:\\PS\\Temp\\Hash.txt";
        if (_access(htemp, 0) != -1)
            int result = remove(htemp);

        // If program exit, Temp files are delete
        if (stop == 1)
        {
            if (_access(rtemp, 0) != -1)
                int result = remove(rtemp);

            if (_access(htemp, 0) != -1)
                int result = remove(htemp);

            if (_access(ptemp, 0) != -1)
                int result = remove(ptemp);

            break;
        }
    }

    return 0;
}