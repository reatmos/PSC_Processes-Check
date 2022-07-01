/*
Create Process list and API key file
Made by Reamos
Github : reatmos
Twitter : @Pa1ath
Blog : https://re-atmosphere.tistory.com/
Blog : 
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

int callback(void* NotUsed, int argc, char** argv, char** azColName)
{
    NotUsed = 0;

    for (int i = 0; i < argc; i++)
    {
        printf("%s = %s\n", azColName[i], argv[i] ? argv[i] : "NULL");
    }

    printf("\n");

    return 0;
}

int createDB(const char* s)
{
    sqlite3* DB;
    int exit = 0;

    exit = sqlite3_open(s, &DB);

    sqlite3_close(DB);

    return 0;
}

int createTable(const char* s)
{
    sqlite3* DB;

    const char* sql = "CREATE TABLE IF NOT EXISTS PROCESS("
        "ID INTEGER PRIMARY KEY AUTOINCREMENT,"
        "Process_Name				VARCHAR(255),"
        "PID                        VARCHAR(255),"
        "Process_Path               VARCHAR(255) );";
    try
    {
        int exit = 0;
        exit = sqlite3_open(s, &DB);

        char* messaggeError;
        exit = sqlite3_exec(DB, sql, callback, 0, &messaggeError);

        if (exit != SQLITE_OK) {
            cerr << "Error : Can't create DB Table" << endl;
            sqlite3_free(messaggeError);

        }
        sqlite3_close(DB);

    }
    catch (const exception& e) {
        cerr << e.what();
    }

    return 0;
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

// Get to Process Path
int GetPath(DWORD p)
{
    setlocale(LC_ALL, "");
    HANDLE processHandle = NULL;

    processHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, p);
    if (processHandle != NULL) {
        if (GetModuleFileNameEx(processHandle, NULL, pPath, MAX_PATH) == 0) {
            tcerr << "Failed to get module filename." << endl;
        }
        CloseHandle(processHandle);
    }

    return 0;
}

// Create Process List
int FirstProcessSnapshot()
{
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
        }

        if (find != 1)
        {
            GetPath(pe32.th32ProcessID);
            insertData(db);
        }
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return 0;
}

int main(void)
{
    std::ofstream fout;

    char vtkey[MAX_PATH];
    char ptemp[MAX_PATH] = "C:\\PS\\Temp\\Temp.txt";
    if (_access(ptemp, 0) != -1)
        int result = remove(ptemp);

    _mkdir("C:\\PS");
    _mkdir("C:\\PS\\Temp");
    createDB(db);
    createTable(db);
    PyCallPDB();
    printf("Create Process List..\n\n");
    FirstProcessSnapshot();
    
    // Check API key
    while (1)
    {
        printf("Enter your API key : ");
        scanf("%s", &vtkey);
        
        if (strlen(vtkey) == 64)
        {
            break;
        }

        printf("\nAPI key is wrong.\n\nTry again\n\n");
    }
    
    fout.open("C:\\PS\\Temp\\vtkey.txt", std::ios_base::out | std::ios_base::app);
    fout << vtkey << endl;
    fout.close();

    if (_access(ptemp, 0) != -1)
        int result = remove(ptemp);

    return 0;
}