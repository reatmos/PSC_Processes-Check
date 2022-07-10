# PSC_Processes-Check
Runnnig Processes Check(Scan) Program

[How to use]
1. Run CreatePSL.exe
2. Enter your Virustotal API
3. Run Process.exe

====================

[Project File(sln) Requirements]
1. Openssl
2. Python

====================

[Project Setting - VC++ Directory]
Include Directory
- C:\\Users\\[User]\\AppData\\Local\\Programs\\Python\\Python[Version]\\include
- C:\\Program Files\\OpenSSL-Win64\\include

Library Directory
- C:\\Users\\[User]\\AppData\\Local\\Programs\\Python\\Python[Version]\\libs
- C:\\Program Files\\OpenSSL-Win64\lib\\VC

[Project Setting - Linker - Input]
Additional dependencies
- libcrypto64MD.lib
- libcrypto64MT.lib
- libssl64MD.lib
- libssl64MT.lib
- python[version].lib
