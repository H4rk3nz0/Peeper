## Description

A P/Invoke C# tool that iterates over known memory structures in Keeper Security's Password Manager Windows Desktop app and pulls password JSON structures out in clear text. Makes use of regex due to unreliable V8 memory mapping structure - not consistent with known MetaMap structures `ff 03 (40 | 20) 00` byte match does not yield expected results.

After logging in, even if a session timeout occurs, Keeper stores cleartext vault entries as JSON strings in memory under the Chrome Embedded Framework Renderer Client ID 5 (ID can change). As the program typically runs with user permissions one can simply get a handle and read the target process' memory. 

NOTE: A user can set the memory to be wiped on exit or restart (not on by default). But if session is active and logged in then credentials are freely available to dump.

## Usage:

```
C:\> .\Peeper.exe
```
