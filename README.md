## Description

A P/Invoke C# tool that iterates over known memory structures in Keeper Security's Password Manager Windows Desktop app and pulls password JSON structures out in clear text. See the below article for an explanation of how it works:

[Dumping Keeper Security](https://harkenzo.tlstickle.com/2023-06-12-Keeper-Password-Dumping/)

After logging in, even if a logout occurs, Keeper stores cleartext vault entries as JSON strings in memory under the Chrome Embedded Framework Renderer Client ID 5 (ID can change). As the program typically runs with user permissions one can simply get a handle and read the target process' memory.

## Usage:

```
C:\> .\Peeper.exe
```
