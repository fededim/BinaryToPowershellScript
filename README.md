# BinaryToPowershellScript
A simple console application to recreate one or more binary files through a Powershell script. You can choose 2 formats: as an explicit **byte array** (default option, either in hex or decimal format, bigger in size, but it should be more difficult to be detected) or as a **base64** string (option -b, it is shorter). By default it will generate a script file for all specified input files with the **_script.ps1** suffix, if the option -s is specified it will generate a single script called either **SingleScript.ps1**. The generated script should work both on standard PowerShell (tested on  5.1.22621.1778) and PowerShell Core (tested on 7.3.7).
<br />
<br />
[How to Transform Binary Files into Powershell Script(s) in Order to Copy Them Silently on a Server](https://www.codeproject.com/Tips/5369565/How-to-Transform-Binary-Files-into-Powershell-Scri)
# Usage

 -i, --inputs          Required. Specify the input file(s) to process, you can use also a wildcard pattern or specify multiple files separted by space<br />
 -o, --outputfolder    Specify the output folder where all the powershell scripts will be generated<br />
 -b, --base64          Specify the base64 file format for the powershell script(s), otherwise the hex text format will be used. <br />
 -d, --decimal         Specify the decimal file format for the powershell script(s). <br />
 -c, --compress        Specify to compress the input file(s) with gzip compression. <br />
 -h, --hash            Specify to add a SHA256 hash as check on file(s) integrity in the powershell script(s). <br />
 -s, --single          Specify to create just a single script file for all input files. <br />
 -p, --password        Specify the password used to encrypt data with AES. <br />
 -r, --recurse         Specify to perform recursive search on all input file(s). <br />
 --help                Display this help screen. <br />
 --version             Display version information. <br />

# Example command lines
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -r --> it will script all files in the current folder and its subfolders to the output folder c:\\temp by creating a script file for all them with the byte array format.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -r -c --> it will script all files in the current folder and its subfolders to the output folder c:\\temp by creating a script file for all them with the byte array format and compressing it with gzip compression.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -b --> it will script all files in the current folder to the output folder c:\\temp by creating a script file for all them with the base64 format.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -d -s --> it will script all files in the current folder as a single file in the output folder c:\\temp with the decimal format.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -s --> it will script all files in the current folder as a single file in the output folder c:\\temp with the byte array format.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -b -s --> it will script all files in the current folder as a single file in the output folder c:\\temp with the base64 format.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -b -s -h --> it will script all files in the current folder as a single file in the output folder c:\\temp with the base64 format, checking the SHA256 hash for each file after recreation.<br />
 .\\BinaryToPowershellScript.exe -i * c:\\windows\\*.exe -o c:\\temp -s -b -> it will script all files in the current folder and in c:\\windows with *.exe extension as a single file in the output folder c:\\temp with the base64 format.<br />
 .\\BinaryToPowershellScript.exe -i * -o c:\\temp -s -p password --> it will script all files in the current folder as a single file in the output folder c:\\temp with the byte array format encrypting all files with password "password".<br />

 # Example output

**.\BinaryToPowershellScript.exe -i * \windows\*.exe -o c:\temp -s -b**
Scripting file .\BinaryToPowershellScript.deps.json 
Scripting file .\BinaryToPowershellScript.dll 
Scripting file .\BinaryToPowershellScript.exe 
Scripting file .\BinaryToPowershellScript.pdb 
Scripting file .\BinaryToPowershellScript.runtimeconfig.json 
Scripting file .\BinaryToPowershellScript_deps_json_script.ps1 
Scripting file .\BinaryToPowershellScript_dll_script.ps1 
Scripting file .\BinaryToPowershellScript_exe_script.ps1 
Scripting file .\BinaryToPowershellScript_pdb_script.ps1 
Scripting file .\BinaryToPowershellScript_runtimeconfig_json_script.ps1 
Scripting file .\CommandLine.dll 
Scripting file .\CommandLine_dll_script.ps1 
Scripting file .\test.txt 
Scripting file \windows\bfsvc.exe 
Scripting file \windows\explorer.exe 
Scripting file \windows\HelpPane.exe 
Scripting file \windows\hh.exe 
Scripting file \windows\notepad.exe 
Scripting file \windows\regedit.exe 
Scripting file \windows\splwow64.exe 
Scripting file \windows\TbtControlCenterToastLauncher.exe 
Scripting file \windows\TbtP2pShortcutService.exe 
Scripting file \windows\ThunderboltService.exe 
Scripting file \windows\winhlp32.exe 
Scripting file \windows\write.exe 
Creating single script file c:\temp\SingleScript_base64.ps1...

**.\BinaryToPowershellScript.exe -i \windows\*.exe -o c:\temp**
Scripting file \windows\bfsvc.exe into c:\temp\bfsvc_exe_script.ps1...
Scripting file \windows\explorer.exe into c:\temp\explorer_exe_script.ps1...
Scripting file \windows\HelpPane.exe into c:\temp\HelpPane_exe_script.ps1...
Scripting file \windows\hh.exe into c:\temp\hh_exe_script.ps1...
Scripting file \windows\notepad.exe into c:\temp\notepad_exe_script.ps1...
Scripting file \windows\regedit.exe into c:\temp\regedit_exe_script.ps1...
Scripting file \windows\splwow64.exe into c:\temp\splwow64_exe_script.ps1...
Scripting file \windows\TbtControlCenterToastLauncher.exe into c:\temp\TbtControlCenterToastLauncher_exe_script.ps1...
Scripting file \windows\TbtP2pShortcutService.exe into c:\temp\TbtP2pShortcutService_exe_script.ps1...
Scripting file \windows\ThunderboltService.exe into c:\temp\ThunderboltService_exe_script.ps1...
Scripting file \windows\winhlp32.exe into c:\temp\winhlp32_exe_script.ps1...
Scripting file \windows\write.exe into c:\temp\write_exe_script.ps1...

# Example of generated script files

**Single Base64 Script**
<img width="1280" alt="image" src="https://github.com/fededim/BinaryToPowershellScript/assets/8364158/85863cc8-8328-4aa4-ab9a-c6fd4cfe30e6">

**Hex ByteArray Script per file**
<img width="1280" alt="image" src="https://github.com/fededim/BinaryToPowershellScript/assets/8364158/376fb77d-fef0-48c1-9a98-5460cbb2fce9">

**Decimal ByteArray Script per file**
<img width="1279" alt="image" src="https://github.com/fededim/BinaryToPowershellScript/assets/8364158/d2d883bb-fa93-48cd-8baa-bbe2dd253a93">
