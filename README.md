# BinaryToPowershellScript
A simple console application to recreate one or more binary files through a Powershell script. You can choose 2 formats: as an explicit **byte array** (default option, bigger in size, but it should be more difficult to be detected) or as a **base64** string (option -b, it is shorter). By default it will generate a script file for all specified input files with the either **_script.ps1** or **_script_base64.ps1** suffix according to the file format specified, if the option -s is specified it will generate a single script called either **SingleScript.ps1** or **SingleScript_base64.ps1** according to the specified file format. The generated script should work both on standard PowerShell (tested on  5.1.22621.1778) and PowerShell Core (tested on 7.3.7).

# Usage

 -i, --inputs          Required. Specify the input file(s) to process, you can use also a wildcard pattern or specify multiple files separted by space<br />
 -o, --outputfolder    Specify the output folder where all the powershell scripts will be generated<br />
 -b, --base64          Specify the base64 file format for the powershell script(s)<br />
 -s, --single          Specify to create just a single script file for all input files<br />
 --help                Display this help screen.<br />
 --version             Display version information.<br />

# Example command lines
 .\BinaryToPowershellScript.exe -i .\* -o c:\temp --> it will script all files in the current folder to the output folder c:\temp by creating a script file for all them with the byte array format.<br />
 .\BinaryToPowershellScript.exe -i .\* -o c:\temp -b --> it will script all files in the current folder to the output folder by creating a script file for all them with the base64 format.<br />
 .\BinaryToPowershellScript.exe -i .\* -o c:\temp -s --> it will script all files in the current folder as a single file in the output folder c:\temp with the byte array format.<br />
 .\BinaryToPowershellScript.exe -i .\* -o c:\temp -b -s --> it will script all files in the current folder as a single file in the output folder c:\temp with the base64 format.<br />
 .\BinaryToPowershellScript.exe -i .\* c:\windows\*.exe -o c:\temp -s -b -> it will script all files in the current folder and in c:\windows with *.exe extension as a single file in the output folder c:\temp with the base64 format.<br />

 # Example output

**.\BinaryToPowershellScript.exe -i .\* c:\windows\*.exe -o c:\temp -s -b**
Scripting file .\BinaryToPowershellScript.deps.json<br />
Scripting file .\BinaryToPowershellScript.dll<br />
Scripting file .\BinaryToPowershellScript.exe<br />
Scripting file .\BinaryToPowershellScript.pdb<br />
Scripting file .\BinaryToPowershellScript.runtimeconfig.json<br />
Scripting file .\CommandLine.dll<br />
Scripting file c:\windows\bfsvc.exe<br />
Scripting file c:\windows\explorer.exe<br />
Scripting file c:\windows\HelpPane.exe<br />
Scripting file c:\windows\hh.exe<br />
Scripting file c:\windows\notepad.exe<br />
Scripting file c:\windows\regedit.exe<br />
Scripting file c:\windows\splwow64.exe<br />
Scripting file c:\windows\TbtControlCenterToastLauncher.exe<br />
Scripting file c:\windows\TbtP2pShortcutService.exe<br />
Scripting file c:\windows\ThunderboltService.exe<br />
Scripting file c:\windows\winhlp32.exe<br />
Scripting file c:\windows\write.exe<br />
Creating single script file c:\temp\SingleScript_base64.ps1...<br />

**.\BinaryToPowershellScript.exe -i c:\windows\*.txt -o c:\temp**
Scripting file c:\windows\bfsvc.exe into c:\temp\bfsvc_exe_script.ps1...<br />
Scripting file c:\windows\explorer.exe into c:\temp\explorer_exe_script.ps1...<br />
Scripting file c:\windows\HelpPane.exe into c:\temp\HelpPane_exe_script.ps1...<br />
Scripting file c:\windows\hh.exe into c:\temp\hh_exe_script.ps1...<br />
Scripting file c:\windows\notepad.exe into c:\temp\notepad_exe_script.ps1...<br />
Scripting file c:\windows\regedit.exe into c:\temp\regedit_exe_script.ps1...<br />
Scripting file c:\windows\splwow64.exe into c:\temp\splwow64_exe_script.ps1...<br />
Scripting file c:\windows\TbtControlCenterToastLauncher.exe into c:\temp\TbtControlCenterToastLauncher_exe_script.ps1...<br />
Scripting file c:\windows\TbtP2pShortcutService.exe into c:\temp\TbtP2pShortcutService_exe_script.ps1...<br />
Scripting file c:\windows\ThunderboltService.exe into c:\temp\ThunderboltService_exe_script.ps1...<br />
Scripting file c:\windows\winhlp32.exe into c:\temp\winhlp32_exe_script.ps1...<br />
Scripting file c:\windows\write.exe into c:\temp\write_exe_script.ps1...<br />

# Example of generated script files

**Single Base64 Script**
<img width="1280" alt="image" src="https://github.com/fededim/BinaryToPowershellScript/assets/8364158/77621535-8a8f-4ba3-bf04-1636b17078aa">

**ByteArray Script per file**
<img width="1280" alt="image" src="https://github.com/fededim/BinaryToPowershellScript/assets/8364158/fa89161a-9871-4d16-83b8-a549db2ea711">
