# SignatureScanner
Scan target process memory for byte signatures
Signature seeking utilizes Reloaded library:
  https://github.com/Reloaded-Project/Reloaded.Memory.SigScan

**Remember to restore NuGet packages for the solution!**

## Usage
Scan pid 1122 main module for pattern ABBA ABBA ABBA
  .\ByteScanner.exe /pid:1122 /pattern:"AB BA AB BA AB BA"
Scan process CalculatorApp memory and all its loaded modules for pattern ABBA ABBA ABBA. Print way too much informaion
  .\ByteScanner.exe /name:Notepad.exe /pattern:"AB BA AB BA AB BA" /all /memory /v

