using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using Reloaded.Memory.Sigscan;
using static ByteScanner.Native;

namespace ByteScanner
{
    //https://reloaded-project.github.io/Reloaded-II/CheatSheet/SignatureScanning/
    internal class Program
    {
        public static bool verbose = false;
        static void Usage()
        {
            Console.WriteLine("Scan pid 1122 for pattern ABBA ABBA ABBA");
            Console.WriteLine("    .\\ByteScanner.exe /pid:1122 /pattern:\"AB BA AB BA AB BA\"");
            Console.WriteLine("Scan process CalculatorApp and all its loaded modules for pattern ABBA ABBA ABBA");
            Console.WriteLine("    .\\ByteScanner.exe /name:CalculatorApp.exe /pattern:\"AB BA AB BA AB BA\" /all");
            Console.WriteLine();
            Console.WriteLine("Provide pattern in form of space delimited string:");
            Console.WriteLine("    11 22 AB 00 FF");
            Console.WriteLine("You may use double question marks (??) as wildcard:");
            Console.WriteLine("    11 22 ?? ?? FF");
            Console.WriteLine();
            Console.WriteLine("Flags:");
            Console.WriteLine("/name        target process name, you may omit the file ending");
            Console.WriteLine("/pid         target process PID");
            Console.WriteLine("/pattern     Byte pattern to look for");
            Console.WriteLine("/input       Byte pattern input file. One pattern per line");
            Console.WriteLine("/v           Verbose print /verbose works as well");
        }

        public static List<string> ParseInputFile(string fileName)
        {

            if (!File.Exists(fileName))
            {
                Console.WriteLine("[-] Input file was not found!");
            }

            var lines = File.ReadLines(fileName);
            if (lines.Count() == 0)
            {
                Console.WriteLine("[-] Input file was empty!");
                return new List<string>(); ;
            }
            var targets = lines.ToList();
            targets.RemoveAll(string.IsNullOrWhiteSpace);
            return targets;
        }

        static int GetProcessPIDFromName(string ProcName)
        {
            var processes = Process.GetProcessesByName(ProcName);
            if (processes != null && processes.Length > 0)
                return processes.FirstOrDefault().Id;
            else
                return 0;
        }

        static void ScanModule(Process proc, ProcessModule module, List<string> searchPatterns) {

            var scanner = new Scanner(proc, module);
            var patternResult = scanner.FindPatterns(searchPatterns);

            if (patternResult.Any(x => x.Found))
            {
                var hitCount = patternResult.Where(x => x.Found).Count();
                Console.WriteLine("Got {0} hits with the provided patterns", hitCount);
                foreach (var result in patternResult.Where(x => x.Found))
                {
                    Console.WriteLine("    Got hit on address: 0x{0:X}", ((long)result.Offset + (long)module.BaseAddress));
                    Console.WriteLine("    Base address: 0x{0:X} on offset 0x{1:X}", (long)module.BaseAddress, (ulong)result.Offset);
                }
            }
            else { 
                if(verbose)
                    Console.WriteLine("Could not find any hits on module: {0}",module.ModuleName);
            }
        }

        static void ScanMemory(int procPid, List<string> searchPatterns) {

            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, procPid);
            if (hProc == IntPtr.Zero)
            {
                Console.Write("[-] Failed to open target process handle!");
                return;
            }

            //We need to use this function to get max address value. Maybe you can also just hardcode for x64 and x86?
            SYSTEM_INFO si;
            GetSystemInfo(out si);

            if (si.pageSize == 0)
            {
                Console.Write("[-] Failed to get System Info!");
                return;
            }

            // saving the values as long ints so I won't have to do a lot of casts later
            long proc_min_address_l = (long)si.minimumApplicationAddress;
            long proc_max_address_l = (long)si.maximumApplicationAddress;

            MEMORY_BASIC_INFORMATION basicInfo;
            uint bufLen = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            //Scan target process memory pages
            long address = proc_min_address_l;
            int counter = 0;
            do
            {
                if (VirtualQueryEx(hProc, (IntPtr)address, out basicInfo, bufLen) == 0)
                {
                    Console.WriteLine("[-] Failed to access process memory! ERROR: {0}", Marshal.GetLastWin32Error());
                    Console.WriteLine("    Memory address was: 0x{0:X}", address);
                    return;
                }

                if (verbose)
                {
                    Console.WriteLine("    BaseAddress: 0x{0:X}, Allocbase: 0x{1:X}, AllocSize {2}", basicInfo.BaseAddress, basicInfo.AllocationBase, basicInfo.RegionSize);
                    Console.WriteLine("    Protection: {0:X}, Type: {1:X}, State: {2:X}", basicInfo.AllocationProtect, basicInfo.Type, basicInfo.State);
                }

                //We have to filter by readable memory only.
                //A hack could be to set all target process memory areas to readable to access them?
                if (basicInfo.Protect == (int)AllocationProtect.PAGE_EXECUTE_READ ||
                basicInfo.Protect == (int)AllocationProtect.PAGE_READONLY ||
                basicInfo.Protect == (int)AllocationProtect.PAGE_READWRITE ||
                basicInfo.Protect == (int)AllocationProtect.PAGE_EXECUTE_READWRITE)
                {
                    byte[] buffer = new byte[basicInfo.RegionSize];
                    IntPtr readlen;
                    if (!ReadProcessMemory(hProc, (IntPtr)basicInfo.BaseAddress, buffer, (int)basicInfo.RegionSize, out readlen))
                    {
                        Console.WriteLine("[-] Failed to read process memory! ERROR: {0}", Marshal.GetLastWin32Error());
                        Console.WriteLine("    Memory address was: 0x{0:X}", basicInfo.BaseAddress);

                        Console.WriteLine("    BaseAddress: 0x{0:X}, Allocbase: 0x{1:X}, AllocSize {2}", basicInfo.BaseAddress, basicInfo.AllocationBase, basicInfo.RegionSize);
                        Console.WriteLine("    Protection: {0:X}, Type: {1:X}, State: {2:X}", basicInfo.AllocationProtect, basicInfo.Type, basicInfo.State);
                        return;
                    }
                    var scanner = new Scanner(buffer);
                    var patternResult = scanner.FindPatterns(searchPatterns);

                    if (patternResult.Any(x => x.Found))
                    {
                        var hitCount = patternResult.Where(x => x.Found).Count();
                        Console.WriteLine("Got {0} hits with the provided patterns", hitCount);
                        foreach (var result in patternResult.Where(x => x.Found))
                        {
                            Console.WriteLine("    Got hit on address: 0x{0:X}", (basicInfo.BaseAddress + (ulong)result.Offset));
                            Console.WriteLine("    Base address: 0x{0:X} on offset 0x{1:X}", basicInfo.BaseAddress, (ulong)result.Offset);
                        }
                    }
                    else
                    {
                        if(verbose)
                            Console.WriteLine("No hits on memory range: 0x{0:X} - 0x{1:X}", basicInfo.BaseAddress, (basicInfo.BaseAddress + (ulong)basicInfo.RegionSize));
                    }
                }
                else if(verbose)
                {
                    Console.WriteLine("Cannot read memory of protection type: 0x{0:X}", basicInfo.Protect);
                }

                counter++;
                if (address == (long)basicInfo.BaseAddress + (long)basicInfo.RegionSize)
                    break;

                address = (long)basicInfo.BaseAddress + (long)basicInfo.RegionSize;
            } while (address <= proc_max_address_l);
        }

        static void Main(string[] args)
        {
            int procPid = 0;
            List<string> searchPatterns = new List<string>();
            string inputFile = "";
            bool scanAllModules = false;
            bool scanMemory = false;

            #region args
            if (args.Count() == 0)
            {
                Usage();
                return;
            }

            var arguments = new Dictionary<string, string>();
            foreach (string argument in args)
            {
                int idx = argument.IndexOf(':');
                if (idx > 0)
                    arguments[argument.Substring(0, idx)] = argument.Substring(idx + 1);
            }

            if (!arguments.ContainsKey("/pid") && !arguments.ContainsKey("/name"))
            {
                Console.WriteLine("[-] You must specify /pid or /name flag!");
                return;
            }
            if (arguments.ContainsKey("/pid") && arguments.ContainsKey("/name"))
            {
                Console.WriteLine("[-] You must specify only /pid or /name flag!");
                return;
            }

            if (arguments.ContainsKey("/pid"))
            {
                try
                {
                    procPid = int.Parse(arguments["/pid"]);
                }
                catch (Exception)
                {
                    Console.WriteLine("[-] Failed to parse argument: pid, input was: {0}", arguments["/pid"]);
                    return;
                }

                if (procPid == 0)
                {
                    Console.WriteLine("[-] Process pid was: {0}", procPid);
                    return;
                }
            }
            if (arguments.ContainsKey("/name"))
            {
                procPid = GetProcessPIDFromName(Path.GetFileNameWithoutExtension(arguments["/name"]));
                if (procPid == 0)
                {
                    Console.WriteLine("[-] Could not find process pid for process: {0}", arguments["/name"]);
                    return;
                }
            }
            if (arguments.ContainsKey("/pattern"))
            {
                searchPatterns.Add(arguments["/pattern"].Trim('"').Trim());
                if (searchPatterns.FirstOrDefault().Split(' ').Length <= 0)
                {
                    Console.WriteLine("[-] Failed to parse pattern: {0}", searchPatterns.FirstOrDefault());
                    return;
                }
            }
            else if(arguments.ContainsKey("/input"))
            {
                inputFile = arguments["/input"];
                if (!File.Exists(inputFile))
                {
                    Console.WriteLine("[-] Input file {0} was not found!", inputFile);
                    return;
                }
                searchPatterns = new List<string>(ParseInputFile(inputFile));
                if (searchPatterns.Count() == 0)
                {
                    Console.Write("[-] Parsed pattern list was empty!");
                    return;
                }

                Console.WriteLine("[*] Parsed in {0} patterns", searchPatterns.Count().ToString());
            }
            else
            {
                Console.WriteLine("[-] You must provide either /pattern or /input flags!");
                return;
            }
            if (args.Contains("/all"))
                scanAllModules = true;
            if (args.Contains("/memory"))
                scanMemory = true;
            if (args.Contains("/v"))
                verbose = true;
            if (args.Contains("/verbose"))
                verbose = true;

            #endregion

            var targetProcess = Process.GetProcessById(procPid);
            if (targetProcess == null)
            {
                Console.WriteLine("[-] Could not find process PID: {0}", procPid);
                return;
            }

            ScanModule(targetProcess, targetProcess.MainModule, searchPatterns);

            if (scanAllModules)
            {
                if(verbose)
                    Console.WriteLine("[*] Scannig all modules of the target process");
                foreach (ProcessModule module in targetProcess.Modules)
                {
                    ScanModule(targetProcess, module, searchPatterns);
                }
            }

            if (scanMemory)
            {
                if (verbose)
                    Console.WriteLine("[*] Scannig whole process memory");
                ScanMemory(procPid, searchPatterns);
            }
            if (verbose)
                Console.WriteLine("Finished searching for patterns.");
        }
    }
}
