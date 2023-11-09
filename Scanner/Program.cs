using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using Reloaded.Memory.Sigscan;
using static ByteScanner.Native;

namespace ByteScanner
{
    internal class Program
    {
        static void Usage()
        {
            Console.WriteLine("Scan pid 1122 for pattern ABBA ABBA ABBA");
            Console.WriteLine("    .\\ByteScanner.exe /pid:1122 /pattern:\"AB BA AB BA AB BA\"");
            Console.WriteLine("Scan process CalculatorApp and all its loaded modules for pattern ABBA ABBA ABBA");
            Console.WriteLine("    .\\ByteScanner.exe /name:CalculatorApp.exe /pattern:\"AB BA AB BA AB BA\" /all");
            Console.WriteLine();
            Console.WriteLine("Provide pattern in form of space delimited string, like:");
            Console.WriteLine("    11 22 AB 00 FF");
            Console.WriteLine("You may use double question marks (??) and wildcard, like:");
            Console.WriteLine("    11 22 ?? ?? FF");
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

            if (patternResult.Length < searchPatterns.Count)
                Console.WriteLine("What?");

            if (patternResult.Any(x => x.Found))
            {
                var hitCount = patternResult.Where(x => x.Found).Count();
                Console.WriteLine("Got {0} hits with the provided patterns", hitCount);
                foreach (var result in patternResult.Where(x => x.Found))
                {
                    Console.WriteLine("    Got hit on offset: {0}", result.Offset);
                }
            }
            else
                Console.WriteLine("Could not find any hits on module: {0}",module.ModuleName);
        }

        static void Main(string[] args)
        {
            int procPid = 0;
            List<string> searchPatterns = new List<string>();
            string inputFile = "";
            bool scanAllModules = false;

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
                searchPatterns.Add(arguments["/pattern"].Trim('"'));
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

            #endregion

            var targetProcess = Process.GetProcessById(procPid);
            if (targetProcess == null)
            {
                Console.WriteLine("[-] Could not find process PID: {0}", procPid);
                return;
            }

            IntPtr hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, procPid);
            if (hProc == IntPtr.Zero)
            {
                Console.Write("[-] Failed to open target process handle!");
                return;
            }

            MEMORY_BASIC_INFORMATION basicInfo;
            uint bufLen = (uint)Marshal.SizeOf(typeof(MEMORY_BASIC_INFORMATION));
            //Scan target process memory pages
            long MaxAddress = 0x7fffffff;
            long address = 0;
            do
            {
                if (VirtualQueryEx(hProc, (IntPtr)address, out basicInfo, bufLen) == 0)
                {
                    Console.WriteLine("[-] Failed to access process memory! ERROR: {0}", Marshal.GetLastWin32Error());
                    return;
                }

                if (basicInfo.Type != AllocationType.MEM_IMAGE)
                {

                }

                if (address == (long)basicInfo.BaseAddress + (long)basicInfo.RegionSize)
                    break;

                address = (long)basicInfo.BaseAddress + (long)basicInfo.RegionSize;
            } while (address <= MaxAddress);


            ScanModule(targetProcess, targetProcess.MainModule, searchPatterns);

            if (scanAllModules)
            {
                Console.WriteLine("[*] Scannig all modules of the target process");
                foreach (ProcessModule module in targetProcess.Modules)
                {
                    ScanModule(targetProcess, module, searchPatterns);
                }
            }


            Console.WriteLine("Finished searching for patterns. Hit any key to exit...");
            Console.ReadKey();
        }
    }
}
