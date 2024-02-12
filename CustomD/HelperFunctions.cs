using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using static CustomD.Configuration;
using static CustomD.Win32;


namespace CustomD
{
    internal class HelperFunctions
    {

        public static IntPtr GetLibAddress(string aes_enc_libname)
        {
            String decrypted_libname = DecryptStringFromBytes(aes_enc_libname, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            IntPtr lib_baseaddress = helperGetModuleHandle(decrypted_libname);
            return lib_baseaddress;
        }


        public static Delegate GetFuncDelegate(IntPtr lib_baseaddress, string aes_enc_funcname, Type delegate_test)
        {
            String decrypted_funcname = DecryptStringFromBytes(aes_enc_funcname, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            IntPtr func_addr = helperGetProcAddress(lib_baseaddress, decrypted_funcname);
            Delegate func_delegate = Marshal.GetDelegateForFunctionPointer(func_addr, delegate_test);
            // return func_addr;
            return func_delegate;
        }


        // CustomGetModuleHandle may fail once if you call it hundreds of times
        public static IntPtr helperGetModuleHandle(String dll_name)
        {
            IntPtr dll_base = IntPtr.Zero;
            while (dll_base == IntPtr.Zero)
            {
                dll_base = CustomGetModuleHandle(dll_name);
            }
            return dll_base;
        }


        // CustomGetProcAddress may fail once if you call it hundreds of times
        public static IntPtr helperGetProcAddress(IntPtr dll_handle, String functioname)
        {
            IntPtr functionaddress = IntPtr.Zero;
            while (functionaddress == IntPtr.Zero)
            {
                functionaddress = CustomGetProcAddress(dll_handle, functioname);
            }
            return functionaddress;
        }


        // Custom implementation for GetModuleHandle
        public unsafe static IntPtr CustomGetModuleHandle(String dll_name)
        {
            uint process_basic_information_size = 48;
            int peb_offset = 0x8;
            int ldr_offset = 0x18;
            int inInitializationOrderModuleList_offset = 0x30;
            int flink_dllbase_offset = 0x20;
            int flink_buffer_offset = 0x50;
            // If 32-bit process these offsets change
            if (IntPtr.Size == 4)
            {
                process_basic_information_size = 24;
                peb_offset = 0x4;
                ldr_offset = 0x0c;
                inInitializationOrderModuleList_offset = 0x1c;
                flink_dllbase_offset = 0x18;
                flink_buffer_offset = 0x30;
            }

            // Get current process handle
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            // Create byte array with the size of the PROCESS_BASIC_INFORMATION structure
            byte[] pbi_byte_array = new byte[process_basic_information_size];

            // Create a PROCESS_BASIC_INFORMATION structure in the byte array
            IntPtr pbi_addr = IntPtr.Zero;
            fixed (byte* p = pbi_byte_array)
            {
                pbi_addr = (IntPtr)p;
                NtQueryInformationProcess(hProcess, 0x0, pbi_addr, process_basic_information_size, out _);
            }

            // Get PEB Base Address
            IntPtr peb_pointer = pbi_addr + peb_offset;
            IntPtr pebaddress = Marshal.ReadIntPtr(peb_pointer);

            // Get Ldr 
            IntPtr ldr_pointer = pebaddress + ldr_offset;
            IntPtr ldr_adress = Marshal.ReadIntPtr(ldr_pointer);

            // Get InInitializationOrderModuleList (LIST_ENTRY) inside _PEB_LDR_DATA struct
            IntPtr InInitializationOrderModuleList = ldr_adress + inInitializationOrderModuleList_offset;

            IntPtr next_flink = Marshal.ReadIntPtr(InInitializationOrderModuleList);
            IntPtr dll_base = (IntPtr)1337;
            while (dll_base != IntPtr.Zero)
            {
                next_flink = next_flink - 0x10;
                // Get DLL base address
                dll_base = Marshal.ReadIntPtr(next_flink + flink_dllbase_offset);
                IntPtr buffer = Marshal.ReadIntPtr(next_flink + flink_buffer_offset);
                // Get DLL name from buffer address
                String char_aux = null;
                String base_dll_name = "";
                while (char_aux != "")
                {
                    char_aux = Marshal.PtrToStringAnsi(buffer);
                    buffer += 2;
                    base_dll_name += char_aux;
                }
                next_flink = Marshal.ReadIntPtr(next_flink + 0x10);
                // Compare with DLL name we are searching
                if (dll_name.ToLower() == base_dll_name.ToLower())
                {
                    return dll_base;
                }
            }

            return IntPtr.Zero;
        }


        // Custom implementation for GetProcAddress
        public static IntPtr CustomGetProcAddress(IntPtr pDosHdr, String func_name)
        {
            // One offset changes between 32 and 64-bit processes
            int exportrva_offset = 136;
            if (IntPtr.Size == 4)
            {
                exportrva_offset = 120;
            }

            // Current process handle
            IntPtr hProcess = Process.GetCurrentProcess().Handle;

            // DOS header(IMAGE_DOS_HEADER)->e_lfanew
            IntPtr e_lfanew_addr = pDosHdr + (int)0x3C;
            byte[] e_lfanew_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, e_lfanew_addr, e_lfanew_bytearr, e_lfanew_bytearr.Length, out _);
            ulong e_lfanew_value = BitConverter.ToUInt32(e_lfanew_bytearr, 0);

            // NT Header (IMAGE_NT_HEADERS)->FileHeader(IMAGE_FILE_HEADER)->SizeOfOptionalHeader
            IntPtr sizeopthdr_addr = pDosHdr + (int)e_lfanew_value + 20;
            byte[] sizeopthdr_bytearr = new byte[2];
            NtReadVirtualMemory(hProcess, sizeopthdr_addr, sizeopthdr_bytearr, sizeopthdr_bytearr.Length, out _);
            ulong sizeopthdr_value = BitConverter.ToUInt16(sizeopthdr_bytearr, 0);
            int numberDataDirectory = ((int)sizeopthdr_value / 16) - 1;

            // exportTableRVA: Optional Header(IMAGE_OPTIONAL_HEADER64)->DataDirectory(IMAGE_DATA_DIRECTORY)[0]->VirtualAddress
            IntPtr exportTableRVA_addr = pDosHdr + (int)e_lfanew_value + exportrva_offset;
            byte[] exportTableRVA_bytearr = new byte[4];
            NtReadVirtualMemory(hProcess, exportTableRVA_addr, exportTableRVA_bytearr, exportTableRVA_bytearr.Length, out _);
            ulong exportTableRVA_value = BitConverter.ToUInt32(exportTableRVA_bytearr, 0);

            if (exportTableRVA_value != 0)
            {
                // NumberOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->NumberOfNames
                IntPtr numberOfNames_addr = pDosHdr + (int)exportTableRVA_value + 0x18;
                byte[] numberOfNames_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, numberOfNames_addr, numberOfNames_bytearr, numberOfNames_bytearr.Length, out _);
                int numberOfNames_value = (int)BitConverter.ToUInt32(numberOfNames_bytearr, 0);

                // AddressOfFunctions: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfFunctions
                IntPtr addressOfFunctionsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x1C;
                byte[] addressOfFunctionsVRA_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, addressOfFunctionsVRA_addr, addressOfFunctionsVRA_bytearr, addressOfFunctionsVRA_bytearr.Length, out _);
                ulong addressOfFunctionsVRA_value = BitConverter.ToUInt32(addressOfFunctionsVRA_bytearr, 0);

                // AddressOfNames: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNames
                IntPtr addressOfNamesVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x20;
                byte[] addressOfNamesVRA_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, addressOfNamesVRA_addr, addressOfNamesVRA_bytearr, addressOfNamesVRA_bytearr.Length, out _);
                ulong addressOfNamesVRA_value = BitConverter.ToUInt32(addressOfNamesVRA_bytearr, 0);

                // AddressOfNameOrdinals: ExportTable(IMAGE_EXPORT_DIRECTORY)->AddressOfNameOrdinals
                IntPtr addressOfNameOrdinalsVRA_addr = pDosHdr + (int)exportTableRVA_value + 0x24;
                byte[] addressOfNameOrdinalsVRA_bytearr = new byte[4];
                NtReadVirtualMemory(hProcess, addressOfNameOrdinalsVRA_addr, addressOfNameOrdinalsVRA_bytearr, addressOfNameOrdinalsVRA_bytearr.Length, out _);
                ulong addressOfNameOrdinalsVRA_value = BitConverter.ToUInt32(addressOfNameOrdinalsVRA_bytearr, 0);

                IntPtr addressOfFunctionsRA = IntPtr.Add(pDosHdr, (int)addressOfFunctionsVRA_value);
                IntPtr addressOfNamesRA = IntPtr.Add(pDosHdr, (int)addressOfNamesVRA_value);
                IntPtr addressOfNameOrdinalsRA = IntPtr.Add(pDosHdr, (int)addressOfNameOrdinalsVRA_value);

                IntPtr auxaddressOfNamesRA = addressOfNamesRA;
                IntPtr auxaddressOfNameOrdinalsRA = addressOfNameOrdinalsRA;
                IntPtr auxaddressOfFunctionsRA = addressOfFunctionsRA;

                for (int i = 0; i < numberOfNames_value; i++)
                {
                    byte[] data5 = new byte[Marshal.SizeOf(typeof(UInt32))];
                    NtReadVirtualMemory(hProcess, auxaddressOfNamesRA, data5, data5.Length, out _);
                    UInt32 functionAddressVRA = (UInt32)BitConverter.ToUInt32(data5, 0);
                    IntPtr functionAddressRA = IntPtr.Add(pDosHdr, (int)functionAddressVRA);
                    byte[] data6 = new byte[func_name.Length];
                    NtReadVirtualMemory(hProcess, functionAddressRA, data6, data6.Length, out _);
                    String functionName = Encoding.ASCII.GetString(data6);
                    if (functionName == func_name)
                    {
                        // AdddressofNames --> AddressOfNamesOrdinals
                        byte[] data7 = new byte[Marshal.SizeOf(typeof(UInt16))];
                        NtReadVirtualMemory(hProcess, auxaddressOfNameOrdinalsRA, data7, data7.Length, out _);
                        UInt16 ordinal = (UInt16)BitConverter.ToUInt16(data7, 0);
                        // AddressOfNamesOrdinals --> AddressOfFunctions
                        auxaddressOfFunctionsRA += 4 * ordinal;
                        byte[] data8 = new byte[Marshal.SizeOf(typeof(UInt32))];
                        NtReadVirtualMemory(hProcess, auxaddressOfFunctionsRA, data8, data8.Length, out _);
                        UInt32 auxaddressOfFunctionsRAVal = (UInt32)BitConverter.ToUInt32(data8, 0);
                        IntPtr functionAddress = IntPtr.Add(pDosHdr, (int)auxaddressOfFunctionsRAVal);
                        return functionAddress;
                    }
                    auxaddressOfNamesRA += 4;
                    auxaddressOfNameOrdinalsRA += 2;
                }
            }
            return IntPtr.Zero;
        }


        // Enc String -> String
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


        // Used to generate AES-encrypted strings in Configuration.cs
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
    }
}
