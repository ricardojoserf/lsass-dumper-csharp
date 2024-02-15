using System;
using System.Runtime.InteropServices;
using static CustomD.Win32;

namespace CustomD
{
    internal class LocalProc
    {
        public static int[] GetTextSectionInfo(IntPtr ntdl_address)
        {
            IntPtr hProcess = System.Diagnostics.Process.GetCurrentProcess().Handle;

            // Check MZ Signature
            byte[] data = new byte[2];
            IntPtr signature_addr = ntdl_address;
            ReadProcessMemory(hProcess, signature_addr, data, data.Length, out _);
            string signature_dos_header = System.Text.Encoding.Default.GetString(data);
            if (signature_dos_header != "MZ")
            {
                Console.WriteLine("[-] Incorrect DOS header signature");
                Environment.Exit(0);
            }

            // e_lfanew in offset 0x3C in _IMAGE_DOS_HEADER structure, its size is 4 bytes 
            data = new byte[4];
            IntPtr e_lfanew_addr = ntdl_address + 0x3C;
            ReadProcessMemory(hProcess, e_lfanew_addr, data, 4, out _);
            int e_lfanew = BitConverter.ToInt32(data, 0);

            // Check PE Signature
            IntPtr image_nt_headers_addr = ntdl_address + e_lfanew;
            data = new byte[2];
            ReadProcessMemory(hProcess, image_nt_headers_addr, data, data.Length, out _);
            string signature_nt_header = System.Text.Encoding.Default.GetString(data);
            if (signature_nt_header != "PE")
            {
                Console.WriteLine("[-] Incorrect NT header signature");
                Environment.Exit(0);
            }

            // Check Optional Headers Magic field value
            IntPtr optional_headers_addr = image_nt_headers_addr + 24; // Marshal.SizeOf(typeof(UInt32)) + Marshal.SizeOf(typeof(IMAGE_FILE_HEADER)) = 24
            data = new byte[4];
            ReadProcessMemory(hProcess, optional_headers_addr, data, data.Length, out _);
            int optional_header_magic = BitConverter.ToInt16(data, 0);
            if (optional_header_magic != 0x20B && optional_header_magic != 0x10B)
            {
                Console.WriteLine("[-] Incorrect Optional Header Magic field value");
                Environment.Exit(0);
            }

            // SizeOfCode
            IntPtr sizeofcode_addr = optional_headers_addr + 4; // Uint16 (2 bytes) + Byte (1 byte) + Byte (1 byte) 
            data = new byte[4];
            ReadProcessMemory(hProcess, sizeofcode_addr, data, data.Length, out _);
            int sizeofcode = BitConverter.ToInt32(data, 0);

            // BaseOfCode
            IntPtr baseofcode_addr = optional_headers_addr + 20; // Uint16 (2 bytes) + 2 Byte (1 byte) + 4 Uint32 (4 byte) - public UInt16 Magic; public Byte MajorLinkerVersion; public Byte MinorLinkerVersion; public UInt32 SizeOfCode; public UInt32 SizeOfInitializedData; public UInt32 SizeOfUninitializedData; public UInt32 AddressOfEntryPoint; public UInt32 BaseOfCode;
            data = new byte[4];
            ReadProcessMemory(hProcess, baseofcode_addr, data, data.Length, out _);
            int baseofcode = BitConverter.ToInt32(data, 0);

            int[] result = { baseofcode, sizeofcode };
            return result;
        }
    }
}