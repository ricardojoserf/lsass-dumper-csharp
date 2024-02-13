using System;
using static Decoder.Win32;

namespace Decoder
{
    internal class Program
    {
        static void EncodeBuffer(byte[] dumpBuffer, byte xor_byte)
        {
            for (int i = 0; i < dumpBuffer.Length; i++)
            {
                dumpBuffer[i] = (byte)(dumpBuffer[i] ^ xor_byte);
            }
        }


        static void Main(string[] args)
        {
            // Get file content to byte array
            string fname = args[0];
            byte[] dumpBuffer = System.IO.File.ReadAllBytes(fname);

            // Decode buffer
            byte xor_byte = (byte)0xCC;
            EncodeBuffer(dumpBuffer, xor_byte);

            // Dump to a file
            fname = fname + ".decoded";
            IntPtr hFile = CreateFileA(fname, GENERIC_ALL, FILE_SHARE_WRITE, IntPtr.Zero, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
            WriteFile(hFile, dumpBuffer, (uint)dumpBuffer.Length, out _, IntPtr.Zero);
        }
    }
}
