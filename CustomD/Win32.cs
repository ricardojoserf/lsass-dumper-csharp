using System;
using System.Text;
using System.Runtime.InteropServices;

namespace CustomD
{
    internal class Win32
    {
        ///////////////// FUNCTION DELEGATES ///////////////// 
        public delegate IntPtr OpenProcessDelegate(
            uint processAccess,
            bool bInheritHandle,
            int processId);

        public delegate bool MinidumpWriteDelegate(
            IntPtr hProcess,
            int ProcessId,
            IntPtr hFile,
            int Type,
            IntPtr ExceptionParam,
            IntPtr UserStreamParam,
            IntPtr CallbackParam);

        public delegate IntPtr LoadLibraryDelegate(
            [MarshalAs(UnmanagedType.LPStr)] string lpFileName);

        public delegate int GetProcessIdDelegate(
            IntPtr handle);

        public delegate bool NtGetNextProcessDelegate(
            IntPtr handle,
            int MAX_ALLOWED,
            int param3,
            int param4,
            out IntPtr outHandle);

        public delegate bool GetProcessImageFileNameDelegate(
            IntPtr handle,
            StringBuilder fname,
            int nsize);

        public delegate bool CallBack(
            int CallbackParam,
            IntPtr PointerCallbackInput,
            IntPtr PointerCallbackOutput);

        //////////////////// FUNCTIONS ////////////////////
        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr pbi,
            uint processInformationLength,
            out IntPtr returnLength
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern bool NtReadVirtualMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("kernel32.dll")]
        public static extern bool WriteFile(
            IntPtr hFile,
            byte[] lpBuffer,
            uint nNumberOfBytesToWrite,
            out uint lpNumberOfBytesWritten,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileA(
            string lpFileName, uint dwDesiredAccess,
            uint dwShareMode, IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        //////////////////// CONSTANTS //////////////////// 
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const uint PROCESS_VM_READ = 0x0010; // https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
        public const uint GENERIC_ALL = 0x10000000;
        public const uint FILE_SHARE_WRITE = 0x00000002;
        public const uint CREATE_ALWAYS = 2;
        public const uint FILE_ATTRIBUTE_NORMAL = 128;

        ////////////////////// ENUMS ////////////////////// 
        public enum MINIDUMP_CALLBACK_TYPE
        {
            ModuleCallback,
            ThreadCallback,
            ThreadExCallback,
            IncludeThreadCallback,
            IncludeModuleCallback,
            MemoryCallback,
            CancelCallback,
            WriteKernelMinidumpCallback,
            KernelMinidumpStatusCallback,
            RemoveMemoryCallback,
            IncludeVmRegionCallback,
            IoStartCallback,
            IoWriteAllCallback,
            IoFinishCallback,
            ReadMemoryFailureCallback,
            SecondaryFlagsCallback,
            IsProcessSnapshotCallback,
            VmStartCallback,
            VmQueryCallback,
            VmPreReadCallback,
            VmPostReadCallback
        }


        //////////////////// STRUCTS ///////////////////// 
        public struct MINIDUMP_CALLBACK_INFORMATION
        {
            public IntPtr CallbackRoutine;
            public IntPtr CallbackParam;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MINIDUMP_IO_CALLBACK
        {
            public IntPtr Handle;
            public ulong Offset;
            public IntPtr Buffer;
            public int BufferBytes;
        }

        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        public struct MINIDUMP_CALLBACK_INPUT
        {
            public int ProcessId;
            public IntPtr ProcessHandle;
            public MINIDUMP_CALLBACK_TYPE CallbackType;
            public MINIDUMP_IO_CALLBACK Io;
        }

        public struct MINIDUMP_CALLBACK_OUTPUT
        {
            public uint status;
        }
    }
}
