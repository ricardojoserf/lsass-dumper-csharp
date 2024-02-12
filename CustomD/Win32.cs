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

        //////////////////// CONSTANTS //////////////////// 
        public static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        public const uint PROCESS_VM_READ = 0x0010; // https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
        public const uint PROCESS_QUERY_INFORMATION = 0x0400;
    }
}
