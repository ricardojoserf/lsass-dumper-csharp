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
        public static extern bool NtReadVirtualMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            out IntPtr lpNumberOfBytesRead
        );

        [DllImport("Kernel32.dll", CharSet = CharSet.Unicode, CallingConvention = CallingConvention.StdCall)] 
        public static extern bool CloseHandle(IntPtr hObject);


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

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr LoadLibrary(
            [MarshalAs(UnmanagedType.LPStr)] string lpFileName);

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













        //////////////////// FUNCTIONS //////////////////// 
        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileA(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            uint lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            uint hTemplateFile
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern bool VirtualProtect(
            IntPtr lpAddress,
            uint dwSize,
            uint flNewProtect,
            out uint lpflOldProtect
        );

        [DllImport("ws2_32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern Int32 WSAGetLastError();


        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr CreateFileMappingA(
            IntPtr hFile,
            uint lpFileMappingAttributes,
            uint flProtect,
            uint dwMaximumSizeHigh,
            uint dwMaximumSizeLow,
            string lpName
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern IntPtr MapViewOfFile(
            IntPtr hFileMappingObject,
            uint dwDesiredAccess,
            uint dwFileOffsetHigh,
            uint dwFileOffsetLow,
            uint dwNumberOfBytesToMap
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtQueryInformationProcess(
            IntPtr processHandle,
            int processInformationClass,
            IntPtr pbi,
            uint processInformationLength,
            out uint returnLength
        );

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern uint ReadProcessMemory(
            IntPtr hProcess,
            IntPtr lpBaseAddress,
            [Out] byte[] lpBuffer,
            int dwSize,
            // out IntPtr lpNumberOfBytesRead
            out uint lpNumberOfBytesRead
        );

        [DllImport("ntdll.dll", SetLastError = true)]
        public static extern uint NtOpenSection(
            ref IntPtr FileHandle,
            int DesiredAccess,
            ref OBJECT_ATTRIBUTES ObjectAttributes
        );

        // Source: https://learn.microsoft.com/en-us/answers/questions/262095/read-file-from-my-computer-using-c
        public static OBJECT_ATTRIBUTES InitializeObjectAttributes(string dll_name, UInt32 Attributes)
        {
            OBJECT_ATTRIBUTES objectAttributes = new OBJECT_ATTRIBUTES();
            objectAttributes.RootDirectory = IntPtr.Zero;
            // ObjectName
            UNICODE_STRING objectName = new UNICODE_STRING();
            objectName.Buffer = dll_name; // Marshal.StringToHGlobalUni(str);
            objectName.Length = (ushort)(dll_name.Length * 2);
            objectName.MaximumLength = (ushort)(dll_name.Length * 2 + 2);
            objectAttributes.ObjectName = Marshal.AllocHGlobal(Marshal.SizeOf(objectName));
            Marshal.StructureToPtr(objectName, objectAttributes.ObjectName, false);
            objectAttributes.SecurityDescriptor = IntPtr.Zero;
            objectAttributes.SecurityQualityOfService = IntPtr.Zero;
            objectAttributes.Attributes = Attributes;
            objectAttributes.Length = Convert.ToUInt32(Marshal.SizeOf(objectAttributes));
            return objectAttributes;
        }

        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool CreateProcess(
            string lpApplicationName,
            string lpCommandLine,
            IntPtr lpProcessAttributes,
            IntPtr lpThreadAttributes,
            bool bInheritHandles,
            uint dwCreationFlags,
            IntPtr lpEnvironment,
            string lpCurrentDirectory,
            ref STARTUPINFO lpStartupInfo,
            out PROCESS_INFORMATION lpProcessInformation
        );

        [DllImport("kernel32.dll")]
        public static extern bool DebugActiveProcessStop(
            int dwProcessId
        );

        [DllImport("kernel32.dll")]
        public static extern bool TerminateProcess(
            IntPtr hProcess,
            uint uExitCode
        );

        ///////////////////// STRUCTS ///////////////////// 
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct UNICODE_STRING
        {
            public ushort Length;
            public ushort MaximumLength;
            [MarshalAs(UnmanagedType.LPWStr)] public string Buffer;
            // public IntPtr Buffer;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct OBJECT_ATTRIBUTES
        {
            public uint Length;
            public IntPtr RootDirectory;
            public IntPtr ObjectName;
            public uint Attributes;
            public IntPtr SecurityDescriptor;
            public IntPtr SecurityQualityOfService;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct STARTUPINFO
        {
            public int cb;
            public IntPtr lpReserved;
            public IntPtr lpDesktop;
            public IntPtr lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public int dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct PROCESS_INFORMATION
        {
            public IntPtr hProcess;
            public IntPtr hThread;
            public int dwProcessId;
            public int dwThreadId;
        }

        //////////////////// CONSTANTS ////////////////////
        public const uint GENERIC_READ = (uint)0x80000000; // https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/262970b7-cd4a-41f4-8c4d-5a27f0092aaa
        public const uint FILE_SHARE_READ = 0x00000001;
        public const uint OPEN_EXISTING = 3; // https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilea
        public const uint PAGE_READONLY = 0x02; // https://learn.microsoft.com/es-es/windows/win32/memory/memory-protection-constants
        public const uint SEC_IMAGE_NO_EXECUTE = 0x11000000; // https://learn.microsoft.com/es-es/windows/win32/api/winbase/nf-winbase-createfilemappinga
        public const uint FILE_MAP_READ = 4; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint PAGE_EXECUTE_WRITECOPY = 0x80;
        public const uint OBJ_CASE_INSENSITIVE = 0x00000040;
        public const int SECTION_MAP_READ = 0x0004; // https://www.codeproject.com/Tips/79069/How-to-use-a-memory-mapped-file-with-Csharp-in-Win
        public const uint DEBUG_PROCESS = 0x00000001;
        public const int offset_mappeddll = 4096;
        public const int offset_fromdiskdll = 0x400;
    }
}
