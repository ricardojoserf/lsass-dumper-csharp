# Customizing Lsass Dumps with C#

Yet another C# program to dump lsass.exe. Without input arguments it creates a dump file with the hostname and date as name and the ".txt" extension (*hostname_DD-MM-YYYY-HHMM.txt*). With input arguments it will use the first one as path for the file.

- Dump is done from a snapshot of the lsass process using PssCaptureSnapshot
- XOR-encoding the dump using a callback function in MinidumpWriteDump call
- Dynamic function resolution with custom implementations for GetProcAddress and GetModuleHandle
- Process enumeration is done using NtGetNextProcessDelegate and GetProcessImageFileNameDelegate 
- Trying to unhook NTDLL and DBGHELP dlls by overwriting the .text sections


## Usage

The fastest way to use it is to right-click the file and click "Run as Administrator": 

![im1](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/custom-lsass-dumper-csharp/image1.png)

This generates a file with the hostname ("DESKTOP-MA54241") and the date (30/08/2021) as name and with extension ".txt":

![im2](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/custom-lsass-dumper-csharp/image2.png)

If we execute it from a command line we can choose any name or path:

![im3](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/custom-lsass-dumper-csharp/image3.png)

The file is generated correctly:

![im4](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/custom-lsass-dumper-csharp/image4.png)

Using the Decoder project we can compile the XOR decoder and decode the dump.

Then we can parse the decoded dump file with Mimikatz, as it does not care about the extension:

![im5](https://raw.githubusercontent.com/ricardojoserf/ricardojoserf.github.io/master/images/custom-lsass-dumper-csharp/image5.png)
