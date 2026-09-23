# Creates ONLY a new, dedicated, dynamically expanding test image. Never formats an existing disk.
[CmdletBinding()]
param([string]$ImagePath = 'C:\disk-cleaner-validation\refs-test-20260923.vhdx')
$ErrorActionPreference = 'Stop'
$report = Join-Path $PSScriptRoot '..\validation\artifacts\refs-volume.json'
$utf8 = New-Object System.Text.UTF8Encoding($false)
function Save-Report($value) { [IO.File]::WriteAllText([IO.Path]::GetFullPath($report), ($value | ConvertTo-Json -Depth 8), $utf8) }
try {
    $principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Administrator rights required.' }
    $expectedRoot = 'C:\disk-cleaner-validation\'
    $ImagePath = [IO.Path]::GetFullPath($ImagePath)
    if (-not $ImagePath.StartsWith($expectedRoot,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetExtension($ImagePath) -ne '.vhdx') { throw 'Image must be a new .vhdx inside C:\disk-cleaner-validation.' }
    if (Test-Path -LiteralPath $ImagePath) { throw 'Refusing to reuse or format an existing image.' }
    [IO.Directory]::CreateDirectory([IO.Path]::GetDirectoryName($ImagePath)) | Out-Null
    $dir = Get-Item -LiteralPath ([IO.Path]::GetDirectoryName($ImagePath))
    if (($dir.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'Test directory must not be a reparse point.' }
    $commands = Join-Path $PSScriptRoot '..\validation\artifacts\create-test-vhd.txt'
    [IO.File]::WriteAllLines([IO.Path]::GetFullPath($commands), @((('create vdisk file="{0}" maximum=65536 type=expandable') -f $ImagePath),'attach vdisk','exit'), [Text.Encoding]::ASCII)
    $diskpartOutput = (& "$env:SystemRoot\System32\diskpart.exe" /s $commands 2>&1 | Out-String)
    $image = Get-DiskImage -ImagePath $ImagePath
    if (-not $image.Attached) { throw "New test image did not attach: $diskpartOutput" }
    $disk = $image | Get-Disk
    if ($disk.IsBoot -or $disk.IsSystem -or $disk.Size -ne 68719476736 -or $disk.PartitionStyle -ne 'RAW' -or $disk.BusType -ne 'File Backed Virtual') { throw 'Safety check failed: not the newly created blank test VHD.' }
    $disk | Initialize-Disk -PartitionStyle GPT
    $partition = New-Partition -DiskNumber $disk.Number -UseMaximumSize -AssignDriveLetter
    # Only the partition obtained from our brand-new, positively identified disk is formatted.
    $volume = Format-Volume -Partition $partition -FileSystem ReFS -DevDrive -NewFileSystemLabel 'DC_REFS_TEST' -Confirm:$false
    $volume = Get-Volume -DriveLetter $partition.DriveLetter
    if ($volume.FileSystem -ne 'ReFS') { throw 'New test volume is not ReFS.' }
    Save-Report @{ status='ready'; image=$ImagePath; diskNumber=$disk.Number; drive=([string]$partition.DriveLetter + ':\'); filesystem=$volume.FileSystem; logicalBytes=$volume.Size; backingFileBytes=(Get-Item -LiteralPath $ImagePath).Length; createdAt=(Get-Date).ToString('o'); originalDevDriveUntouched=$true }
} catch {
    Save-Report @{status='failed'; image=$ImagePath; error=$_.Exception.Message; originalDevDriveUntouched=$true}
    throw
}
