#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 10/11 Privacy & Security Hardening Tool

.DESCRIPTION
    Interactive TUI for hardening Windows 10/11 systems. Covers 11 categories:
    telemetry, privacy, services, scheduled tasks, network, security, Defender
    ASR rules, bloatware, AI/Copilot, Windows Update, and miscellaneous.

    Features:
    - Audit mode: scan system and show hardening score without changing anything
    - Quick harden: apply all recommended settings with one keypress
    - Custom harden: pick individual categories to apply
    - Automatic registry backup before any changes
    - Restore from previous backups
    - Silent/CLI mode for automation

.NOTES
    Requires Administrator privileges.
    Supports Windows 10 (1903+) and Windows 11 (including 24H2).
    License: MIT

.EXAMPLE
    .\Harden-Windows.ps1
    # Interactive TUI mode

.EXAMPLE
    .\Harden-Windows.ps1 -Silent -All
    # Apply all hardening silently (for automation)

.EXAMPLE
    .\Harden-Windows.ps1 -Silent -Categories Telemetry,Privacy,Defender
    # Apply only specific categories
#>

[CmdletBinding()]
param(
    # Run without TUI, apply settings and exit
    [switch]$Silent,
    # Apply all categories (requires -Silent)
    [switch]$All,
    # Specific categories to apply (requires -Silent)
    [ValidateSet('Telemetry','Privacy','Services','Tasks','Network','Security','Defender','Bloatware','AI','Updates','Misc')]
    [string[]]$Categories
)

Set-StrictMode -Version Latest

# ============================================================================
# CONSTANTS
# ============================================================================

$script:Version   = "1.1.0"
$script:BackupDir = Join-Path $env:USERPROFILE "WindowsHardeningBackups"
$script:LogFile   = Join-Path $script:BackupDir "harden-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"

# TUI color theme - all console colors referenced by semantic name
$script:Colors = @{
    Banner  = 'Cyan'       # Logo and chrome
    Title   = 'White'      # Headings and prompts
    Menu    = 'Gray'       # Normal menu text
    Success = 'Green'      # Hardened / OK items
    Warning = 'Yellow'     # Partial / cautionary
    Error   = 'Red'        # Not hardened / failures
    Info    = 'DarkCyan'   # Progress bars, status
    Accent  = 'Magenta'    # Section headers
    Muted   = 'DarkGray'   # Descriptions, secondary text
}

# When true, Write-StatusLine and Write-SectionHeader produce no output.
# Used during audit loading screen to collect data without printing.
$script:SuppressOutput = $false

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

# Returns $true if the current process is elevated (Run as Administrator)
function Test-Admin {
    $identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]$identity
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Append a timestamped entry to the log file
function Write-Log {
    param([string]$Message, [string]$Level = 'INFO')
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    Add-Content -Path $script:LogFile -Value "[$ts] [$Level] $Message" -ErrorAction SilentlyContinue
}

# Detect Windows version, build number, and edition (Pro/Enterprise/Home)
function Get-OSInfo {
    $os      = Get-CimInstance Win32_OperatingSystem
    $build   = [int]$os.BuildNumber
    $name    = if ($build -ge 22000) { "Windows 11" } else { "Windows 10" }
    $edition = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -Name EditionID -ErrorAction SilentlyContinue).EditionID
    return @{ Name = $name; Build = $build; Edition = $edition; FullVersion = $os.Version }
}

# Create a registry key path if it does not exist (recursive)
function New-RegKey {
    param([string]$Path)
    if (!(Test-Path $Path)) { New-Item -Path $Path -Force | Out-Null }
}

# Write a registry value. Creates the key path if missing.
# Type defaults to DWord; pass 'String' for REG_SZ values.
function Set-Reg {
    param([string]$Path, [string]$Name, $Value, [string]$Type = 'DWord')
    New-RegKey $Path
    Set-ItemProperty -Path $Path -Name $Name -Value $Value -Type $Type -Force -ErrorAction Stop
    Write-Log "SET $Path\$Name = $Value ($Type)"
}

# Read a single registry value. Returns $null if the key or value is absent.
function Get-Reg {
    param([string]$Path, [string]$Name)
    $item = Get-ItemProperty -Path $Path -Name $Name -ErrorAction SilentlyContinue
    if ($null -ne $item) { return $item.$Name }
    return $null
}

# Query a Windows service's current status and startup type
function Get-ServiceState {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        return @{ Status = $svc.Status.ToString(); StartType = $svc.StartType.ToString(); Exists = $true }
    }
    return @{ Status = 'N/A'; StartType = 'N/A'; Exists = $false }
}

# Stop and disable a service. Falls back to sc.exe for protected services
# (e.g., DiagTrack) where Set-Service alone is insufficient.
function Disable-Svc {
    param([string]$Name)
    $svc = Get-Service -Name $Name -ErrorAction SilentlyContinue
    if ($svc) {
        if ($svc.Status -eq 'Running') { Stop-Service -Name $Name -Force -ErrorAction SilentlyContinue }
        Set-Service -Name $Name -StartupType Disabled -ErrorAction SilentlyContinue
        # Verify - some protected services resist Set-Service
        $svc2 = Get-Service -Name $Name -ErrorAction SilentlyContinue
        if ($svc2 -and $svc2.StartType -ne 'Disabled') {
            & sc.exe config $Name start= disabled 2>&1 | Out-Null
        }
        Write-Log "Disabled service: $Name"
        return $true
    }
    return $false
}

# Query whether a scheduled task exists and its current state (Ready/Disabled/NotFound)
function Get-TaskState {
    param([string]$TaskPath, [string]$TaskName)
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task) { return $task.State.ToString() }
    return 'NotFound'
}

# Disable a scheduled task. Falls back to schtasks.exe if the PowerShell
# cmdlet fails (happens with some system-protected tasks).
function Disable-Task {
    param([string]$TaskPath, [string]$TaskName)
    $task = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($task -and $task.State -ne 'Disabled') {
        Disable-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue | Out-Null
        if ((Get-TaskState $TaskPath $TaskName) -ne 'Disabled') {
            & schtasks.exe /Change /TN "$TaskPath$TaskName" /Disable 2>&1 | Out-Null
        }
        Write-Log "Disabled task: $TaskPath$TaskName"
        return $true
    }
    return $false
}

# ============================================================================
# AUDIT / APPLY ENGINE
# ============================================================================
# Central engine that processes an array of hardening items. Each item is a
# hashtable with these possible keys:
#
#   Name     - Display name shown in audit output
#   Path     - Registry key path (HKLM:\... or HKCU:\...)
#   Key      - Registry value name
#   Want     - Desired value (integer or string)
#   Type     - Registry type: 'DWord' (default) or 'String'
#   NullOk   - If $true, a missing key counts as "already secure" (for settings
#              where Windows defaults are safe, e.g. DEP, WDigest)
#   Check    - Scriptblock returning $true/$false for custom checks that go
#              beyond simple registry comparison (e.g. SMBv1 feature state)
#   ApplyFn  - Scriptblock to run when applying a custom-check item

function Invoke-RegItems {
    param([switch]$AuditOnly, [array]$Items)
    $results = @{ Applied = 0; Skipped = 0; Failed = 0; Items = @() }

    foreach ($item in $Items) {
        # --- Custom check path (scriptblock-based) ---
        if ($item.ContainsKey('Check')) {
            $hardened = try { & $item.Check } catch { $false }
            if ($AuditOnly) {
                $status = if ($hardened) { "OK" } else { "Not configured" }
                Write-StatusLine $item.Name $status $hardened
                $results.Items += @{ Name = $item.Name; Hardened = $hardened }
            } else {
                if (!$hardened -and $item.ContainsKey('ApplyFn')) {
                    try   { & $item.ApplyFn; $results.Applied++; Write-Log "Applied: $($item.Name)" }
                    catch { $results.Failed++; Write-Log "FAIL $($item.Name): $_" 'ERROR' }
                } else { $results.Skipped++ }
            }
            continue
        }

        # --- Standard registry check path ---
        $current = Get-Reg -Path $item.Path -Name $item.Key
        $isNull  = ($null -eq $current)
        $nullOk  = ($item.ContainsKey('NullOk') -and $item.NullOk -eq $true)

        # Determine hardened status:
        #   - Null + NullOk = hardened (Windows default is already secure)
        #   - Null + !NullOk = not hardened (policy not configured)
        #   - Value matches Want = hardened
        $hardened = if ($isNull -and $nullOk) { $true }
                    elseif ($isNull) { $false }
                    else { $current -eq $item.Want }

        if ($AuditOnly) {
            $valStr = if ($isNull) { 'Not set' } else { "$current" }
            if ($hardened) {
                $status = if ($isNull -and $nullOk) { "Default secure" } else { "$($item.Key) = $valStr" }
            } else {
                $status = "$($item.Key) = $valStr [want $($item.Want)]"
            }
            Write-StatusLine $item.Name $status $hardened
            $results.Items += @{ Name = $item.Name; Hardened = $hardened }
        } else {
            if (!$hardened) {
                try {
                    # Use item-specific Type if provided, otherwise default DWord
                    $regType = if ($item.ContainsKey('Type')) { $item.Type } else { 'DWord' }
                    Set-Reg -Path $item.Path -Name $item.Key -Value $item.Want -Type $regType
                    $results.Applied++
                } catch { $results.Failed++; Write-Log "FAIL $($item.Name): $_" 'ERROR' }
            } else { $results.Skipped++ }
        }
    }
    return $results
}

# ============================================================================
# TUI RENDERING
# ============================================================================

function Clear-Screen {
    [Console]::Clear()
    [Console]::SetCursorPosition(0, 0)
}

# Display the ASCII art banner with version and detected OS info
function Write-Banner {
    $os = Get-OSInfo
    $osLine = "$($os.Name) $($os.Edition) (Build $($os.Build))"
    $pad = 37 - $osLine.Length
    if ($pad -lt 1) { $pad = 1 }
    Write-Host ""
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor $script:Colors.Banner
    Write-Host "  |                                                           |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   ##  ##  ###  #####  ####  ##### ##  ##                  |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   ##  ## ## ## ## ##  ## ## ##     ### ##                  |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   ###### ##### #####  ## ## ####  ######                  |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   ##  ## ## ## ## ##  ## ## ##     ## ###                  |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   ##  ## ## ## ## ## ####  ##### ##  ##                   |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |                                                           |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   Windows Privacy and Security Hardening Tool  v$($script:Version)     |" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   $osLine$(' ' * $pad)|" -ForegroundColor $script:Colors.Banner
    Write-Host "  |                                                           |" -ForegroundColor $script:Colors.Banner
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor $script:Colors.Banner
    Write-Host ""
}

# Print a single audit result line: [OK] or [!!] with label and status
function Write-StatusLine {
    param([string]$Label, [string]$Status, [bool]$Hardened)
    if ($script:SuppressOutput) { return }
    $color = if ($Hardened) { $script:Colors.Success } else { $script:Colors.Error }
    $icon  = if ($Hardened) { "[OK]" } else { "[!!]" }
    Write-Host "    $icon " -ForegroundColor $color -NoNewline
    Write-Host "$Label" -ForegroundColor $script:Colors.Menu -NoNewline
    $pad = 48 - $Label.Length
    if ($pad -lt 1) { $pad = 1 }
    Write-Host (' ' * $pad) -NoNewline
    Write-Host "$Status" -ForegroundColor $color
}

# Print a category section divider with title
function Write-SectionHeader {
    param([string]$Title)
    if ($script:SuppressOutput) { return }
    $lineLen = 56 - $Title.Length
    if ($lineLen -lt 1) { $lineLen = 1 }
    Write-Host ""
    Write-Host "  -- $Title $('-' * $lineLen)" -ForegroundColor $script:Colors.Accent
}

# Inline progress bar for the apply phase
function Write-Progress2 {
    param([int]$Current, [int]$Total, [string]$Activity)
    $pct    = [math]::Floor(($Current / $Total) * 100)
    $barLen = 40
    $filled = [math]::Floor($barLen * $Current / $Total)
    $bar    = ('#' * $filled) + ('-' * ($barLen - $filled))
    Write-Host "`r  [$bar] $pct% - $Activity" -ForegroundColor $script:Colors.Info -NoNewline
    if ($Current -eq $Total) { Write-Host "" }
}

# Return a single-character spinner frame for animation
function Write-Spinner {
    param([int]$Frame)
    return @('|', '/', '-', '\')[$Frame % 4]
}

# Render the audit loading screen with progress bar, spinner, and per-category
# mini results as each category scan completes.
function Show-LoadingScreen {
    param([string]$Phase, [int]$Current, [int]$Total, [string]$Detail, [hashtable[]]$CompletedCategories)

    $pct     = [math]::Floor(($Current / $Total) * 100)
    $barLen  = 44
    $filled  = [math]::Floor($barLen * $Current / $Total)
    $bar     = ('#' * $filled) + ('-' * ($barLen - $filled))
    $spinner = Write-Spinner -Frame $script:SpinnerFrame
    $script:SpinnerFrame++

    # Redraw from top of screen each frame
    [Console]::SetCursorPosition(0, 0)

    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor $script:Colors.Banner
    Write-Host "  |   HARDEN - Windows Privacy and Security Hardening Tool    |" -ForegroundColor $script:Colors.Banner
    Write-Host "  +-----------------------------------------------------------+" -ForegroundColor $script:Colors.Banner
    Write-Host ""
    Write-Host "  Scanning System..." -ForegroundColor $script:Colors.Title
    Write-Host ""
    Write-Host "  [$bar] $pct%" -ForegroundColor $script:Colors.Info
    Write-Host ""

    # Current activity with spinner
    Write-Host "  $spinner  $Phase" -ForegroundColor $script:Colors.Warning -NoNewline
    $padLen = 60 - $Phase.Length
    if ($padLen -gt 0) { Write-Host (' ' * $padLen) } else { Write-Host "" }
    Write-Host "     $Detail" -ForegroundColor $script:Colors.Muted -NoNewline
    $padLen2 = 58 - $Detail.Length
    if ($padLen2 -gt 0) { Write-Host (' ' * $padLen2) } else { Write-Host "" }
    Write-Host ""

    # Build up results table as categories complete
    if ($CompletedCategories.Count -gt 0) {
        Write-Host "  Results so far:" -ForegroundColor $script:Colors.Muted
        Write-Host "  ------------------------------------------------------------" -ForegroundColor $script:Colors.Muted
        foreach ($c in $CompletedCategories) {
            $ok = $c.Ok; $bad = $c.Bad; $catTotal = $ok + $bad
            $catColor = if ($catTotal -eq 0 -or ($ok / $catTotal) -ge 0.8) { $script:Colors.Success }
                        elseif (($ok / $catTotal) -ge 0.5) { $script:Colors.Warning }
                        else { $script:Colors.Error }
            $miniLen  = [math]::Floor(20 * $ok / [math]::Max($catTotal,1))
            $miniBar  = ('#' * $miniLen) + ('-' * (20 - $miniLen))
            Write-Host "    $($c.Label)" -ForegroundColor $script:Colors.Menu -NoNewline
            $namePad = 32 - $c.Label.Length; if ($namePad -lt 1) { $namePad = 1 }
            Write-Host (' ' * $namePad) -NoNewline
            Write-Host "[$miniBar] " -ForegroundColor $catColor -NoNewline
            Write-Host "$ok/$catTotal" -ForegroundColor $catColor
        }
        # Clear remaining lines from previous frames
        $remaining = $Total - $CompletedCategories.Count
        for ($i = 0; $i -lt $remaining; $i++) { Write-Host (' ' * 65) }
    }
}

# Wait for a single keypress. If $ValidKeys is non-empty, only those keys are
# accepted. Pass @() to accept any key (used for "press any key" prompts).
function Read-MenuChoice {
    param([string]$Prompt, [string[]]$ValidKeys)
    Write-Host ""
    Write-Host "  $Prompt" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host " " -NoNewline
    do {
        $key  = [Console]::ReadKey($true)
        $char = $key.KeyChar.ToString().ToUpper()
    } while ($ValidKeys -and $char -notin $ValidKeys)
    Write-Host $char
    return $char
}

# ============================================================================
# BACKUP AND RESTORE
# ============================================================================

# Export all policy registry keys that this script modifies into a .reg file.
# Called automatically before any apply operation.
function New-RegistryBackup {
    if (!(Test-Path $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }
    $timestamp  = Get-Date -Format 'yyyyMMdd-HHmmss'
    $backupFile = Join-Path $script:BackupDir "backup-$timestamp.reg"

    Write-Host "`n  Creating registry backup..." -ForegroundColor $script:Colors.Info

    # All registry paths that hardening categories modify
    $regPaths = @(
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\System',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\CloudContent',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsAI',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\GameDVR',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\Personalization',
        'HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell',
        'HKLM\SOFTWARE\Policies\Microsoft\Dsh',
        'HKLM\SOFTWARE\Policies\Microsoft\FindMyDevice',
        'HKLM\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config',
        'HKLM\SYSTEM\CurrentControlSet\Control\Lsa',
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters',
        'HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters',
        'HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager',
        'HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Search',
        'HKCU\SOFTWARE\Microsoft\Input\TIPC',
        'HKCU\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'
    )

    $content = "Windows Registry Editor Version 5.00`r`n; Backup by Harden-Windows.ps1 on $timestamp`r`n"
    foreach ($regPath in $regPaths) {
        $tmpFile = "$backupFile.tmp"
        & reg.exe export $regPath $tmpFile /y 2>&1 | Out-Null
        if (Test-Path $tmpFile) {
            $content += Get-Content $tmpFile -Raw -ErrorAction SilentlyContinue
            Remove-Item $tmpFile -Force
        }
    }

    Set-Content -Path $backupFile -Value $content -Encoding Unicode
    Write-Log "Backup created: $backupFile"
    Write-Host "  Backup saved: " -ForegroundColor $script:Colors.Success -NoNewline
    Write-Host $backupFile -ForegroundColor $script:Colors.Muted
    return $backupFile
}

# Display available backups and import the user's selection via reg.exe
function Restore-RegistryBackup {
    if (!(Test-Path $script:BackupDir)) {
        Write-Host "`n  No backups found." -ForegroundColor $script:Colors.Warning
        return
    }
    $backups = Get-ChildItem $script:BackupDir -Filter '*.reg' | Sort-Object LastWriteTime -Descending
    if ($backups.Count -eq 0) {
        Write-Host "`n  No backup files found in $script:BackupDir" -ForegroundColor $script:Colors.Warning
        return
    }

    Write-Host "`n  Available backups:" -ForegroundColor $script:Colors.Title
    for ($i = 0; $i -lt [Math]::Min($backups.Count, 9); $i++) {
        $b = $backups[$i]
        Write-Host "    [$($i+1)] $($b.Name)  ($($b.LastWriteTime.ToString('yyyy-MM-dd HH:mm')))" -ForegroundColor $script:Colors.Menu
    }
    Write-Host "    [0] Cancel" -ForegroundColor $script:Colors.Muted

    $choice = Read-MenuChoice "Select backup:" @('0','1','2','3','4','5','6','7','8','9')
    if ($choice -eq '0') { return }
    $idx = [int]$choice - 1
    if ($idx -ge $backups.Count) { Write-Host "  Invalid." -ForegroundColor $script:Colors.Error; return }

    $file = $backups[$idx].FullName
    Write-Host "`n  Restoring $($backups[$idx].Name)..." -ForegroundColor $script:Colors.Info
    & reg.exe import $file 2>&1 | Out-Null
    Write-Log "Restored backup: $file"
    Write-Host "  Registry restored. Restart recommended." -ForegroundColor $script:Colors.Success
}

# ============================================================================
# CATEGORY: TELEMETRY AND DATA COLLECTION
# Disables Windows diagnostic data, feedback prompts, error reporting,
# application compatibility tracking, and advertising identifiers.
# ============================================================================

function Invoke-Telemetry {
    param([switch]$AuditOnly)
    $items = @(
        # Set telemetry to Security level (0 = off on Enterprise, minimal on Pro)
        @{ Name = 'Telemetry level - Security/Off';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Key = 'AllowTelemetry'; Want = 0 },
        # Suppress "How was your experience?" feedback popups
        @{ Name = 'Feedback notifications';             Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Key = 'DoNotShowFeedbackNotifications'; Want = 1 },
        # Never prompt for feedback surveys
        @{ Name = 'Feedback frequency - Never';        Path = 'HKCU:\SOFTWARE\Microsoft\Siuf\Rules'; Key = 'NumberOfSIUFInPeriod'; Want = 0 },
        # Disable personalized tips based on diagnostic data
        @{ Name = 'Tailored experiences';               Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Privacy'; Key = 'TailoredExperiencesWithDiagnosticDataEnabled'; Want = 0 },
        # Disable Diagnostic Data Viewer app data collection
        @{ Name = 'Diagnostic data viewer';             Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Key = 'DisableDiagnosticDataViewer'; Want = 1 },
        # Disable Windows Error Reporting entirely
        @{ Name = 'Error reporting';                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting'; Key = 'Disabled'; Want = 1 },
        # Block handwriting recognition error data uploads
        @{ Name = 'Handwriting error reports';          Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\HandwritingErrorReports'; Key = 'PreventHandwritingErrorReports'; Want = 1 },
        # Disable app compatibility inventory collector (sends app data to MS)
        @{ Name = 'Inventory collector';                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\AppCompat'; Key = 'DisableInventory'; Want = 1 },
        # Disable per-user advertising identifier used for ad tracking
        @{ Name = 'Advertising ID';                     Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo'; Key = 'Enabled'; Want = 0 },
        # Disable typing/inking data collection for personalization
        @{ Name = 'Input personalization';              Path = 'HKCU:\SOFTWARE\Microsoft\Input\TIPC'; Key = 'Enabled'; Want = 0 },
        # Limit the size of diagnostic log files collected
        @{ Name = 'Diagnostic log collection';          Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Key = 'LimitDiagnosticLogCollection'; Want = 1 },
        # Limit diagnostic memory dump collection
        @{ Name = 'Dump collection';                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection'; Key = 'LimitDumpCollection'; Want = 1 }
    )
    return (Invoke-RegItems -AuditOnly:$AuditOnly -Items $items)
}

# ============================================================================
# CATEGORY: PRIVACY
# Controls activity tracking, location services, speech data, clipboard sync,
# device finding, and hardware access defaults.
# ============================================================================

function Invoke-Privacy {
    param([switch]$AuditOnly)
    $items = @(
        # Disable Windows Timeline activity feed
        @{ Name = 'Activity history - feed';           Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'EnableActivityFeed'; Want = 0 },
        # Don't publish user activities to Microsoft
        @{ Name = 'Activity history - publish';        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'PublishUserActivities'; Want = 0 },
        # Don't upload activity history to the cloud
        @{ Name = 'Activity history - upload';         Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'UploadUserActivities'; Want = 0 },
        # Disable cloud-based speech recognition
        @{ Name = 'Online speech recognition';         Path = 'HKCU:\SOFTWARE\Microsoft\Speech_OneCore\Settings\OnlineSpeechPrivacy'; Key = 'HasAccepted'; Want = 0 },
        # Disable inking and typing personalization data sharing
        @{ Name = 'Inking/typing personalization';     Path = 'HKCU:\SOFTWARE\Microsoft\Personalization\Settings'; Key = 'AcceptedPrivacyPolicy'; Want = 0 },
        # Disable system-wide location tracking
        @{ Name = 'Location tracking';                 Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Key = 'DisableLocation'; Want = 1 },
        # Disable location scripting APIs
        @{ Name = 'Location scripting';                Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\LocationAndSensors'; Key = 'DisableLocationScripting'; Want = 1 },
        # Disable clipboard history (local storage)
        @{ Name = 'Clipboard cloud sync';              Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'AllowClipboardHistory'; Want = 0 },
        # Disable clipboard sync across devices
        @{ Name = 'Cross-device clipboard';            Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'AllowCrossDeviceClipboard'; Want = 0 },
        # Don't track which apps are launched (used for Start menu suggestions)
        @{ Name = 'App launch tracking';               Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'Start_TrackProgs'; Want = 0 },
        # Disable Find My Device location reporting
        @{ Name = 'Find My Device';                    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\FindMyDevice'; Key = 'AllowFindMyDevice'; Want = 0 },
        # Disable online tips in the Settings app
        @{ Name = 'Settings app online tips';          Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Key = 'AllowOnlineTips'; Want = 0 },
        # Deny apps camera access by default (users can still grant per-app)
        @{ Name = 'Camera access default';             Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam'; Key = 'Value'; Want = 'Deny'; Type = 'String' },
        # Deny apps microphone access by default
        @{ Name = 'Microphone access default';         Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone'; Key = 'Value'; Want = 'Deny'; Type = 'String' }
    )
    return (Invoke-RegItems -AuditOnly:$AuditOnly -Items $items)
}

# ============================================================================
# CATEGORY: SERVICES
# Disables unnecessary Windows services that consume resources or pose risk.
# Skips any service not present on the system.
# ============================================================================

function Invoke-Services {
    param([switch]$AuditOnly)
    $results = @{ Applied = 0; Skipped = 0; Failed = 0; Items = @() }

    $services = @(
        @{ Name = 'DiagTrack';        Display = 'Connected User Experiences/Telemetry' },  # Primary telemetry service
        @{ Name = 'dmwappushservice'; Display = 'WAP Push Message Routing' },              # Telemetry helper
        @{ Name = 'lfsvc';            Display = 'Geolocation Service' },                   # Location tracking
        @{ Name = 'MapsBroker';       Display = 'Downloaded Maps Manager' },               # Offline maps updates
        @{ Name = 'RetailDemo';       Display = 'Retail Demo Service' },                   # Store demo mode
        @{ Name = 'WerSvc';           Display = 'Windows Error Reporting' },               # Crash dump uploads
        @{ Name = 'Fax';              Display = 'Fax Service' },                           # Legacy fax
        @{ Name = 'XblAuthManager';   Display = 'Xbox Live Auth Manager' },                # Xbox auth
        @{ Name = 'XblGameSave';      Display = 'Xbox Live Game Save' },                   # Xbox cloud saves
        @{ Name = 'XboxNetApiSvc';    Display = 'Xbox Live Networking' },                  # Xbox networking
        @{ Name = 'XboxGipSvc';       Display = 'Xbox Accessory Management' },             # Xbox peripherals
        @{ Name = 'WMPNetworkSvc';    Display = 'Windows Media Player Sharing' },          # DLNA media sharing
        @{ Name = 'RemoteRegistry';   Display = 'Remote Registry' }                        # Remote registry editing
    )

    foreach ($svc in $services) {
        $state = Get-ServiceState $svc.Name
        if (!$state.Exists) { continue }
        $hardened = ($state.StartType -eq 'Disabled')
        if ($AuditOnly) {
            Write-StatusLine "$($svc.Display) [$($svc.Name)]" "$($state.Status) / $($state.StartType)" $hardened
            $results.Items += @{ Name = $svc.Display; Hardened = $hardened }
        } else {
            if (!$hardened) {
                if (Disable-Svc $svc.Name) { $results.Applied++ } else { $results.Failed++ }
            } else { $results.Skipped++ }
        }
    }
    return $results
}

# ============================================================================
# CATEGORY: SCHEDULED TASKS
# Disables telemetry, feedback, and compatibility data-collection tasks.
# Tasks that don't exist on the system are silently skipped.
# ============================================================================

function Invoke-Tasks {
    param([switch]$AuditOnly)
    $results = @{ Applied = 0; Skipped = 0; Failed = 0; Items = @() }

    $tasks = @(
        @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'Consolidator' },            # CEIP data upload
        @{ Path = '\Microsoft\Windows\Customer Experience Improvement Program\'; Name = 'UsbCeip' },                 # USB CEIP telemetry
        @{ Path = '\Microsoft\Windows\Application Experience\';                   Name = 'Microsoft Compatibility Appraiser' },  # Compat telemetry
        @{ Path = '\Microsoft\Windows\Application Experience\';                   Name = 'ProgramDataUpdater' },      # App compat data
        @{ Path = '\Microsoft\Windows\Application Experience\';                   Name = 'StartupAppTask' },          # Startup app evaluation
        @{ Path = '\Microsoft\Windows\Feedback\Siuf\';                            Name = 'DmClient' },               # Feedback data
        @{ Path = '\Microsoft\Windows\Feedback\Siuf\';                            Name = 'DmClientOnScenarioDownload' },  # Feedback triggers
        @{ Path = '\Microsoft\Windows\Maps\';                                     Name = 'MapsToastTask' },           # Maps notifications
        @{ Path = '\Microsoft\Windows\Maps\';                                     Name = 'MapsUpdateTask' },          # Maps data updates
        @{ Path = '\Microsoft\Windows\DiskDiagnostic\';                           Name = 'Microsoft-Windows-DiskDiagnosticDataCollector' },  # Disk telemetry
        @{ Path = '\Microsoft\Windows\CloudExperienceHost\';                      Name = 'CreateObjectTask' },        # OOBE cloud tasks
        @{ Path = '\Microsoft\Windows\Autochk\';                                  Name = 'Proxy' }                    # Autochk telemetry proxy
    )

    foreach ($task in $tasks) {
        $state = Get-TaskState $task.Path $task.Name
        if ($state -eq 'NotFound') { continue }
        $hardened = ($state -eq 'Disabled')
        if ($AuditOnly) {
            Write-StatusLine "$($task.Name)" $state $hardened
            $results.Items += @{ Name = $task.Name; Hardened = $hardened }
        } else {
            if (!$hardened) {
                if (Disable-Task $task.Path $task.Name) { $results.Applied++ } else { $results.Failed++ }
            } else { $results.Skipped++ }
        }
    }
    return $results
}

# ============================================================================
# CATEGORY: NETWORK AND FIREWALL
# Hardens network protocols (SMBv1, LLMNR, NetBIOS, WPAD), secures RDP,
# enables DNS-over-HTTPS, and blocks telemetry at the firewall level.
# ============================================================================

function Invoke-Network {
    param([switch]$AuditOnly)
    $results = @{ Applied = 0; Skipped = 0; Failed = 0; Items = @() }

    $items = @(
        # Disable Link-Local Multicast Name Resolution (LLMNR) - prevents poisoning attacks
        @{ Name = 'Disable LLMNR';              Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient'; Key = 'EnableMulticast'; Want = 0 },
        # Disable Web Proxy Auto-Discovery - prevents MITM via rogue WPAD servers
        @{ Name = 'Disable WPAD';                Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Wpad'; Key = 'WpadOverride'; Want = 1 },
        # Disable SMBv1 (legacy, vulnerable to EternalBlue/WannaCry). Uses feature
        # state check since the registry key may not exist when SMBv1 was never installed.
        @{ Name = 'SMBv1 disabled';
            Check = {
                $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
                if ($null -eq $feature -or $feature.State -eq 'Disabled') { return $true }
                $reg = Get-Reg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start'
                return ($reg -eq 4)
            }
            ApplyFn = {
                Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue | Out-Null
                Set-Reg -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\mrxsmb10' -Name 'Start' -Value 4
            }
        },
        # Disable peer-to-peer Delivery Optimization (downloads from other PCs)
        @{ Name = 'Delivery opt. no P2P';        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Key = 'DODownloadMode'; Want = 0 },
        # Disable Hotspot 2.0 auto-connect to open networks
        @{ Name = 'Disable Hotspot 2.0';         Path = 'HKLM:\SOFTWARE\Microsoft\WlanSvc\AnqpCache'; Key = 'OsuRegistrationStatus'; Want = 0 },
        # Disable auto-connect to suggested open Wi-Fi hotspots
        @{ Name = 'Disable WiFi auto-connect';   Path = 'HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config'; Key = 'AutoConnectAllowedOEM'; Want = 0 },
        # Require Network Level Authentication for RDP (prevents pre-auth attacks)
        @{ Name = 'RDP: require NLA';             Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Key = 'UserAuthentication'; Want = 1 },
        # Force TLS as the RDP security layer (instead of weaker RDP Security)
        @{ Name = 'RDP: TLS encryption';          Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Key = 'SecurityLayer'; Want = 2 },
        # Set RDP encryption to High (128-bit)
        @{ Name = 'RDP: high encryption level';   Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'; Key = 'MinEncryptionLevel'; Want = 3 },
        # Enable DNS-over-HTTPS automatic upgrade (Win11) for encrypted DNS
        @{ Name = 'DNS-over-HTTPS auto-upgrade';  Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters'; Key = 'EnableAutoDoh'; Want = 2 },
        # Set NetBIOS to P-node (point-to-point only) - mitigates name poisoning
        @{ Name = 'Disable NetBIOS over TCP';     Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters'; Key = 'NodeType'; Want = 2 }
    )

    $regResults = Invoke-RegItems -AuditOnly:$AuditOnly -Items $items
    $results.Applied += $regResults.Applied; $results.Skipped += $regResults.Skipped
    $results.Failed  += $regResults.Failed;  $results.Items   += $regResults.Items

    # --- Outbound firewall rule blocking known Microsoft telemetry endpoints ---
    $fwRule    = Get-NetFirewallRule -DisplayName 'Block-MS-Telemetry' -ErrorAction SilentlyContinue
    $fwHardened = ($null -ne $fwRule -and $fwRule.Enabled -eq 'True')
    if ($AuditOnly) {
        Write-StatusLine "Firewall: block telemetry endpoints" $(if ($fwHardened) {"Active"} else {"Not configured"}) $fwHardened
        $results.Items += @{ Name = 'Telemetry firewall rule'; Hardened = $fwHardened }
    } else {
        if (!$fwHardened) {
            try {
                Remove-NetFirewallRule -DisplayName 'Block-MS-Telemetry' -ErrorAction SilentlyContinue
                $ips = @()
                @('vortex.data.microsoft.com','vortex-win.data.microsoft.com',
                  'telecommand.telemetry.microsoft.com','watson.telemetry.microsoft.com',
                  'watson.microsoft.com','settings-sandbox.data.microsoft.com',
                  'oca.telemetry.microsoft.com','sqm.telemetry.microsoft.com'
                ) | ForEach-Object {
                    try { $ips += [System.Net.Dns]::GetHostAddresses($_) | ForEach-Object { $_.IPAddressToString } } catch {}
                }
                $ips = $ips | Select-Object -Unique
                if ($ips.Count -gt 0) {
                    New-NetFirewallRule -DisplayName 'Block-MS-Telemetry' -Direction Outbound -Action Block `
                        -RemoteAddress $ips -Profile Any -Enabled True | Out-Null
                    $results.Applied++
                    Write-Log "Created firewall rule blocking $($ips.Count) telemetry IPs"
                }
            } catch { $results.Failed++; Write-Log "FAIL firewall rule: $_" 'ERROR' }
        } else { $results.Skipped++ }
    }

    # --- Ensure Windows Firewall is enabled on all profiles ---
    foreach ($p in (Get-NetFirewallProfile -ErrorAction SilentlyContinue)) {
        $enabled = ($p.Enabled -eq 'True')
        if ($AuditOnly) {
            Write-StatusLine "Firewall profile: $($p.Name)" $(if ($enabled) {"Enabled"} else {"DISABLED"}) $enabled
            $results.Items += @{ Name = "Firewall: $($p.Name)"; Hardened = $enabled }
        } else {
            if (!$enabled) {
                try { Set-NetFirewallProfile -Name $p.Name -Enabled True; $results.Applied++ }
                catch { $results.Failed++ }
            } else { $results.Skipped++ }
        }
    }

    return $results
}

# ============================================================================
# CATEGORY: SECURITY HARDENING
# Core OS security: UAC, NTLM, LSA protection, Credential Guard, autorun,
# PowerShell logging, SMB signing, anonymous access restrictions, and memory
# protections (DEP, SEHOP, WDigest).
# ============================================================================

function Invoke-Security {
    param([switch]$AuditOnly)
    $items = @(
        # Ensure User Account Control is enabled
        @{ Name = 'UAC enabled';                  Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Key = 'EnableLUA'; Want = 1 },
        # Prompt for consent on the secure desktop for admin operations
        @{ Name = 'UAC max prompt level';          Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Key = 'ConsentPromptBehaviorAdmin'; Want = 2 },
        # Disable autorun on all drive types (prevents malware from USB/CD)
        @{ Name = 'Disable autorun';               Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer'; Key = 'NoDriveTypeAutoRun'; Want = 255 },
        # Disable autoplay dialog for removable media
        @{ Name = 'Disable autoplay';              Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers'; Key = 'DisableAutoplay'; Want = 1 },
        # Prevent remote assistance connections
        @{ Name = 'Disable remote assistance';     Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Remote Assistance'; Key = 'fAllowToGetHelp'; Want = 0 },
        # Disable automatic admin shares (C$, ADMIN$)
        @{ Name = 'Disable admin shares';          Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Key = 'AutoShareWks'; Want = 0 },
        # Log PowerShell script block content (critical for forensics)
        @{ Name = 'PS script block logging';       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'; Key = 'EnableScriptBlockLogging'; Want = 1 },
        # Log PowerShell module loading
        @{ Name = 'PS module logging';             Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging'; Key = 'EnableModuleLogging'; Want = 1 },
        # SEHOP is enabled by default on Win10+; NullOk avoids false alarm when key absent
        @{ Name = 'SEH overwrite protection';      Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\kernel'; Key = 'DisableExceptionChainValidation'; Want = 0; NullOk = $true },
        # DEP is on by default; NullOk avoids false alarm when policy key absent
        @{ Name = 'Data Execution Prevention';     Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Key = 'NoDataExecutionPrevention'; Want = 0; NullOk = $true },
        # WDigest credential caching disabled since Win8.1; NullOk for absent key
        @{ Name = 'WDigest credential caching';    Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest'; Key = 'UseLogonCredential'; Want = 0; NullOk = $true },
        # Force NTLMv2 only, refuse LM and NTLMv1 (CIS L1, mitigates relay attacks)
        @{ Name = 'NTLM: NTLMv2 only';            Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Key = 'LmCompatibilityLevel'; Want = 5 },
        # Don't store LAN Manager hash (weak, easily cracked)
        @{ Name = 'NTLM: No LM hash storage';     Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Key = 'NoLMHash'; Want = 1 },
        # Run LSA as a Protected Process (blocks credential-dumping tools)
        @{ Name = 'LSA Protection - RunAsPPL';     Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Key = 'RunAsPPL'; Want = 1 },
        # Require SMB packet signing on the server side
        @{ Name = 'SMB server signing required';   Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters'; Key = 'RequireSecuritySignature'; Want = 1 },
        # Require SMB packet signing on the client side
        @{ Name = 'SMB client signing required';   Path = 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters'; Key = 'RequireSecuritySignature'; Want = 1 },
        # Credential Guard: uses VBS to isolate NTLM hashes and Kerberos TGTs.
        # AUDIT-ONLY: enabling requires compatible hardware (UEFI, TPM, VBS) and
        # can cause boot failures on unsupported systems. Enable manually via:
        #   reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v LsaCfgFlags /t REG_DWORD /d 1 /f
        @{ Name = 'Credential Guard [audit-only]';
            Check = {
                $dg = Get-CimInstance -ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction SilentlyContinue
                if ($dg -and $dg.SecurityServicesRunning -contains 1) { return $true }
                $reg = Get-Reg -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'LsaCfgFlags'
                return ($reg -eq 1 -or $reg -eq 2)
            }
        },
        # Block anonymous enumeration of SAM accounts
        @{ Name = 'Restrict anonymous SAM enum';   Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Key = 'RestrictAnonymousSAM'; Want = 1 },
        # Block anonymous enumeration of shares and accounts
        @{ Name = 'Restrict anonymous access';     Path = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'; Key = 'RestrictAnonymous'; Want = 1 }
    )
    return (Invoke-RegItems -AuditOnly:$AuditOnly -Items $items)
}

# ============================================================================
# CATEGORY: DEFENDER AND ASR RULES
# Enables Microsoft Defender Attack Surface Reduction rules (CIS/ACSC baseline)
# and verifies Defender protection features. ASR rules are set to Block mode.
# ============================================================================

function Invoke-Defender {
    param([switch]$AuditOnly)
    $results = @{ Applied = 0; Skipped = 0; Failed = 0; Items = @() }

    # ASR rules from CIS Benchmark and Microsoft recommended baseline.
    # Action values: 0=Disabled, 1=Block, 2=Audit, 6=Warn
    $asrRules = @(
        @{ Id = '3B576869-A4EC-4529-8536-B80A7769E899'; Desc = 'Block Office apps creating executables' },
        @{ Id = 'D4F940AB-401B-4EFC-AADC-AD5F3C50688A'; Desc = 'Block Office apps creating child processes' },
        @{ Id = '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84'; Desc = 'Block Office apps injecting into processes' },
        @{ Id = 'D3E037E1-3EB8-44C8-A917-57927947596D'; Desc = 'Block JS/VBS launching downloads' },
        @{ Id = '5BEB7EFE-FD9A-4556-801D-275E5FFC04CC'; Desc = 'Block obfuscated scripts' },
        @{ Id = 'B2B3F03D-6A65-4F7B-A9C7-1C7EF74A9BA4'; Desc = 'Block untrusted USB processes' },
        @{ Id = '9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2'; Desc = 'Block credential stealing from LSASS' },
        @{ Id = 'BE9BA2D9-53EA-4CDC-84E5-9B1EEEE46550'; Desc = 'Block executables from email' },
        @{ Id = 'E6DB77E5-3DF2-4CF1-B95A-636979351E5B'; Desc = 'Block persistence via WMI' },
        @{ Id = 'D1E49AAC-8F56-4280-B9BA-993A6D77406C'; Desc = 'Block process creation from PSExec/WMI' },
        @{ Id = '56A863A9-875E-4185-98A7-B882C64B5CE5'; Desc = 'Block abuse of vulnerable signed drivers' },
        @{ Id = '26190899-1602-49E8-8B27-EB1D0A1CE869'; Desc = 'Block Office comms creating child processes' },
        @{ Id = '7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C'; Desc = 'Block Adobe Reader creating child processes' },
        @{ Id = '92E97FA1-2EDF-4476-BDD6-9DD0B4DDDC7B'; Desc = 'Block Win32 API calls from Office macros' }
    )

    # Cache Defender preferences once (avoid repeated WMI calls per rule)
    $currentIds     = @()
    $currentActions = @()
    $mpPref         = $null
    try {
        $mpPref         = Get-MpPreference -ErrorAction Stop
        $currentIds     = @($mpPref.AttackSurfaceReductionRules_Ids)
        $currentActions = @($mpPref.AttackSurfaceReductionRules_Actions)
    } catch {
        Write-Log "Could not query Defender preferences: $_" 'WARN'
    }

    # Check each ASR rule
    foreach ($rule in $asrRules) {
        $idx = -1
        for ($i = 0; $i -lt $currentIds.Count; $i++) {
            if ($currentIds[$i] -eq $rule.Id) { $idx = $i; break }
        }
        $action  = if ($idx -ge 0 -and $idx -lt $currentActions.Count) { $currentActions[$idx] } else { -1 }
        $hardened = ($action -eq 1)  # Block mode

        if ($AuditOnly) {
            $statusMap = @{ 0 = 'Disabled'; 1 = 'Block'; 2 = 'Audit'; 6 = 'Warn'; -1 = 'Not configured' }
            $status = if ($statusMap.ContainsKey([int]$action)) { $statusMap[[int]$action] } else { "Unknown ($action)" }
            Write-StatusLine $rule.Desc $status $hardened
            $results.Items += @{ Name = $rule.Desc; Hardened = $hardened }
        } else {
            if (!$hardened) {
                try {
                    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule.Id -AttackSurfaceReductionRules_Actions 1 -ErrorAction Stop
                    $results.Applied++
                    Write-Log "ASR enabled: $($rule.Id) - $($rule.Desc)"
                } catch { $results.Failed++; Write-Log "FAIL ASR $($rule.Id): $_" 'ERROR' }
            } else { $results.Skipped++ }
        }
    }

    # Additional Defender feature checks (using cached $mpPref)
    $defenderItems = @(
        @{ Name = 'Real-time protection';
            Check = { if ($mpPref) { $mpPref.DisableRealtimeMonitoring -eq $false } else { $false } }
        },
        @{ Name = 'Cloud-delivered protection';
            Check = { if ($mpPref) { $mpPref.MAPSReporting -ge 1 } else { $false } }
        },
        @{ Name = 'PUA protection enabled';
            Check   = { if ($mpPref) { $mpPref.PUAProtection -eq 1 } else { $false } }
            ApplyFn = { Set-MpPreference -PUAProtection 1 -ErrorAction Stop }
        },
        @{ Name = 'Network protection enabled';
            Check   = { if ($mpPref) { $mpPref.EnableNetworkProtection -eq 1 } else { $false } }
            ApplyFn = { Set-MpPreference -EnableNetworkProtection 1 -ErrorAction Stop }
        },
        # AUDIT-ONLY: Controlled Folder Access blocks untrusted apps from modifying
        # protected folders (Documents, Desktop, etc). Can break legitimate apps that
        # write to these locations. Enable manually via:
        #   Set-MpPreference -EnableControlledFolderAccess 1
        @{ Name = 'Controlled folder access [audit-only]';
            Check = { if ($mpPref) { $mpPref.EnableControlledFolderAccess -eq 1 } else { $false } }
        }
    )

    $regResults = Invoke-RegItems -AuditOnly:$AuditOnly -Items $defenderItems
    $results.Applied += $regResults.Applied; $results.Skipped += $regResults.Skipped
    $results.Failed  += $regResults.Failed;  $results.Items   += $regResults.Items

    return $results
}

# ============================================================================
# CATEGORY: BLOATWARE REMOVAL
# Removes pre-installed Microsoft Store apps and disables suggested/promoted
# content in Start menu and Settings.
# ============================================================================

function Invoke-Bloatware {
    param([switch]$AuditOnly)
    $results = @{ Applied = 0; Skipped = 0; Failed = 0; Items = @() }

    # AppX packages to remove (wildcard supported)
    $packages = @(
        'Microsoft.BingNews', 'Microsoft.BingWeather', 'Microsoft.GetHelp',
        'Microsoft.Getstarted', 'Microsoft.MicrosoftSolitaireCollection',
        'Microsoft.People', 'Microsoft.PowerAutomate*', 'Microsoft.Todos',
        'Microsoft.WindowsFeedbackHub', 'Microsoft.WindowsMaps',
        'Microsoft.ZuneMusic', 'Microsoft.ZuneVideo',
        'Microsoft.MicrosoftOfficeHub', 'Clipchamp.Clipchamp',
        'Microsoft.549981C3F5F10',   # Cortana
        'Microsoft.YourPhone', 'MicrosoftTeams', 'Microsoft.GamingApp',
        'Microsoft.Xbox.TCUI', 'Microsoft.XboxGameOverlay',
        'Microsoft.XboxGamingOverlay', 'Microsoft.XboxIdentityProvider',
        'Microsoft.XboxSpeechToTextOverlay'
    )

    # Registry settings that control suggested/promoted content
    $regItems = @(
        @{ Name = 'Suggested apps in Start';       Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Key = 'SystemPaneSuggestionsEnabled'; Want = 0 },
        @{ Name = 'Suggested content in Settings';  Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Key = 'SubscribedContent-338393Enabled'; Want = 0 },
        @{ Name = 'Tips and suggestions';           Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Key = 'SubscribedContent-338389Enabled'; Want = 0 },
        @{ Name = 'Silently installed apps';        Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Key = 'SilentInstalledAppsEnabled'; Want = 0 },
        @{ Name = 'Pre-installed app suggestions';  Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Key = 'PreInstalledAppsEnabled'; Want = 0 },
        @{ Name = 'OEM pre-installed suggestions';  Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager'; Key = 'OemPreInstalledAppsEnabled'; Want = 0 },
        @{ Name = 'Cloud consumer features';        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Key = 'DisableWindowsConsumerFeatures'; Want = 1 },
        @{ Name = 'Spotlight features';             Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Key = 'DisableWindowsSpotlightFeatures'; Want = 1 },
        @{ Name = 'Soft landing tips/tricks';       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Key = 'DisableSoftLanding'; Want = 1 },
        @{ Name = 'Cloud-optimized content';        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent'; Key = 'DisableCloudOptimizedContent'; Want = 1 }
    )

    # Audit or remove bloatware packages
    if ($AuditOnly) {
        if (-not $script:SuppressOutput) {
            Write-Host ""
            Write-Host "    Installed bloatware packages:" -ForegroundColor $script:Colors.Muted
        }
        $found = 0
        foreach ($pkg in $packages) {
            $installed = Get-AppxPackage -Name $pkg -ErrorAction SilentlyContinue
            if ($installed) {
                if (-not $script:SuppressOutput) { Write-Host "      - $($installed.Name)" -ForegroundColor $script:Colors.Error }
                $found++
                $results.Items += @{ Name = $installed.Name; Hardened = $false }
            }
        }
        if (-not $script:SuppressOutput) {
            if ($found -eq 0) { Write-Host "      None found" -ForegroundColor $script:Colors.Success }
            Write-Host ""
        }
    } else {
        foreach ($pkg in $packages) {
            $installed = Get-AppxPackage -Name $pkg -ErrorAction SilentlyContinue
            if ($installed) {
                try {
                    $installed | Remove-AppxPackage -ErrorAction Stop
                    # Also remove the provisioned package so it doesn't reinstall for new users
                    Get-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue |
                        Where-Object DisplayName -eq $pkg |
                        Remove-AppxProvisionedPackage -Online -ErrorAction SilentlyContinue | Out-Null
                    $results.Applied++
                    Write-Log "Removed: $($installed.Name)"
                } catch { $results.Failed++; Write-Log "FAIL remove $pkg : $_" 'ERROR' }
            } else { $results.Skipped++ }
        }
    }

    # Process suggested-content registry settings
    $regResults = Invoke-RegItems -AuditOnly:$AuditOnly -Items $regItems
    $results.Applied += $regResults.Applied; $results.Skipped += $regResults.Skipped
    $results.Failed  += $regResults.Failed;  $results.Items   += $regResults.Items

    return $results
}

# ============================================================================
# CATEGORY: AI / COPILOT / RECALL
# Disables Windows Copilot, Recall (AI screenshot analysis), and Bing/web
# search integration in the Start menu and taskbar.
# ============================================================================

function Invoke-AI {
    param([switch]$AuditOnly)
    $items = @(
        # Disable Copilot system-wide via Group Policy
        @{ Name = 'Disable Windows Copilot';      Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Key = 'TurnOffWindowsCopilot'; Want = 1 },
        # Disable Copilot for the current user
        @{ Name = 'Disable Copilot - user';        Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\WindowsCopilot'; Key = 'TurnOffWindowsCopilot'; Want = 1 },
        # Disable Recall AI data analysis (screenshot-based history)
        @{ Name = 'Disable Recall / AI analysis';  Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Key = 'DisableAIDataAnalysis'; Want = 1 },
        # Disable Recall snapshot capture
        @{ Name = 'Disable Recall snapshots';       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsAI'; Key = 'TurnOffSavingSnapshots'; Want = 1 },
        # Disable web search from Start menu / search bar
        @{ Name = 'Search: disable web search';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Key = 'DisableWebSearch'; Want = 1 },
        # Don't show web results in local search
        @{ Name = 'Search: disable web results';   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search'; Key = 'ConnectedSearchUseWeb'; Want = 0 },
        # Disable search box auto-suggestions (cloud-powered)
        @{ Name = 'Search: disable suggestions';   Path = 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Explorer'; Key = 'DisableSearchBoxSuggestions'; Want = 1 },
        # Disable Bing AI chat integration in search
        @{ Name = 'Search: disable Bing AI chat';  Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search'; Key = 'BingSearchEnabled'; Want = 0 }
    )
    return (Invoke-RegItems -AuditOnly:$AuditOnly -Items $items)
}

# ============================================================================
# CATEGORY: WINDOWS UPDATE
# Controls update delivery, deferral, and restart behavior. Does NOT disable
# Windows Update (that would be a security risk).
# ============================================================================

function Invoke-Updates {
    param([switch]$AuditOnly)
    $items = @(
        # Prevent forced restarts when users are logged in
        @{ Name = 'No auto-restart with users';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'; Key = 'NoAutoRebootWithLoggedOnUsers'; Want = 1 },
        # Delivery Optimization: LAN only (no internet P2P)
        @{ Name = 'Delivery optimization LAN only'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\DeliveryOptimization'; Key = 'DODownloadMode'; Want = 1 },
        # Don't install driver updates through Windows Update
        @{ Name = 'No driver updates via WU';      Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Key = 'ExcludeWUDriversInQualityUpdate'; Want = 1 },
        # Defer feature updates by 365 days (gives time to assess stability)
        @{ Name = 'Defer feature updates 365d';    Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Key = 'DeferFeatureUpdatesPeriodInDays'; Want = 365 },
        # Block enrollment in Windows Insider Program
        @{ Name = 'Disable insider program';       Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'; Key = 'ManagePreviewBuildsPolicyValue'; Want = 1 }
    )
    return (Invoke-RegItems -AuditOnly:$AuditOnly -Items $items)
}

# ============================================================================
# CATEGORY: MISCELLANEOUS
# Quality-of-life security tweaks: file extension visibility, lock screen,
# GameDVR, and widgets.
# ============================================================================

function Invoke-Misc {
    param([switch]$AuditOnly)
    $items = @(
        # Show file extensions (prevents ".pdf.exe" social engineering)
        @{ Name = 'Show file extensions';              Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'HideFileExt'; Want = 0 },
        # Show hidden files (helps spot malware in hidden folders)
        @{ Name = 'Show hidden files';                 Path = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced'; Key = 'Hidden'; Want = 1 },
        # Don't show notification content on the lock screen
        @{ Name = 'Disable lock screen notifications'; Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System'; Key = 'DisableLockScreenAppNotifications'; Want = 1 },
        # Disable camera on the lock screen
        @{ Name = 'Disable lock screen camera';        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Personalization'; Key = 'NoLockScreenCamera'; Want = 1 },
        # Show detailed status messages during logon/logoff
        @{ Name = 'Verbose logon messages';            Path = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'; Key = 'VerboseStatus'; Want = 1 },
        # Disable Xbox Game DVR/Bar (reduces attack surface, frees resources)
        @{ Name = 'Disable GameDVR';                   Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\GameDVR'; Key = 'AllowGameDVR'; Want = 0 },
        # Disable News and Interests / Widgets on the taskbar
        @{ Name = 'Disable News and Interests';        Path = 'HKLM:\SOFTWARE\Policies\Microsoft\Dsh'; Key = 'AllowNewsAndInterests'; Want = 0 }
    )
    return (Invoke-RegItems -AuditOnly:$AuditOnly -Items $items)
}

# ============================================================================
# CATEGORY MAP
# Maps category keys to their display labels, functions, and descriptions.
# The order here determines the order in the TUI and audit output.
# ============================================================================

$script:CategoryMap = [ordered]@{
    Telemetry = @{ Label = 'Telemetry and Data Collection'; Fn = 'Invoke-Telemetry'; Desc = 'Disable diagnostic data, feedback, error reports' }
    Privacy   = @{ Label = 'Privacy';                        Fn = 'Invoke-Privacy';   Desc = 'Activity history, location, speech, camera/mic' }
    Services  = @{ Label = 'Services';                       Fn = 'Invoke-Services';  Desc = 'Stop unnecessary Windows services' }
    Tasks     = @{ Label = 'Scheduled Tasks';                Fn = 'Invoke-Tasks';     Desc = 'Disable CEIP, feedback, compatibility tasks' }
    Network   = @{ Label = 'Network and Firewall';           Fn = 'Invoke-Network';   Desc = 'SMBv1, LLMNR, RDP NLA, DNS-over-HTTPS' }
    Security  = @{ Label = 'Security Hardening';             Fn = 'Invoke-Security';  Desc = 'UAC, NTLM, LSA, Credential Guard, SMB sign' }
    Defender  = @{ Label = 'Defender and ASR Rules';         Fn = 'Invoke-Defender';  Desc = 'Attack Surface Reduction, PUA, network prot.' }
    Bloatware = @{ Label = 'Bloatware Removal';              Fn = 'Invoke-Bloatware'; Desc = 'Remove pre-installed apps, suggested content' }
    AI        = @{ Label = 'AI / Copilot / Recall';          Fn = 'Invoke-AI';        Desc = 'Disable Copilot, Recall, Bing AI, web search' }
    Updates   = @{ Label = 'Windows Update';                 Fn = 'Invoke-Updates';   Desc = 'Defer updates, disable P2P, no auto-restart' }
    Misc      = @{ Label = 'Miscellaneous';                  Fn = 'Invoke-Misc';      Desc = 'File extensions, GameDVR, widgets, lock screen' }
}

# ============================================================================
# TUI MENUS
# ============================================================================

function Show-MainMenu {
    Clear-Screen
    Write-Banner
    Write-Host "    [1]  Audit System" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host "           Show current hardening status" -ForegroundColor $script:Colors.Muted
    Write-Host "    [2]  Quick Harden" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host "          Apply all recommended settings" -ForegroundColor $script:Colors.Muted
    Write-Host "    [3]  Custom Harden" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host "         Choose categories to apply" -ForegroundColor $script:Colors.Muted
    Write-Host "    [4]  Create Backup" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host "         Export registry before changes" -ForegroundColor $script:Colors.Muted
    Write-Host "    [5]  Restore Backup" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host "        Import a previous registry backup" -ForegroundColor $script:Colors.Muted
    Write-Host "    [Q]  Quit" -ForegroundColor $script:Colors.Title -NoNewline
    Write-Host "                 Exit the tool" -ForegroundColor $script:Colors.Muted
    return Read-MenuChoice "Select option:" @('1','2','3','4','5','Q')
}

# Audit: Phase 1 shows animated loading screen, Phase 2 shows detailed results
function Show-AuditMenu {
    # --- Phase 1: Animated loading screen ---
    Clear-Screen
    [Console]::CursorVisible = $false
    $script:SpinnerFrame = 0

    $keys          = @($script:CategoryMap.Keys)
    $catCount      = $keys.Count
    $completedCats = @()
    $auditResults  = [ordered]@{}

    # Human-readable detail text for each category during scan
    $scanDetails = @(
        'Checking registry policies...',
        'Querying service states...',
        'Inspecting scheduled tasks...',
        'Scanning network configuration...',
        'Evaluating firewall rules...',
        'Reading security settings...',
        'Querying Defender ASR rules...',
        'Enumerating installed packages...',
        'Checking AI/Copilot policies...',
        'Reviewing update configuration...',
        'Verifying miscellaneous settings...'
    )

    for ($i = 0; $i -lt $catCount; $i++) {
        $catKey = $keys[$i]
        $cat    = $script:CategoryMap[$catKey]
        $detail = if ($i -lt $scanDetails.Count) { $scanDetails[$i] } else { 'Scanning...' }

        # Animate a few spinner frames before the actual scan
        for ($f = 0; $f -lt 3; $f++) {
            Show-LoadingScreen -Phase "Scanning: $($cat.Label)" -Current $i -Total $catCount -Detail $detail -CompletedCategories $completedCats
            Start-Sleep -Milliseconds 80
        }

        # Run the audit with output suppressed (data only, no Write-Host)
        $script:SuppressOutput = $true
        try     { $r = & $cat.Fn -AuditOnly }
        finally { $script:SuppressOutput = $false }

        $ok  = @($r.Items | Where-Object { $_.Hardened }).Count
        $bad = @($r.Items | Where-Object { !$_.Hardened }).Count

        $auditResults[$catKey] = $r
        $completedCats += @{ Label = $cat.Label; Ok = $ok; Bad = $bad }

        Show-LoadingScreen -Phase "Done: $($cat.Label)" -Current ($i + 1) -Total $catCount -Detail 'Complete' -CompletedCategories $completedCats
        Start-Sleep -Milliseconds 120
    }

    Start-Sleep -Milliseconds 400
    [Console]::CursorVisible = $true

    # --- Phase 2: Detailed results view ---
    Clear-Screen
    Write-Banner
    Write-Host "  System Hardening Audit" -ForegroundColor $script:Colors.Title
    Write-Host "  ==========================================================" -ForegroundColor $script:Colors.Muted

    $totalOk = 0; $totalBad = 0

    foreach ($catKey in $keys) {
        $cat      = $script:CategoryMap[$catKey]
        $r        = $auditResults[$catKey]
        $ok       = @($r.Items | Where-Object { $_.Hardened }).Count
        $bad      = @($r.Items | Where-Object { !$_.Hardened }).Count
        $catTotal = $ok + $bad
        $catPct   = if ($catTotal -gt 0) { [math]::Round(($ok / $catTotal) * 100) } else { 0 }

        Write-SectionHeader "$($cat.Label)  [$ok/$catTotal - $catPct%]"

        foreach ($item in $r.Items) {
            $iColor = if ($item.Hardened) { $script:Colors.Success } else { $script:Colors.Error }
            $icon   = if ($item.Hardened) { "[OK]" } else { "[!!]" }
            Write-Host "    $icon " -ForegroundColor $iColor -NoNewline
            Write-Host $item.Name -ForegroundColor $script:Colors.Menu
        }
        $totalOk += $ok; $totalBad += $bad
    }

    # Overall score with progress bar and rating
    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor $script:Colors.Muted
    $total      = $totalOk + $totalBad
    $pct        = if ($total -gt 0) { [math]::Round(($totalOk / $total) * 100) } else { 0 }
    $scoreLen   = 40
    $scoreFill  = [math]::Floor($scoreLen * $totalOk / [math]::Max($total, 1))
    $scoreBar   = ('#' * $scoreFill) + ('-' * ($scoreLen - $scoreFill))
    $scoreColor = if ($pct -ge 80) { $script:Colors.Success } elseif ($pct -ge 50) { $script:Colors.Warning } else { $script:Colors.Error }

    Write-Host ""
    Write-Host "  Overall Score" -ForegroundColor $script:Colors.Title
    Write-Host "  [$scoreBar] " -ForegroundColor $scoreColor -NoNewline
    Write-Host "$totalOk/$total hardened ($pct%)" -ForegroundColor $scoreColor
    Write-Host ""

    if     ($pct -ge 90) { Write-Host "  Excellent! Your system is well hardened." -ForegroundColor $script:Colors.Success }
    elseif ($pct -ge 70) { Write-Host "  Good. A few items could still be tightened." -ForegroundColor $script:Colors.Warning }
    elseif ($pct -ge 40) { Write-Host "  Fair. Consider running Quick Harden to improve your score." -ForegroundColor $script:Colors.Warning }
    else                 { Write-Host "  Low. Your system has significant exposure. Run Quick Harden." -ForegroundColor $script:Colors.Error }
    Write-Host ""
    Write-Host "  Note: Items marked [audit-only] are not applied automatically" -ForegroundColor $script:Colors.Muted
    Write-Host "  because they require compatible hardware or may break apps." -ForegroundColor $script:Colors.Muted
    Write-Host "  See comments in the script for manual enable instructions." -ForegroundColor $script:Colors.Muted
    Write-Host ""

    Read-MenuChoice "Press any key to return..." @()
}

# Interactive category selector with toggle checkboxes
function Show-CategorySelector {
    $keys    = @($script:CategoryMap.Keys)
    $selected = @{}
    foreach ($k in $keys) { $selected[$k] = $true }

    # Key mapping: 1-9 for first 9 items, 0 for 10th, - for 11th, = for 12th
    $keyChars = @('1','2','3','4','5','6','7','8','9','0','-','=')

    while ($true) {
        Clear-Screen
        Write-Banner
        Write-Host "  Select Categories  " -ForegroundColor $script:Colors.Title -NoNewline
        Write-Host "(toggle with key, A=all, N=none, Enter=apply)" -ForegroundColor $script:Colors.Muted
        Write-Host "  ==========================================================" -ForegroundColor $script:Colors.Muted
        Write-Host ""

        for ($i = 0; $i -lt $keys.Count; $i++) {
            $k          = $keys[$i]
            $cat        = $script:CategoryMap[$k]
            $check      = if ($selected[$k]) { "X" } else { " " }
            $checkColor = if ($selected[$k]) { $script:Colors.Success } else { $script:Colors.Muted }
            $label      = if ($i -lt $keyChars.Count) { $keyChars[$i] } else { '?' }
            Write-Host "    [$label] " -ForegroundColor $script:Colors.Title -NoNewline
            Write-Host "[$check]" -ForegroundColor $checkColor -NoNewline
            Write-Host " $($cat.Label)" -ForegroundColor $script:Colors.Menu -NoNewline
            $pad = 30 - $cat.Label.Length; if ($pad -lt 1) { $pad = 1 }
            Write-Host (' ' * $pad) -NoNewline
            Write-Host $cat.Desc -ForegroundColor $script:Colors.Muted
        }

        Write-Host ""
        Write-Host "    [A] Select all  [N] Select none  [Enter] Apply  [Esc] Cancel" -ForegroundColor $script:Colors.Muted
        Write-Host ""
        Write-Host "  Toggle: " -ForegroundColor $script:Colors.Title -NoNewline

        $key  = [Console]::ReadKey($true)
        if ($key.Key -eq 'Enter')  { return ($keys | Where-Object { $selected[$_] }) }
        if ($key.Key -eq 'Escape') { return @() }

        $char = $key.KeyChar.ToString()
        if     ($char.ToUpper() -eq 'A') { foreach ($k in $keys) { $selected[$k] = $true } }
        elseif ($char.ToUpper() -eq 'N') { foreach ($k in $keys) { $selected[$k] = $false } }
        else {
            $idx = [array]::IndexOf($keyChars, $char)
            if ($idx -ge 0 -and $idx -lt $keys.Count) {
                $k = $keys[$idx]
                $selected[$k] = !$selected[$k]
            }
        }
    }
}

# Apply selected categories with progress bar and summary
function Apply-Categories {
    param([string[]]$SelectedKeys)
    if ($SelectedKeys.Count -eq 0) {
        Write-Host "`n  No categories selected." -ForegroundColor $script:Colors.Warning
        return
    }

    Write-Host ""
    New-RegistryBackup

    $totalApplied = 0; $totalSkipped = 0; $totalFailed = 0; $count = 0

    foreach ($catKey in $SelectedKeys) {
        $cat = $script:CategoryMap[$catKey]
        $count++
        Write-Progress2 $count $SelectedKeys.Count $cat.Label
        Write-Host ""
        Write-SectionHeader "Applying: $($cat.Label)"
        $r = & $cat.Fn
        $totalApplied += $r.Applied; $totalSkipped += $r.Skipped; $totalFailed += $r.Failed
        Write-Host "    Applied: $($r.Applied)  Skipped: $($r.Skipped)  Failed: $($r.Failed)" -ForegroundColor $script:Colors.Muted
    }

    Write-Host ""
    Write-Host "  ==========================================================" -ForegroundColor $script:Colors.Muted
    Write-Host "  Summary:" -ForegroundColor $script:Colors.Title
    Write-Host "    Applied: $totalApplied" -ForegroundColor $script:Colors.Success
    Write-Host "    Already set: $totalSkipped" -ForegroundColor $script:Colors.Muted
    if ($totalFailed -gt 0) { Write-Host "    Failed: $totalFailed (check log)" -ForegroundColor $script:Colors.Error }
    Write-Host "    Log: $script:LogFile" -ForegroundColor $script:Colors.Muted
    Write-Host ""
    Write-Host "  Restart your computer for all changes to take effect." -ForegroundColor $script:Colors.Warning
    Write-Host ""
}

# ============================================================================
# CLI MODE (non-interactive, for automation / scripting)
# ============================================================================

function Invoke-SilentMode {
    param([string[]]$SelectedCategories)
    if (!(Test-Path $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }

    Write-Host "Harden-Windows v$script:Version - Silent Mode" -ForegroundColor $script:Colors.Banner
    Write-Host "Categories: $($SelectedCategories -join ', ')" -ForegroundColor $script:Colors.Info
    New-RegistryBackup

    $totalApplied = 0; $totalFailed = 0
    foreach ($catKey in $SelectedCategories) {
        if ($script:CategoryMap.Contains($catKey)) {
            $cat = $script:CategoryMap[$catKey]
            Write-Host "  Applying $($cat.Label)..." -ForegroundColor $script:Colors.Info
            $r = & $cat.Fn
            $totalApplied += $r.Applied; $totalFailed += $r.Failed
        } else {
            Write-Host "  Unknown category: $catKey" -ForegroundColor $script:Colors.Error
        }
    }

    $doneColor = if ($totalFailed -eq 0) { $script:Colors.Success } else { $script:Colors.Warning }
    Write-Host "Done. Applied: $totalApplied, Failed: $totalFailed" -ForegroundColor $doneColor
    Write-Host "Log: $script:LogFile"
}

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

# Enforce administrator privileges
if (!(Test-Admin)) {
    Write-Host ""
    Write-Host "  This script requires Administrator privileges." -ForegroundColor Red
    Write-Host "  Right-click PowerShell -> Run as Administrator, then re-run." -ForegroundColor Yellow
    Write-Host ""
    exit 1
}

# Create backup/log directory
if (!(Test-Path $script:BackupDir)) { New-Item -ItemType Directory -Path $script:BackupDir -Force | Out-Null }

# CLI mode: apply and exit without TUI
if ($Silent) {
    $cats = if ($All) { @($script:CategoryMap.Keys) } else { $Categories }
    if ($cats.Count -eq 0) {
        Write-Host "Specify -All or -Categories when using -Silent" -ForegroundColor Red
        exit 1
    }
    Invoke-SilentMode -SelectedCategories $cats
    exit 0
}

# Interactive TUI loop
while ($true) {
    $choice = Show-MainMenu
    switch ($choice) {
        '1' { Show-AuditMenu }
        '2' {
            Clear-Screen; Write-Banner
            Write-Host "  Quick Harden - All Categories" -ForegroundColor $script:Colors.Title
            Write-Host ""
            Write-Host "  This will apply ALL hardening settings." -ForegroundColor $script:Colors.Warning
            Write-Host "  A registry backup will be created first." -ForegroundColor $script:Colors.Muted
            $confirm = Read-MenuChoice "  Proceed? (Y/N)" @('Y','N')
            if ($confirm -eq 'Y') {
                Apply-Categories -SelectedKeys @($script:CategoryMap.Keys)
                Read-MenuChoice "Press any key to return..." @()
            }
        }
        '3' {
            $selected = Show-CategorySelector
            if ($selected.Count -gt 0) {
                Clear-Screen; Write-Banner
                Apply-Categories -SelectedKeys $selected
                Read-MenuChoice "Press any key to return..." @()
            }
        }
        '4' { Clear-Screen; Write-Banner; New-RegistryBackup; Write-Host ""; Read-MenuChoice "Press any key to return..." @() }
        '5' { Clear-Screen; Write-Banner; Restore-RegistryBackup; Write-Host ""; Read-MenuChoice "Press any key to return..." @() }
        'Q' { Clear-Screen; Write-Host "`n  Goodbye.`n" -ForegroundColor $script:Colors.Banner; exit 0 }
    }
}
