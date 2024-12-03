<#
.SYNOPSIS
Main execution script for system language configuration.

.DESCRIPTION
This script manages the staged installation of language packs and configuration
of system and user language settings. It handles directory permissions,
scheduled tasks, and manages the entire process across multiple reboots.

.PARAMETER Culture
Array of culture codes to install, with the primary language first.
Example: @('de-CH', 'en-US')

.NOTES
Requires administrative privileges
Multiple reboots are required for complete setup
#>

# Initialize logging
$LogPath = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs"
$LogFile = "LanguageInstall_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:LogFilePath = Join-Path -Path $LogPath -ChildPath $LogFile

# Script configuration
$Culture = @('en-GB', 'en-US')  # Primary language first

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
   
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logLine = "[$timestamp] [$Level] $Message"
   
    if (-not (Test-Path -Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }
   
    Add-Content -Path $script:LogFilePath -Value $logLine
   
    switch ($Level) {
        'Info' { Write-Host $logLine }
        'Warning' { Write-Host $logLine -ForegroundColor Yellow }
        'Error' { Write-Host $logLine -ForegroundColor Red }
    }
}

function Test-AdminRights {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Test-FirstBootComplete {
    try {
        Write-Log "Checking if first boot after language pack installation has completed..."
        
        # Check for common first boot markers
        $setupInProgress = Get-ItemProperty -Path "HKLM:\SYSTEM\Setup" -Name "SetupInProgress" -ErrorAction SilentlyContinue
        $systemSetupInProgress = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Setup\State" -Name "ImageState" -ErrorAction SilentlyContinue
        
        if ($setupInProgress.SetupInProgress -eq 1) {
            Write-Log "Setup is still in progress" -Level Warning
            return $false
        }

        if ($systemSetupInProgress.ImageState -eq "IMAGE_STATE_UNDEPLOYABLE") {
            Write-Log "System is still in undeployable state" -Level Warning
            return $false
        }

        # Additional check for pending file rename operations
        $pendingFileRename = Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations"
        if ($pendingFileRename) {
            Write-Log "Pending file rename operations detected" -Level Warning
            return $false
        }

        Write-Log "Post-language pack installation boot appears to be complete"
        return $true
    }
    catch {
        Write-Log "Error checking boot status: $_" -Level Error
        return $false
    }
}
function Install-LanguageFeatures {
    param ([string]$LanguageTag)
   
    try {
        Write-Log "Installing language pack for $LanguageTag"
        $result = Install-Language -Language $LanguageTag -CopyToSettings
        Write-Log "Language installation status completed"
       
        # Verify installation
        $verifyStatus = Get-WindowsCapability -Online | Where-Object { $_.Name -like "*$LanguageTag*" }
        $verifyStatus | ForEach-Object {
            Write-Log "Feature: $($_.Name) - State: $($_.State)"
        }
    }
    catch {
        Write-Log "Failed to install language: $_" -Level Warning
    }
}
function Set-LanguageRegistry {
    param ([string[]]$Culture)
   
    $registryPath = "HKLM:\SOFTWARE\LanguageSetup"
   
    try {
        if (-not (Test-Path $registryPath)) {
            New-Item -Path $registryPath -Force | Out-Null
        }
       
        $cultureString = $Culture -join ','
        Set-ItemProperty -Path $registryPath -Name "InstalledCultures" -Value $cultureString -Type String
        Set-ItemProperty -Path $registryPath -Name "PrimaryLanguage" -Value $Culture[0] -Type String
        Set-ItemProperty -Path $registryPath -Name "InstallDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String
       
        Write-Log "Saved culture settings to registry: $cultureString"
        return $true
    }
    catch {
        Write-Log "Failed to save culture settings to registry: $_" -Level Error
        return $false
    }
}
function Register-UserLanguageSetup {
    param ([string[]]$Culture)
    
    Get-ScheduledTask -TaskName "UserLanguageSetup" -ErrorAction SilentlyContinue | Unregister-ScheduledTask -Confirm:$false
    
    $scriptDirectory = "C:\ProgramData\Microsoft\IntuneScripts"
    $scriptPath = Join-Path $scriptDirectory "UserLanguageSetup.ps1"
    
    # Force directory creation
    if (-not (Test-Path $scriptDirectory)) {
        New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
    }
    
    $scriptContent = @"
 `$ErrorActionPreference = 'Stop'
 Start-Transcript -Path "$LogPath\UserLanguageSetup_`$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
 
 try {
    `$registryPath = "HKLM:\SOFTWARE\LanguageSetup"
    `$cultures = (Get-ItemProperty -Path `$registryPath -Name "InstalledCultures").InstalledCultures -split ','
    `$primaryLanguage = (Get-ItemProperty -Path `$registryPath -Name "PrimaryLanguage").PrimaryLanguage
    
    Set-WinUILanguageOverride -Language `$primaryLanguage
    
    # Create proper language list starting with primary language from registry
    `$UserLanguageList = New-WinUserLanguageList -Language `$primaryLanguage
    `$UserLanguageList[0].Handwriting = `$true
    
    # Add remaining languages from registry
    foreach (`$lang in `$cultures) {
        if (`$lang -ne `$primaryLanguage) {
            `$UserLanguageList.Add(`$lang)
            `$UserLanguageList[-1].Handwriting = `$true
        }
    }
    
    Set-WinUserLanguageList -LanguageList `$UserLanguageList -Force
    
    # Create completion marker
    "Setup completed: `$(Get-Date)" | Out-File -FilePath "C:\ProgramData\Microsoft\Language\`${primaryLanguage}_complete.txt"
 } catch {
    Write-Error "`$_"
    exit 1
 } finally {
    Stop-Transcript
    Unregister-ScheduledTask -TaskName "UserLanguageSetup" -Confirm:`$false
 }
"@
 
    # Write script content
    Set-Content -Path $scriptPath -Value $scriptContent -Force
    Write-Log "Created script at: $scriptPath"
    
    # Create scheduled task for Domain Users
    $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
    $taskTrigger = New-ScheduledTaskTrigger -AtLogOn
    
    # Modified: Use Domain Users group
    $taskPrincipal = New-ScheduledTaskPrincipal -GroupId "Domain Users" -RunLevel Highest
    
    $taskSettings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    
    Register-ScheduledTask -TaskName "UserLanguageSetup" -Action $taskAction -Principal $taskPrincipal -Trigger $taskTrigger -Settings $taskSettings -Force
    Write-Log "User language setup task created"
}
  

function Register-SystemLanguageSetup {
    param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string[]]$Culture
    )
    # Verify administrative privileges
    if (-not (Test-AdminRights)) {
        Write-Log "Administrator privileges required" -Level Error
        exit 1
    }
    function Set-DirectoryPermissions {
        param(
            [string]$Path
        )
    
        Write-Log "Setting up permissions for directory: $Path"
    
        # Create directory if it doesn't exist
        if (-not (Test-Path $Path)) {
            New-Item -ItemType Directory -Path $Path -Force | Out-Null
        }
    
        # Get current ACL
        $acl = New-Object System.Security.AccessControl.DirectorySecurity
        $acl.SetAccessRuleProtection($true, $false)
    
        # Get SIDs
        $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
        $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
    
        # Add SYSTEM with full control
        $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $systemSid,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($systemRule)
    
        # Add Administrators with full control
        $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            $adminSid,
            "FullControl",
            "ContainerInherit,ObjectInherit",
            "None",
            "Allow"
        )
        $acl.AddAccessRule($adminRule)
    
        # Apply the ACL
        Set-Acl -Path $Path -AclObject $acl
        Write-Log "Permissions set successfully for: $Path"
    }

    # Setup directories and permissions first
    $scriptDirectory = "C:\ProgramData\Microsoft\IntuneScripts"
    $scriptPath = Join-Path $scriptDirectory "SystemLanguageSetup.ps1"

    # Setup directory permissions
    Set-DirectoryPermissions -Path $scriptDirectory
    Set-DirectoryPermissions -Path $LogPath
    Set-DirectoryPermissions -Path "C:\ProgramData\Microsoft\Language"

    # Check for and remove any existing setup scripts
    foreach ($path in @($scriptPath, "C:\Windows\Temp\Set-SystemLanguageSetup.ps1")) {
        if (Test-Path $path) {
            Write-Log "Found existing script at $path - removing..."
            try {
                Remove-Item -Path $path -Force -ErrorAction Stop
                Write-Log "Successfully removed existing script: $path"
            }
            catch {
                Write-Log "Warning: Could not remove existing script at $path : $_" -Level Warning
                # Continue anyway as we'll try to overwrite it
            }
        }
    }

    Write-Log "Creating system language setup script..."

    # Create the script content that will run as SYSTEM
    $scriptContent = @"
`$ErrorActionPreference = 'Stop'
`$LogPath = "$LogPath"

Start-Transcript -Path "`$LogPath\SystemLanguageSetup_Runtime_`$(Get-Date -Format 'yyyyMMdd_HHmmss').log"

try {
# Verify running as SYSTEM
`$currentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()
if (`$currentIdentity.User.Value -ne 'S-1-5-18') {
    throw "Script must run as SYSTEM. Current identity: `$(`$currentIdentity.Name)"
}

Write-Output "Running as SYSTEM, proceeding with language setup..."

# Read language settings from registry
`$registryPath = "HKLM:\SOFTWARE\LanguageSetup"
if (-not (Test-Path `$registryPath)) {
    throw "Registry path `$registryPath not found"
}

`$primaryLanguage = (Get-ItemProperty -Path `$registryPath -Name "PrimaryLanguage" -ErrorAction Stop).PrimaryLanguage

if ([string]::IsNullOrEmpty(`$primaryLanguage)) {
    throw "Primary language not found in registry"
}

Write-Output "Setting system preferred UI language to: `$primaryLanguage"
Set-SystemPreferredUILanguage -Language `$primaryLanguage
Restart-Computer -Force

# Create completion marker
`$markerPath = "C:\ProgramData\Microsoft\Language\`${primaryLanguage}_system_complete.txt"
"Setup completed: `$(Get-Date)" | Out-File -FilePath `$markerPath

Write-Output "Language setup completed successfully"
} catch {
Write-Error "Error during system language setup: `$_"
exit 1
} finally {
Stop-Transcript
# Remove the scheduled task only if successful
if (`$?) {
    Unregister-ScheduledTask -TaskName "SystemLanguageSetup" -Confirm:`$false
}
}
"@

    # Write script content
    Set-Content -Path $scriptPath -Value $scriptContent -Force
    Write-Log "Created script at: $scriptPath"

    # Remove existing task if present
    Get-ScheduledTask -TaskName "SystemLanguageSetup" -ErrorAction SilentlyContinue | 
    Unregister-ScheduledTask -Confirm:$false

    # Create scheduled task
    $taskAction = New-ScheduledTaskAction -Execute "PowerShell.exe" `
        -Argument "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""

    # Configure to run at next logon
    $taskTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 1)

    # Configure to run as SYSTEM
    $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    $taskSettings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30)

    Register-ScheduledTask -TaskName "SystemLanguageSetup" `
        -Action $taskAction `
        -Principal $taskPrincipal `
        -Trigger $taskTrigger `
        -Settings $taskSettings `
        -Force

    Write-Log "System language setup task created successfully"
    Write-Log "Task will run as SYSTEM at startup"

    # Optionally start the task immediately
    Write-Log "Starting the task now..."
    Start-ScheduledTask -TaskName "SystemLanguageSetup"

}
function Register-ScriptAutoStart {
    param(
        [string]$ScriptPath
    )
    
    Write-Log "Setting up script auto-start mechanism"
    
    # Create a scheduled task to run this script at startup
    $taskName = "LanguageSetupContinuation"
    
    # Remove existing task if present
    Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue | 
    Unregister-ScheduledTask -Confirm:$false
    
    # Create the PowerShell execution command with bypass policy
    $argument = "-ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -Command `"& {Start-Transcript -Path 'C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\ScriptAutoStart.log' -Append; & '$ScriptPath'; Stop-Transcript}`""
    
    $action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $argument
    
    $trigger = New-ScheduledTaskTrigger -AtStartup
    
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    $settings = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable

    Register-ScheduledTask -TaskName $taskName `
        -Action $action `
        -Principal $principal `
        -Trigger $trigger `
        -Settings $settings `
        -Force

    Write-Log "Auto-start task created successfully"
}
function Invoke-SafeRestart {
    param(
        [string]$Message = "Initiating system restart"
    )
    
    Write-Log $Message
    try {
        Start-Sleep -Seconds 10
        Restart-Computer -Force -ErrorAction Stop
    }
    catch {
        Write-Log "System restart already in progress - this is expected"
        return
    }
}
# Main execution
try {
    # Copy script to permanent location if not already there
    $scriptName = "Set-SystemLanguage.ps1"
    $permanentPath = Join-Path "C:\ProgramData\Microsoft\IntuneScripts" $scriptName

    Write-Log "Starting execution of $scriptName with $culture"
    
    # Check if we're already running from the permanent location
    if ($MyInvocation.MyCommand.Path -ne $permanentPath) {
        Write-Log "Setting up script in permanent location: $permanentPath"
        
        # Ensure the directory exists
        $permanentDir = Split-Path $permanentPath -Parent
        if (-not (Test-Path $permanentDir)) {
            New-Item -ItemType Directory -Path $permanentDir -Force | Out-Null
        }
        
        # Get the current script content
        if ($MyInvocation.MyCommand.Path) {
            $scriptContent = Get-Content -Path $MyInvocation.MyCommand.Path -Raw
        }
        else {
            # If running through Invoke-Command, use the current script block
            $scriptContent = $MyInvocation.MyCommand.ScriptBlock.ToString()
        }
        
        # Write the script to the permanent location
        $scriptContent | Set-Content -Path $permanentPath -Force
        
        # Register script to run at startup and start immediately
        Register-ScriptAutoStart -ScriptPath $permanentPath
        Start-Sleep -Seconds 15
        Start-ScheduledTask -TaskName "LanguageSetupContinuation"
        
        # Exit the current instance since the scheduled task is now running
        exit
    }

    # Verify administrative privileges
    Test-AdminRights

    Write-Log "Current setup stage: $(if ($stageValue) { $stageValue } else { 'Initial' })"
    
    #region STAGE DETECTION
    $stagePath = "HKLM:\SOFTWARE\LanguageSetup"
    $stageValue = $null
    
    if (Test-Path $stagePath) {
        $stageValue = (Get-ItemProperty -Path $stagePath -Name "SetupStage" -ErrorAction SilentlyContinue).SetupStage
    }
    #endregion STAGE DETECTION

    #region DIRECTORY SETUP AND PERMISSIONS
    try {
        # Define directories to process
        $dirPaths = @(
            "C:\ProgramData\Microsoft\IntuneScripts",
            "C:\ProgramData\Microsoft\Language",
            $LogPath
        )

        # Create and secure each directory
        foreach ($dir in $dirPaths) {
            try {
                # Create directory if it doesn't exist
                if (-not (Test-Path $dir)) {
                    Write-Log "Creating directory: $dir"
                    New-Item -ItemType Directory -Path $dir -Force | Out-Null
                }

                # Get current ACL
                $acl = Get-Acl -Path $dir

                # Clear existing permissions
                $acl.SetAccessRuleProtection($true, $false)

                # Convert security principal names to security identifiers (SIDs)
                $systemSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::LocalSystemSid, $null)
                $adminSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinAdministratorsSid, $null)
                $usersSid = New-Object System.Security.Principal.SecurityIdentifier([System.Security.Principal.WellKnownSidType]::BuiltinUsersSid, $null)

                Write-Log "Setting up basic permissions for $dir"

                # Add SYSTEM with full control
                $systemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $systemSid,
                    "FullControl",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Allow"
                )
                $acl.AddAccessRule($systemRule)

                # Add Administrators with full control
                $adminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $adminSid,
                    "FullControl",
                    "ContainerInherit,ObjectInherit",
                    "None",
                    "Allow"
                )
                $acl.AddAccessRule($adminRule)

                # Add Users with modify rights for Language directory and LogPath
                if ($dir -eq "C:\ProgramData\Microsoft\Language" -or $dir -eq $LogPath) {
                    $usersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                        $usersSid,
                        "Modify",
                        "ContainerInherit,ObjectInherit",
                        "None",
                        "Allow"
                    )
                    $acl.AddAccessRule($usersRule)
                }

                # Apply the new ACL
                Set-Acl -Path $dir -AclObject $acl
                Write-Log "Successfully set permissions for $dir"

                # Verify permissions were set
                $verifyAcl = Get-Acl -Path $dir
                Write-Log "Verified permissions for $dir. Access rules count: $($verifyAcl.Access.Count)"
            }
            catch {
                Write-Log "Error processing directory $dir : $_" -Level Error
                throw
            }
        }
    }
    catch {
        Write-Log "Critical error during directory setup: $_" -Level Error
        throw
    }
    #endregion DIRECTORY SETUP AND PERMISSIONS

    #region STAGED EXECUTION
    switch ($stageValue) {
        $null {
            Write-Log "Starting initial language installation for: $($Culture -join ', ')"
            
            # First install language packs
            foreach ($lang in $Culture) {
                Write-Log "Processing language: $lang"
                Install-LanguageFeatures -LanguageTag $lang
            }
            
            # Configure registry settings
            Set-LanguageRegistry -Culture $Culture
            
            # Set next stage before reboot
            Set-ItemProperty -Path $stagePath -Name "SetupStage" -Value "SystemLanguage" -Type String
            
            # Create the SystemLanguageSetup task but don't start it yet
            Write-Log "Creating system language setup task (will run after reboot)..."
            Register-SystemLanguageSetup -Culture $Culture
            
            Write-Log "Initial setup complete. System will reboot once to complete language pack installation."
            Invoke-SafeRestart -Message "Single reboot for language pack installation"
        }
        
        "SystemLanguage" {
            Write-Log "Verifying system state after language pack installation"
            
            $primaryLanguage = (Get-ItemProperty -Path $stagePath -Name "PrimaryLanguage").PrimaryLanguage
            $systemCompletePath = "C:\ProgramData\Microsoft\Language\${primaryLanguage}_system_complete.txt"
            
            if (-not (Test-Path $systemCompletePath)) {
                Write-Log "Starting previously created SystemLanguageSetup task"
                Start-ScheduledTask -TaskName "SystemLanguageSetup"
                
                # Wait for completion marker
                $maxAttempts = 12  # 2 minutes total
                $attempts = 0
                while (-not (Test-Path $systemCompletePath) -and $attempts -lt $maxAttempts) {
                    Write-Log "Waiting for system language setup to complete... Attempt $($attempts + 1)/$maxAttempts"
                    Start-Sleep -Seconds 10
                    $attempts++
                }
                
                if (-not (Test-Path $systemCompletePath)) {
                    Write-Log "System language setup did not complete in time" -Level Error
                    exit 1
                }
            }
            
            # Register user language setup task
            Write-Log "Registering user language setup task..."
            Register-UserLanguageSetup -Culture $Culture
            
            # Cleanup
            Write-Log "System language setup completed. Cleaning up..."
            Remove-ItemProperty -Path $stagePath -Name "SetupStage"
            Set-ItemProperty -Path $stagePath -Name "SetupComplete" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String
            
            # Remove the continuation task
            Unregister-ScheduledTask -TaskName "LanguageSetupContinuation" -Confirm:$false
            
            Write-Log "Setup completed. User language preferences will be configured at next user logon."
            # No additional restart needed
        }
        
        default {
            Write-Log "Unknown setup stage: $stageValue" -Level Error
            exit 1
        }
    }
}
catch {
    Write-Log "Critical error during installation: $_" -Level Error
    exit 1
}