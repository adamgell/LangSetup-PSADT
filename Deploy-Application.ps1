# Deploy-Application.ps1
<#
.SYNOPSIS
    Script for system language configuration using PSADT.
.DESCRIPTION
    Manages the staged installation of language packs and configuration
    of system and user language settings within the PSAppDeployToolkit framework.
#>

##*===============================================
##* DO NOT MODIFY SECTION BELOW
##*===============================================
[CmdletBinding()]
Param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('Install', 'Uninstall', 'Repair')]
    [String]$DeploymentType = 'Install',
    
    [Parameter(Mandatory = $false)]
    [ValidateSet('Interactive', 'Silent', 'NonInteractive')]
    [String]$DeployMode = 'Interactive',
    
    [Parameter(Mandatory = $false)]
    [switch]$AllowRebootPassThru = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$TerminalServerMode = $false,
    
    [Parameter(Mandatory = $false)]
    [switch]$DisableLogging = $false
)

Try {
    ## Set the script execution policy for this process
    Try { Set-ExecutionPolicy -ExecutionPolicy 'ByPass' -Scope 'Process' -Force -ErrorAction 'Stop' } Catch {}

    ##*===============================================
    ##* VARIABLE DECLARATION
    ##*===============================================
    ## Variables: Application
    [string]$appVendor = 'Celerion'
    [string]$appName = 'Language installation'
    [string]$appVersion = '1.0.0'
    [string]$appArch = ''
    [string]$appLang = ''
    [string]$appRevision = '01'
    [string]$appScriptVersion = '1.0.0'
    [string]$appScriptDate = Get-Date -Format 'yyyy-MM-dd'
    [string]$appScriptAuthor = 'Your Name'
    [string]$deployAppScriptFriendlyName = 'Celerion Language Configuration'

    ##* Do not modify section below
    #region DoNotModify
    ## Variables: Exit Code
    [int32]$mainExitCode = 0

    ## Variables: Script
    [string]$deployAppScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Definition

    ## Variables: Environment
    If (Test-Path -LiteralPath 'variable:HostInvocation') { $InvocationInfo = $HostInvocation } Else { $InvocationInfo = $MyInvocation }
    [string]$scriptDirectory = Split-Path -Path $InvocationInfo.MyCommand.Definition -Parent

    # Load AppDeployToolkit
    . "$scriptDirectory\AppDeployToolkit\AppDeployToolkitMain.ps1"
    #endregion DoNotModify
    ##* Do not modify section above

    ##*===============================================
    ##* END VARIABLES
    ##*===============================================

    ##*===============================================
    ##* LANGUAGE CONFIG VARIABLES
    ##*===============================================
    # Define language array after PSADT initialization to avoid conflicts
    New-Variable -Name 'LanguagesToInstall' -Value @('en-GB', 'en-US') -Force

    ##*===============================================
    ##* PRE-INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Pre-Installation'

    ## Show Welcome Message, close applications if required, verify there is enough disk space to complete the install, and persist the prompt
    Show-InstallationWelcome -CloseApps 'iexplore' -CheckDiskSpace -PersistPrompt -CustomText -AllowDefer

    ## Show Progress Message (with the default message)
    Show-InstallationProgress

    ##*===============================================
    ##* INSTALLATION
    ##*===============================================

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

    [string]$installPhase = 'Installation'

    $stagePath = "HKLM:\SOFTWARE\LanguageSetup"
    $stageValue = $null
    
    if (Test-Path $stagePath) {
        $stageValue = (Get-ItemProperty -Path $stagePath -Name "SetupStage" -ErrorAction SilentlyContinue).SetupStage
    }

    Switch ($stageValue) {
        $null {
            # Initial message
            Show-InstallationProgress -StatusMessage "Preparing to install language packs..."
            
            $totalLanguages = $LanguagesToInstall.Count
            $currentIndex = 0
            
            foreach ($lang in $LanguagesToInstall) {
                $currentIndex++
                Write-Log -Message "Processing language: $lang" -Source $deployAppScriptFriendlyName
                
                # Show status
                Show-InstallationProgress -StatusMessage "Installing language pack [$currentIndex of $totalLanguages]: $lang"
                
                # install language packs
                Write-Log "Processing language: $lang"
                Install-LanguageFeatures -LanguageTag $lang
    
                
                # Brief pause between languages
                if ($currentIndex -lt $totalLanguages) {
                    Show-InstallationProgress -StatusMessage "Preparing next language pack..."
                    Start-Sleep -Seconds 2
                }
            }
            
            Show-InstallationProgress -StatusMessage "Finalizing language pack installation..."
            
            # Set registry values
            if (-not (Test-Path $stagePath)) {
                New-Item -Path $stagePath -Force | Out-Null
            }
            
            $cultureString = $LanguagesToInstall -join ','
            Set-ItemProperty -Path $stagePath -Name "InstalledCultures" -Value $cultureString -Type String
            Set-ItemProperty -Path $stagePath -Name "PrimaryLanguage" -Value $LanguagesToInstall[0] -Type String
            Set-ItemProperty -Path $stagePath -Name "InstallDate" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String
            Set-ItemProperty -Path $stagePath -Name "SetupStage" -Value "SystemLanguage" -Type String
            
            Show-InstallationProgress -StatusMessage "Language pack installation complete. Preparing for restart..."

            #set up for secondary stage after reboot
            function Register-UserLanguageSetup {    

                function New-LanguageSetupShortcut {
                    $scriptDirectory = "C:\ProgramData\Microsoft\IntuneScripts"
                    $scriptPath = Join-Path $scriptDirectory "UserLanguageSetup.ps1"
                    $shortcutPath = "C:\Users\Public\Desktop\Set Keyboard Language.lnk"
                    $iconPath = "C:\Windows\System32\input.dll,1" # Default icon, we can change this
                    
                    # Create shortcut
                    $shell = New-Object -ComObject WScript.Shell
                    $shortcut = $shell.CreateShortcut($shortcutPath)
                    $shortcut.TargetPath = "powershell.exe"
                    $shortcut.Arguments = "-ExecutionPolicy Bypass -NoProfile -File `"$scriptPath`""
                    $shortcut.IconLocation = $iconPath
                    $shortcut.Description = "Configure keyboard and language settings"
                    $shortcut.WorkingDirectory = $scriptDirectory
                    $shortcut.Save()
                    
                    Write-Log "Created language setup shortcut at: $shortcutPath"
                }
   
                $scriptDirectory = "C:\ProgramData\Microsoft\IntuneScripts"
                $scriptPath = Join-Path $scriptDirectory "UserLanguageSetup.ps1"
    
                # Force directory creation
                if (-not (Test-Path $scriptDirectory)) {
                    New-Item -ItemType Directory -Path $scriptDirectory -Force | Out-Null
                }
    
                $scriptContent = @"
    `$ErrorActionPreference = 'Stop'
    `$LogPath = "C:\ProgramData\Microsoft\IntuneScripts"
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
    }
"@
             
                # Write script content
                Set-Content -Path $scriptPath -Value $scriptContent -Force
                Write-Output "Created script at: $scriptPath"
                
                # Create shortcut
                New-LanguageSetupShortcut

                # run once 
                New-LanguageSetupRunOnce

            }
            
            function Register-SystemLanguageSetup {
                
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
            
                $scriptDirectory = "C:\ProgramData\Microsoft\IntuneScripts"
                $scriptPath = Join-Path $scriptDirectory "SystemLanguageSetup.ps1"
            
                # Setup directory permissions [remains the same]
                Set-DirectoryPermissions -Path $scriptDirectory
                Set-DirectoryPermissions -Path "C:\ProgramData\Microsoft\Language"
            
                # [Previous cleanup code remains the same]
            
$scriptContent = @"
`$ErrorActionPreference = 'Stop'
`$LogPath = "$scriptDirectory"

# Check if task has already run
`$markerPath = "C:\ProgramData\Microsoft\Language\SystemSetup_Complete.txt"
if (Test-Path `$markerPath) {
Write-Output "System language setup has already been completed"
Unregister-ScheduledTask -TaskName "SystemLanguageSetup" -Confirm:`$false
exit 0
}

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

# Create completion markers
"Setup completed: `$(Get-Date)" | Out-File -FilePath `$markerPath
"Setup completed: `$(Get-Date)" | Out-File -FilePath "C:\ProgramData\Microsoft\Language\`${primaryLanguage}_system_complete.txt"

Write-Output "Language setup completed successfully"

# Remove the scheduled task
Unregister-ScheduledTask -TaskName "SystemLanguageSetup" -Confirm:`$false

# Force a restart
Restart-Computer -Force
} catch {
Write-Error "Error during system language setup: `$_"
exit 1
} finally {
Stop-Transcript
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
            
                # Configure to run once at startup
                $taskTrigger = New-ScheduledTaskTrigger -AtStartup -RandomDelay (New-TimeSpan -Minutes 1)
                # Add expiration
                $taskTrigger.EndBoundary = (Get-Date).AddDays(1).ToString('s') # Task expires after 1 day
            
                # Configure to run as SYSTEM
                $taskPrincipal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
            
                $taskSettings = New-ScheduledTaskSettingsSet `
                    -AllowStartIfOnBatteries `
                    -DontStopIfGoingOnBatteries `
                    -StartWhenAvailable `
                    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
                    -DeleteExpiredTaskAfter (New-TimeSpan -Minutes 1)
            
                Register-ScheduledTask -TaskName "SystemLanguageSetup" `
                    -Action $taskAction `
                    -Principal $taskPrincipal `
                    -Trigger $taskTrigger `
                    -Settings $taskSettings `
                    -Force
            
                Write-Log "System language setup task created successfully"
                Write-Log "Task will run once at next system startup"
            }
            
            Register-SystemLanguageSetup
            Register-UserLanguageSetup
            
            # Prompt for restart
            $buttonClicked = Show-InstallationPrompt -Message "The system will restart to complete language pack installation." `
                -ButtonRightText "Restart" -ButtonLeftText "Later" -Icon Information
            
            if ($buttonClicked -eq "Restart") {
                Write-Log -Message "User initiated restart." -Source $deployAppScriptFriendlyName
                # set exit code to 1641 to indicate a restart is required
                Restart-Computer -Force
                Exit-script -ExitCode 1641
            }
            else {
                Write-Log -Message "User deferred restart." -Source $deployAppScriptFriendlyName
            }
        }
        
        "SystemLanguage" {
            Show-InstallationProgress -StatusMessage "Configuring system language..."
            
            $primaryLanguage = (Get-ItemProperty -Path $stagePath -Name "PrimaryLanguage").PrimaryLanguage
            
            # Set system language
            Execute-Process -Path "PowerShell.exe" -Parameters "-Command Set-SystemPreferredUILanguage -Language $primaryLanguage" -WindowStyle Hidden
            
            Remove-ItemProperty -Path $stagePath -Name "SetupStage"
            Set-ItemProperty -Path $stagePath -Name "SetupComplete" -Value (Get-Date -Format "yyyy-MM-dd HH:mm:ss") -Type String
            
            Write-Log -Message "Language configuration completed successfully." -Source $deployAppScriptFriendlyName
            Show-InstallationPrompt -Message "Language configuration has been completed." -ButtonRightText "OK"
        }
        
        default {
            Write-Log -Message "Unknown setup stage: $stageValue" -Source $deployAppScriptFriendlyName -Severity 3
            Exit-Script -ExitCode 1
        }
    }

    ##*===============================================
    ##* POST-INSTALLATION
    ##*===============================================
    [string]$installPhase = 'Post-Installation'

    Write-Log -Message "Installation completed successfully." -Source $deployAppScriptFriendlyName

    ## Display a message at the end of the install
    If (-not $useDefaultMsi) {
        Show-InstallationPrompt -Message "Installation completed successfully." -ButtonRightText 'OK' -Icon Information -NoWait
    }
}
Catch {
    [string]$mainErrorMessage = "There was an error during installation: $($_.Exception.Message)"
    Write-Log -Message $mainErrorMessage -Severity 3 -Source $deployAppScriptFriendlyName
    Show-InstallationPrompt -Message $mainErrorMessage -ButtonRightText 'OK' -Icon Error
    Exit-Script -ExitCode 1
}