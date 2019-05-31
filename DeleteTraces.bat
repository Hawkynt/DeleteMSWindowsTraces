@echo off
call :main
goto :eof

:main
setlocal enabledelayedexpansion
  
  call :EncryptPagingFile
  call :BlockMicrosoftLogon
  call :DisableSearchIndex
  call :DisableCortanaSearchIndex
  call :RemoveEdge
  call :TweakDefenderSettings
  call :TurnOffErrorReporting
  call :DisableWindowTips
  call :RemoveContactSupport
  call :RemoveMaps
  call :RemoveHelloFace
  call :TurnOffUnneededScheduledTasks
    
  for /D %%a in ("%systemdrive%\Users\*") do (
    set userappdata=%%~dpna\AppData\Roaming
    call :DeleteFolder "%%~na's Temp Folder" "%%~dpna\AppData\Local\Temp" true
    call :DeleteFolder "%%~na's SVN Cache" "%%~dpna\AppData\Local\TSVNCache" true
    call :DeleteFolder "%%~na's Crash Dumps" "%%~dpna\AppData\Local\CrashDumps" true
    call :DeleteFolder "%%~na's Recent Files" "!userappdata!\Microsoft\Windows\Recent"
    call :DeleteFolder "%%~na's Jumplists" "!userappdata!\Microsoft\Windows\Recent\AutomaticDestinations"
    call :DeleteFolder "%%~na's Office Recent Files" "!userappdata!\Microsoft\Office\Recent"
  )
  
  call :DeleteFolder "Current Temp Folder" "%Temp%" true
  call :DeleteFolder "System Temp Folder" "%SystemRoot%\Temp" true
  call :DeleteFolder "Root Temp Folder" "C:\Temp" true
  call :DeleteMRU "Cleaning current user's typed adresses/MRUs"
  call :DeleteFile "Prefetch folder" "%SystemRoot%\Prefetch\*.pf"
  call :DeleteFile "Rainmeter log" "D:\_COPYAPPS\Rainmeter\Rainmeter.log"

  call :CleanRecycleBins
  call :RemoveUnnededPackages
  call :CleanEventLogs
  
  taskkill /im:explorer.exe /f >NUL 2>&1
  for /D %%a in ("%systemdrive%\Users\*") do (
    set userappdata=%%~dpna\AppData\Roaming
    call :DeleteFile "%%~na's Icon Cache" "%%~dpna\AppData\Local\IconCache.db"
    call :DeleteFile "%%~na's Icon Cache" "%%~dpna\AppData\Local\Microsoft\Windows\Explorer\*Cache*.d*"
  )
  start explorer.exe
    
  rem call :RunCCleaner
  title Eingabeaufforderung

  endlocal
goto :eof

:DisplayTitle
  title %~1
  echo %~1
goto :eof

:TurnOffUnneededScheduledTasks
  call :DisplayTitle "Turning off unneeded Scheduled Tasks"
  schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Uploader" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyUpload" /disable >NUL 2>&1
  schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitor" /disable >NUL 2>&1
  schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyMonitorToastTask" /disable >NUL 2>&1
  schtasks /Change /TN "\Microsoft\Windows\Shell\FamilySafetyRefreshTask" /disable >NUL 2>&1
  schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /disable >NUL 2>&1
goto :eof

:DisableWindowTips
  call :DisplayTitle "Turning off Windows Tips"
  reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableSoftLanding /t REG_DWORD /d 1 /f >NUL 2>&1
  reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsSpotlightFeatures /t REG_DWORD /d 1 /f >NUL 2>&1
  reg add "HKLM\Software\Policies\Microsoft\Windows\CloudContent" /v DisableWindowsConsumerFeatures /t REG_DWORD /d 1 /f >NUL 2>&1
  reg add "HKLM\Software\Policies\Microsoft\Windows\DataCollection" /v DoNotShowFeedbackNotifications /t REG_DWORD /d 1 /f >NUL 2>&1
  reg add "HKLM\Software\Policies\Microsoft\WindowsInkWorkspace" /v AllowSuggestedAppsInWindowsInkWorkspace /t REG_DWORD /d 0 /f >NUL 2>&1
goto :eof

:TurnOffErrorReporting
  call :DisplayTitle "Turning off Error Reporting"
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >NUL 2>&1
  reg add "HKLM\SOFTWARE\Microsoft\Windows\Windows Error Reporting" /v Disabled /t REG_DWORD /d 1 /f >NUL 2>&1
goto :eof

:CleanRecycleBins
  for %%a in (A B C D E F G H I J K L M N O P Q R S T U V W X Y Z) do (
    call :DeleteFolder "Clearing Recycle Bin of Drive %%a:" "%%a:\$RECYCLE.BIN" true
  )
goto :eof

:RemoveUnnededPackages
  call :RemoveMicrosoftComponent "Windows-RetailDemo" "Demo Program"
  call :RemoveMicrosoftComponent "Windows-TroubleShooting" "Send TroubleShooting Info"
  call :RemoveMicrosoftComponent "OneCore-TroubleShooting" "Send TroubleShooting Info"
  call :RemoveMicrosoftComponent "Windows-BioEnrollment" "BioMetrics"
  call :RemoveMicrosoftComponent "OneCore-Biometrics" "BioMetrics"
  call :RemoveMicrosoftComponent "Windows-Geolocation" "GeoLocation"
  
  call :DisplayTitle "Removing StickyNote"
  call :RunPowerShellCommand "Get-AppxPackage -AllUsers *sticky* | Remove-AppxPackage"
    
  call :DisplayTitle "Removing Bing Stuff (News, Weather)"
  call :RunPowerShellCommand "Get-AppxPackage -AllUsers *bing* | Remove-AppxPackage"

  call :DisplayTitle "Removing QuickAssist"
  call :RunPowerShellCommand "Get-WindowsPackage -Online | Where PackageName -like *QuickAssist* | Remove-WindowsPackage -Online -NoRestart"
goto :eof

:RemoveHelloFace
  call :DisplayTitle "Removing Hello Face"
  call :RunPowerShellCommand "Get-WindowsPackage -Online | Where PackageName -like *Hello-Face* | Remove-WindowsPackage -Online -NoRestart"
  schtasks /Change /TN "\Microsoft\Windows\HelloFace\FODCleanupTask" /Disable >NUL 2>&1
goto :eof

:RemoveContactSupport
  call :RemoveMicrosoftComponent "Windows-ContactSupport" "Call For Support"
  call :RunPowerShellCommand "Get-AppxPackage -AllUsers *GetHelp* | Remove-AppxPackage"
goto :eof

:RemoveSkype
  call :DisplayTitle "Removing Skype"
  call :RunPowerShellCommand "Get-AppxPackage -AllUsers *Skype* | Remove-AppxPackage"
goto :eof

:RemoveEdge
  call :RemoveMicrosoftComponent "Windows-Internet" "Edge"
  call :RunPowerShellCommand "Get-WindowsPackage -Online | Where PackageName -like *InternetExplorer* | Remove-WindowsPackage -Online -NoRestart"
  
  for /D %%a in ("%windir%\SystemApps\Microsoft.MicrosoftEdge*") do (
    call :RenameExecutable "%%~dpnxa\MicrosoftEdge.exe"
    call :RenameExecutable "%%~dpnxa\MicrosoftEdgeCP.exe"
  )
  
goto :eof

:RemoveMaps
  call :DisplayTitle "Removing Microsoft Maps"
  call :RunPowerShellCommand "Get-AppxPackage -AllUsers *maps* | Remove-AppxPackage"
  sc delete MapsBroker >NUL 2>&1
  sc delete lfsvc >NUL 2>&1
  schtasks /Change /TN "\Microsoft\Windows\Maps\MapsUpdateTask" /disable >NUL 2>&1
  schtasks /Change /TN "\Microsoft\Windows\Maps\MapsToastTask" /disable >NUL 2>&1
goto :eof

:TweakDefenderSettings
  call :DisplayTitle "Tweaking Defender Settings"
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpyNetReporting /t REG_DWORD /d 0 /f >NUL 2>&1
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f >NUL 2>&1
  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v DontReportInfectionInformation /t REG_DWORD /d 1 /f >NUL 2>&1
  reg add "HKLM\SOFTWARE\Policies\Microsoft\MRT" /v "DontReportInfectionInformation" /t REG_DWORD /d 1 /f >NUL 2>&1
goto :eof

:DisableSearchIndex
  call :DisplayTitle "Disabling Search Index"
  call :RemoveMicrosoftComponent "Windows-Search2" "Online Search"
  call :RemoveMicrosoftComponent "Windows-SearchEngine" "Online Search"

  sc stop "WSearch" >NUL 2>&1
  sc config "WSearch" start=disabled >NUL 2>&1
goto :eof

:DisableCortanaSearchIndex
  call :DisplayTitle "Disabling Cortana"
  call :RemoveMicrosoftComponent "Windows-Cortana" "Cortana Assistant"

  for /D %%a in ("%windir%\SystemApps\Microsoft.Windows.Cortana*") do (
    call :RenameExecutable "%%~dpnxa\SearchUI.exe"
  )

  reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Windows Search" /v AllowCortana /t REG_DWORD /d 0 /f >NUL 2>&1
  reg add "HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\FirewallRules"  /v "{2765E0F4-2918-4A46-B9C9-43CDD8FCBA2B}" /t REG_SZ /d  "BlockCortana|Action=Block|Active=TRUE|Dir=Out|App=C:\windows\systemapps\microsoft.windows.cortana_cw5n1h2txyewy\searchui.exe|Name=Search  and Cortana  application|AppPkgId=S-1-15-2-1861897761-1695161497-2927542615-642690995-327840285-2659745135-2630312742|" /f >NUL 2>&1
  
goto :eof

:RunCCleaner
  "D:\_COPYAPPS\CCleaner\CCleaner.exe" /AUTO
goto :eof

:CleanEventLogs
  call :DisplayTitle "Cleaning Event Logs"
  for /F "tokens=*" %%a in ('wevtutil.exe el') do wevtutil.exe cl "%%a" >NUL 2>&1
goto :eof

:EncryptPagingFile
  call :DisplayTitle "Encrypting Paging File (needs restart if changed)"
  fsutil behavior set EncryptPagingFile 1 >NUL 2>&1
goto :eof

:DeleteFolder
setlocal
  set display=%~1
  set folder=%~2
  set recursive=%~3
  if exist "%folder%" (
    call :DisplayTitle "%display%"
    if "%recursive%"=="true" (
      rd /s /q "%folder%" >NUL 2>&1
      if not exist "%folder%" md "%folder%" >NUL 2>&1
    ) else (
      attrib "%folder%\*.*" -r -s -h >NUL 2>&1
      del /q "%folder%\*.*" >NUL 2>&1
    )
  )
endlocal
goto :eof

:DeleteFile
setlocal
  set display=%~1
  set file=%~2
  if exist "%file%" (
    call :DisplayTitle "%display%"
    attrib "%file%" -r -s -h >NUL 2>&1
    del /f /q "%file%" >NUL 2>&1
  )
endlocal
goto :eof

:BlockMicrosoftLogon
  call :DisplayTitle "Blocking Microsoft Logons"
  reg add "HKLM\Software\Policies\Microsoft\Windows\CurrentVersion\Policies\System" /v NoConnectedUser /t REG_DWORD /d 3 /f >NUL 2>&1
  reg add "HKLM\Software\Microsoft\PolicyManager\default\Settings\AllowYourAccount" /v value /t REG_DWORD /d 0 /f >NUL 2>&1
  reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSync /t REG_DWORD /d 2 /f >NUL 2>&1
  reg add "HKLM\Software\Policies\Microsoft\Windows\SettingSync" /v DisableSettingSyncUserOverride /t REG_DWORD /d 1 /f >NUL 2>&1
  del /F /Q "%SystemRoot%\System32\Tasks\Microsoft\Windows\SettingSync\*" >NUL 2>&1
goto :eof

:DeleteMRU
setlocal
  set display=%~1
  set fileName=%temp%\%random%.reg
  call :DisplayTitle "%display%"
  echo Windows Registry Editor Version 5.00>"%fileName%"
  echo.>>"%fileName%"
  
  rem explorer address bars
  call :AddEmptyKeyCommandToRegFile "%fileName%" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths"
  
  rem Run window
  call :AddEmptyKeyCommandToRegFile "%fileName%" "HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU"

  rem Visual Studio
  for /l %%i in (10,1,14) do (
    call :AddEmptyKeyCommandToRegFile "%fileName%" "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\%%i.0\ProjectMRUList"
    call :AddEmptyKeyCommandToRegFile "%fileName%" "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\%%i.0\FileMRUList"
    call :AddEmptyKeyCommandToRegFile "%fileName%" "HKEY_CURRENT_USER\Software\Microsoft\VisualStudio\%%i.0\MRUItems"
  )
  
  reg import  "%fileName%" >NUL 2>&1
  del /Q "%fileName%" >NUL 2>&1
endlocal
goto :eof

:AddEmptyKeyCommandToRegFile
setlocal
  set file=%~1
  set key=%~2
  echo [-%key%]>>"%file%"
  echo.>>"%file%"
  echo [%key%]>>"%file%"
  echo.>>"%file%"
endlocal
goto :eof

:AddSetValueCommandToRegFile
setlocal
  set file=%~1
  set key=%~2
  set valueName=%~3
  set value=%~4
  echo [%key%]>>"%file%"
  echo "%valueName%"=%value%>>"%file%"
  echo.>>"%file%"
endlocal
goto :eof

:RemoveMicrosoftComponent
setlocal
  set component=%~1
  set display=%~2
  call :DisplayTitle "Removing Package '%display%'"
  "%~dp0.\install_wim_tweak.exe" /o /c "Microsoft-%component%" /r >NUL 2>&1
endlocal
goto :eof

:RunPowerShellCommand
setlocal
  powershell -Command "& {%~1}" >NUL 2>&1
endlocal
goto :eof

:RenameExecutable
setlocal
  set file=%~dpnx1
  set directory=%~dp1
  set filename=%~nx1
  
  pushd "%directory%." >NUL 2>&1
    takeown /f "%fileName%" >NUL 2>&1
    icacls "%fileName%" /grant administrators:f >NUL 2>&1
    icacls "%fileName%" /grant administratoren:f >NUL 2>&1
    taskkill /im:"%fileName%" /f >NUL 2>&1
    rename "%fileName%" "%fileName%.bak" >NUL 2>&1
  popd
  
endlocal
goto :eof
