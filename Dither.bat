<# :

@echo off
  >nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

  if '%errorlevel%' NEQ '0' (

      goto UACPrompt
)  else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    set params = %*:"=""
    echo UAC.ShellExecute "cmd.exe", "/c %~s0 %params%", "", "runas", 1 >> "%temp%\getadmin.vbs"

    "%temp%\getadmin.vbs"
    del "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    pushd "%CD%"
    CD /D "%~dp0"
@echo off



  @echo off
     powershell /nologo /noprofile /command ^
        "&{[ScriptBlock]::Create((cat """%~f0""") -join [Char[]]10).Invoke(@(&{$args}%*))}"
     pause /b 1
     cls
     cmd /k Dither.bat
     
     



#>
<#9>&2 2>nul (call :lockAndRestoreStdErr %* 8>>"%~f0") || (
  echo Only one instance allowed - "%~f0" is already running >&2
  pause
  
)
exit /b

:lockAndRestoreStdErr
call :main %* 2>&9
exit /b 0
:main
::enable save files location (persistant memory)#>
$esc = ([char]27)
$null = Register-EngineEvent -SourceIdentifier `
([System.Management.Automation.PsEngineEvent]::Exiting) -Action {Write-Host "$([char]27)[1;34mMade by $([char]27)[1;36mSL$([char]27)[0m" }
$addcounter = 0
$Host.UI.RawUI.WindowTitle = 'Dithering Options'
Write-Host "                                                                                                       
$esc[94;5m ____   ___  _____  _   _  _____  ____   ___  _   _   ____     ___   ____   _____  ___   ___   _   _  ____  
$esc[94;5m|  _ \ |_ _||_   _|| | | || ____||  _ \ |_ _|| \ | | / ___|   / _ \ |  _ \ |_   _||_ _| / _ \ | \ | |/ ___| 
$esc[94;5m| | | | | |   | |  | |_| ||  _|  | |_) | | | |  \| || |  _   | | | || |_) |  | |   | | | | | ||  \| |\___ \ 
$esc[36;5m| |_| | | |   | |  |  _  || |___ |  _ <  | | | |\  || |_| |  | |_| ||  __/   | |   | | | |_| || |\  | ___) |
$esc[4;37m|____/ |___|  |_|  |_| |_||_____||_| \_\|___||_| \_| \____|   \___/ |_|      |_|  |___| \___/ |_| \_||____/$esc[0m`n"
                                                                                                                      
$DisplayPath = "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY"
$defaultcheck = Test-Path -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\DISPLAY\Default*"
if ($defaultcheck -eq $true) {$GetDisplay = Get-Item -Path $DisplayPath\* -exclude Default* | ForEach-Object Name |Split-Path -Leaf}
else {Write-Host "Default is NOT PRESENT";$GetDisplay = Get-Item -Path $DisplayPath\* | ForEach-Object Name  |Split-Path -Leaf}
$GetDisplay = $GetDisplay.replace("}","")
$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase"
$TestPath = Test-Path -Path $Path
if($TestPath -eq $true){$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase";$KeyPath = "SYSTEM\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase";$GetFolder = Get-ChildItem -Recurse -Path $Path -Include $GetDisplay.ForEach({ $_ + '*'}) |Select-Object Name |Split-Path -Leaf
$GetFolder = $GetFolder.replace("}","");$result = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase\$GetFolder"} else{$Path = "HKLM:\SYSTEM\CurrentControlSet\Services\nvlddmkm\DisplayDatabase";$KeyPath = "SYSTEM\CurrentControlSet\Services\nvlddmkm\DisplayDatabase";$GetFolder = Get-ChildItem -Recurse -Path $Path -Include $GetDisplay.ForEach({ $_ + '*'}) |Select-Object Name |Split-Path -Leaf
$GetFolder = $GetFolder.replace("}","");$result = "Registry::HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\DisplayDatabase\$GetFolder"}
$user =  get-winevent -FilterHashtable @{Logname = 'system';ID =1501} -MaxEvent 1
$realid = $user.userid.Translate([system.security.principal.ntaccount])
$subkey = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey($KeyPath,[Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree,[System.Security.AccessControl.RegistryRights]::ChangePermissions)
$acl = $subkey.GetAccessControl()
$person = [System.Security.Principal.NTAccount]"$realid"
$access = [System.Security.AccessControl.RegistryRights]"FullControl"
$inheritance  = [System.Security.AccessControl.InheritanceFlags]"ContainerInherit,ObjectInherit"
$propagation = [System.Security.AccessControl.PropagationFlags]"None"
$type = [System.Security.AccessControl.AccessControlType]"Allow"
$rule = New-Object System.Security.AccessControl.RegistryAccessRule($person,$access,$inheritance,$propagation,$type)
$acl.SetAccessRule($rule)
$subkey.SetAccessControl($acl)
$urlcounter = 0
$counter = 0

function urlswitch {
switch ($readkey.Character){
  1{Start-Process "http://www.lagom.nl/lcd-test/black.php"`n | out-null;CloseAppOrReg($addcounter,$reginput.Character -eq ("4"))}
  2{Start-Process "https://tannerhelland.com/2012/12/28/dithering-eleven-algorithms-source-code.html" | out-null;CloseAppOrReg($addcounter,$reginput.Character -eq ("4"))}
  3{Start-Process "https://tftcentral.co.uk/features" | out-null;CloseAppOrReg($addcounter,$reginput.Character -eq ("4"))}
  4{$addcounter = 0;$urlcounter = 0;CloseAppOrReg($addcounter,$urlcounter )}
  default{if($urlcounter -lt 4){Write-Host "`n$esc[1;31mWRONG INPUT$esc`a[0m";$addcounter = 2;$urlcounter++;CloseAppOrReg($addcounter,$reginput.Character -eq ("4"),$urlcounter) }}
}
}
function jumpReg ($registryPath)
{
    New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Applets\Regedit" -Name "LastKey" -Value $registryPath -PropertyType String -Force
    regedit
}
function CloseAppOrReg{
if($addcounter -eq 0 ) {Write-Host "`n`n$esc[1;36m[1]-$esc[1;34mClose CMD $esc[1;36m[2]-$esc[1;34mRestart PC $esc[1;36m[3]-$esc[1;34mOpen Registry $esc[1;36m[4]-$esc[1;34mURLs$esc[0m`n"
Write-Host "$esc[1;1mChoose an action: $esc"
$reginput= $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") ;}
if($reginput.Character -eq ("C")-or $reginput.Character -eq ("1") -or $reginput.Character -eq ("c")){
   clear
   Write-Host "                     

$esc[1;34m  .___  ___.      ___       _______   _______    .______   ____    ____ $esc[1;36m     _______. __      
$esc[1;34m  |   \/   |     /   \     |       \ |   ____|   |   _  \  \   \  /   / $esc[1;36m    /       ||  |     
$esc[1;34m  |  \  /  |    /  ^  \    |  .--.  ||  |__      |  |_)  |  \   \/   /  $esc[1;36m   |   (----`|  |     
$esc[1;34m  |  |\/|  |   /  /_\  \   |  |  |  ||   __|     |   _  <    \_    _/   $esc[1;36m    \   \    |  |     
$esc[1;34m  |  |  |  |  /  _____  \  |  '--'  ||  |____    |  |_)  |     |  |     $esc[1;36m.----)   |   |  `----.
$esc[1;34m  |__|  |__| /__/     \__\ |_______/ |_______|   |______/      |__|     $esc[1;36m|_______/    |_______|
 $esc[0m                                                                                              
"
  Start-Sleep -Milliseconds 650
  Stop-Process -Name "CMD";
  exit
}
elseif($reginput.Character -eq ("R")-or $reginput.Character  -eq ("2")-or $reginput -eq 2 -or $reginput.Character -eq ("r")){

Restart-Computer
}
elseif($reginput.Character -eq ("O")-or $reginput.Character -eq ("3") -or $reginput.Character -eq ("o")){
  jumpReg ("HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\nvlddmkm\State\DisplayDatabase\$GetFolder") | Out-Null
  exit
}
elseif($reginput.Character -eq ("U")-or $reginput.Character -eq ("4") -or $reginput.Charactebr -eq ("u")){
 if(($addcounter -eq 0 -or 2)-and $urlcounter -lt 5 ){Write-Host "`n`n`n$esc[1;34mMaybe useful sites:`n`n$esc[0m$esc[1;1mPress the corresponding button: $esc`n       
$esc[1;36m[1]$esc[1;34mhttp://www.lagom.nl/lcd-test/black.php/#fineprint $esc`n
$esc[1;36m[2]$esc[1;34mhttps://tannerhelland.com/2012/12/28/dithering-eleven-algorithms-source-code.html$esc`n
$esc[1;36m[3]$esc[1;34mhttps://tftcentral.co.uk/features$esc[0m`n
$esc[1;36m[4]$esc[1;34mBack$esc[0m`n"
 $readkey = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyUp") ;$addcounter = 1;urlswitch($readkey.Character,$addcounter);}
   else{exit
}
}
else{
exit;
}
}
$delentry = "$esc[1;36m[4]-$esc[1;34mDelete Current Entry$esc[0m";
$restartpc = "$esc[1;36m[5]-$esc[1;34mRestart PC$esc[0m`n";
$resultpath = Test-Path -Path $result
$valuename = "DitherRegistryKey"
$NoneValue = 00
$TempValue6bit=[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x00,0x04,0xF2,0x00,0x00,0x00)
$hexStringT6 = ($TempValue6bit|ForEach-Object ToString X2) -join ''
$TempValue8bit=[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x01,0x04,0xF3,0x00,0x00,0x00)
$hexStringT8 = ($TempValue8bit|ForEach-Object ToString X2) -join ''
$TempValue10bit =[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x02,0x04,0xF4,0x00,0x00,0x00)
$hexStringT10 =($TempValue10bit|ForEach-Object ToString X2) -join ''
$StaticValue6bit=[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x00,0x03,0xF1,0x00,0x00,0x00)
$hexStringS6 =($StaticValue6bit|ForEach-Object ToString X2) -join ''
$StaticValue8bit=[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x01,0x03,0xF2,0x00,0x00,0x00)
$hexStringS8 =($StaticValue8bit|ForEach-Object ToString X2) -join ''
$StaticValue10bit =[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x02,0x03,0xF3,0x00,0x00,0x00)
$hexStringS10 =($StaticValue10bit|ForEach-Object ToString X2) -join ''
$DynamicValue6bit=[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x00,0x02,0xF0,0x00,0x00,0x00)
$hexStringD6 =($DynamicValue6bit|ForEach-Object ToString X2) -join ''
$DynamicValue8bit=[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x01,0x02,0xF1,0x00,0x00,0x00)
$hexStringD8 =($DynamicValue8bit|ForEach-Object ToString X2) -join ''
$DynamicValue10bit =[byte[]](0xDB,0x01,0x00,0x00,0x10,0x00,0x00,0x00,0x01,0x01,0x02,0x02,0xF2,0x00,0x00,0x00)
$hexStringD10 =($DynamicValue10bit|ForEach-Object ToString X2) -join ''
$Temporal6 = "TEMPORAL(6bit)"
$Temporal8 = "TEMPORAL(8bit)"
$Temporal10 = "TEMPORAL(10bit)"
$Static6 = "STATIC(6bit)"
$Static8 = "STATIC(8bit)"
$Static10 = "STATIC(10bit)"
$Dynamic6 = "DYNAMIC(6bit)"
$Dynamic8 = "DYNAMIC(8bit)"
$Dynamic10 = "DYNAMIC(10bit)"
$6checker = $true
$8checker = $true
$10checker = $true
$switcher = $true

function searchforexist {
    $entry=$entry+$mainbit
    switch($entry){
     T66{$entry = "T6"}
     T88{$entry = "T8"}
     T1010{$entry = "T10"}
     S66{$entry = "S6"}
     S88{$entry = "S8"}
     S1010{$entry = "S10"}
     D66{$entry = "D6"}
     D88{$entry = "D8"}
     D1010{$entry = "D10"}
 }   
   
    if ($resultpath) {
   
   $regentry= Get-ItemProperty -Path $result -Name $valuename -ErrorAction SilentlyContinue
    if($regentry){$regcheck = $true} else{$regcheck = $false}
     switch($entry){
      T6{$checkname = $Temporal6}
      T8{$checkname = $Temporal8}
      T10{$checkname = $Temporal10}
      S6{$checkname = $Static6}
      S8{$checkname = $Static8}
      S10{$checkname = $Static10}
      D6{$checkname = $Dynamic6}
      D8{$checkname = $Dynamic8}
      D10{$checkname = $Dynamic10}

}
   
   if (($regcheck -eq $true) -and $switcher -eq $true) {
    
    $currentValue = Get-ItemProperty -Path $result | Select-Object -ExpandProperty $valuename -ErrorAction SilentlyContinue
    $hexStringval = ($currentValue|ForEach-Object ToString X2) -join ''
    
        switch($hexStringval){
               $hexStringT6{if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36m$Temporal6$esc[0m"};if($counter -eq 0){Choose-Option};$check = $Temporal6 ;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
             $hexStringT8{if($counter -eq 0){Write-Host  "$esc[7;1mCurrent method is $esc[1;36m$Temporal8$esc[0m"};if($counter -eq 0){Choose-Option};$check = $Temporal8;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
               $hexStringT10{if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36m$Temporal10$esc[0m"};if($counter -eq 0){Choose-Option};$check = $Temporal10;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
              $hexStringS6{if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36m$Static6$esc[0m" } ;if($counter -eq 0){Choose-Option};$check = $Static6;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
               $hexStringS8{if($counter -eq 0){Write-Host  "$esc[7;1mCurrent method is $esc[1;36m$Static8$esc[0m" } ;if($counter -eq 0){Choose-Option};$check = $Static8;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
               $hexStringS10{if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36m$Static10$esc[0m" } ;if($counter -eq 0){Choose-Option};$check = $Static10;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
              $hexStringD6 {if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36m$Dynamic6$esc[0m" };if($counter -eq 0){Choose-Option};$check = $Dynamic6;Get-Entry($entrychecker= "PromtEntry",$check,$checkname);exit}
               $hexStringD8{if($counter -eq 0){Write-Host  "$esc[7;1mCurrent method is $esc[1;36m$Dynamic8$esc[0m" };if($counter -eq 0){Choose-Option};$check = $Dynamic8;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
               $DynamicValue10bit{if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36m$Dynamic10$esc[0m" };if($counter -eq 0){Choose-Option};$check = $Dynamic10;Get-Entry($entrychecker = "PromtEntry",$check,$checkname);exit}
               default {Write-Host "None"}
}
}               
    elseif(($regcheck -eq $false) -or ($regcheck -eq $true -and $switcher -eq $false)){
        
        switch($entry,$NoneValue) {
            00{if($counter -eq 0){Write-Host "$esc[7;1mCurrent method is $esc[1;36mNONE$esc[0m"}}
            T6{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $TempValue6bit;Write-Host "`n`n$esc[1;36m$Temporal6$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit           }
            T8{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $TempValue8bit ;Write-Host "`n`n$esc[1;36m$Temporal8$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit           }
            T10{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $TempValue10bit;Write-Host "`n`n$esc[1;36m$Temporal10$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit           }
            S6{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $StaticValue6bit ;Write-Host "`n`n$esc[1;36m$Static6$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit             }
            S8{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $StaticValue8bit ;Write-Host "`n`n$esc[1;36m$Static8$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit             }
            S10{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $StaticValue10bit ;Write-Host "`n`n$esc[1;36m$Static10$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit             }
            D6{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $DynamicValue6bit ;Write-Host "`n`n$esc[1;36m$Dynamic6$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit            }
            D8{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $DynamicValue8bit ;Write-Host "`n`n$esc[1;36m$Dynamic8$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit            }
            D10{$GetFolder.ForEach({Remove-ItemProperty  -Path Registry::HKEY_LOCAL_MACHINE\$KeyPath\$_ -Name $valuename});$GetFolder.ForEach({New-ItemProperty -Path $result -Name $valuename -PropertyType Binary -Value $DynamicValue10bit ;Write-Host "`n`n$esc[1;36m$Dynamic10$esc[0m$esc[1;21m"was successfully created"$esc[0m"});CloseAppOrReg;exit            }
            
}
}
     }          

else { Write-Host "Couldn't find folder"
}
}

function entrybit {
$displaybit=$entry
$entrychecker =$entry  
      switch($displaybit){

       {($displaybit -eq "T" -and  $hexStringval -eq $hexStringT6 )-or($displaybit -eq "S" -and $hexStringval -eq $hexStringS6 )-or($displaybit -eq "D" -and $hexStringval -eq $hexStringD6)}{$displaymessage = "$esc[1;36m[2]-$esc[1;34m8bit $esc[1;36m[3]-$esc[1;34m10bit$esc[0m`n";$6checker = $false}
       {($displaybit -eq "T" -and $hexStringval -eq $hexStringT8)-or($displaybit -eq "S" -and $hexStringval -eq $hexStringS8)-or($displaybit -eq "D" -and $hexStringval -eq $hexStringD8)}{$displaymessage = "$esc[1;36m[1]-$esc[1;34m6bit $esc[1;36m[3]-$esc[1;34m10bit$esc[0m`n";$8checker =  $false}
       {($displaybit -eq "T" -and $hexStringval -eq $hexStringT10)-or($displaybit -eq "S" -and $hexStringval -eq $hexStringS10)-or($displaybit -eq "D" -and $hexStringval-eq $hexStringD10)}{$displaymessage = "$esc[1;36m[1]-$esc[1;34m6bit $esc[1;36m[2]-$esc[1;34m8bit $esc[0m`n";$10checker = $false}
       default{$displaymessage = "$esc[1;36m[1]-$esc[1;34m6bit $esc[1;36m[2]-$esc[1;34m8bit $esc[1;36m[3]-$esc[1;34m10bit $esc[0m`n"}
}
     if($counter -le 5){ Write-Host $displaymessage
      $bit= Read-Host "$esc[1;1mChoose version$esc[0m"
      $bit=$bit.Trim()
      
       switch ($bit,$6checker,$8checker,$10checker){

          {($bit -eq 1 -or $bit -eq 6)-and ($6checker -eq $true)}{$mainbit = 6;searchforexist($entrychecker,$counter,$mainbit,$entry)     }
          {($bit -eq 2 -or $bit -eq 8)-and ($8checker -eq $true)}{$mainbit = 8;searchforexist($entrychecker,$counter,$mainbit,$entry)     }
          {($bit -eq 3 -or $bit -eq 10)-and ($10checker -eq $true)}{$mainbit = 10;searchforexist($entrychecker,$counter,$mainbit,$entry)            }
           default{Write-Host "$esc[1;31mWRONG INPUT`n`a$esc[0m";$counter++;entrybit($counter) }
         }
       else{exit}
}
else { exit}
}

      

function Get-Entry {
if ($counter -le 2){
  switch($entrychecker){    
     PromtEntry{$delete = Read-Host "`n`n$esc[1;31mENTRY ALREADY EXISTS-$esc[1;36m$check`n`n`n[1]-$esc[1;34mRewrite to $esc[1;36m$checkname$esc[0m $esc[1;36m[2]-$esc[1;34mDelete$esc[0m";$delete=$delete.Trim(); if($delete.StartsWith("d")-or $delete-eq 2-or $delete.StartsWith("D")) {$entrychecker ="Delete";Get-Entry($entrychecker)} elseif($delete.StartsWith("r")-or $delete-eq 1-or $delete.StartsWith("R")) {$entrychecker ="Write";Get-Entry($entrychecker)}}
     Delete{Write-Host "`n$esc[1;31mENTRY WAS DELETED`n $esc[0m";Remove-ItemProperty  -Path $result -Name DitherRegistryKey;CloseAppOrReg }
     Write{$switcher = $false;searchforexist($switcher,$entry)}
     default{Write-Host "`n$esc[1;31mWRONG INPUT`n`a$esc[0m";$counter++;Get-Entry($counter)}
     
     }
 }  
}
function Choose-Option { if ($counter -eq 5) {exit};Write-Host $name1;$options = Write-Host "$esc[1;36m[1]$esc[0m-$esc[1;34mTemporal $esc[1;36m[2]$esc[0m-$esc[1;34mStatic 2x2 $esc[1;36m[3]$esc[0m-$esc[1;34mDynamic 2x2$esc[0m`n"; 
if($regentry) {Write-Host $delentry $restartpc};
$title=  "Choose your method";$input = Read-Host "$esc[1;1m$title`a$esc[0m"`n;$input=$input.Trim();if ($input.StartsWith("T")-or$input.StartsWith("t")-or $input -eq 1) {$Tinput = $input};if ($input.StartsWith("S")-or$input.StartsWith("s")-or $input -eq 2) {$Sinput = $input};if ($input.StartsWith("D")-or$input.StartsWith("d")-or $input -eq 3) {$Dinput = $input};
  
  Switch ($input) {
      
     $Tinput{Write-Host "`n$esc[1;36mTEMPORAL`n$esc[0m";$entry = "T";$counter++;entrybit($entry,$counter)}
     $Sinput{Write-Host "`n$esc[1;36mSPATIAL STATIC 2X2`n$esc[0m";$entry = "S";$counter++;entrybit($entry,$counter)}
     $Dinput{Write-Host "`n$esc[1;36mSPATIAL DYNAMIC 2X2`n$esc[0m";$entry = "D";$counter++;entrybit($entry,$counter)}
     4{if($regentry){Get-Entry($entrychecker = "Delete")} else{Write-Host "$esc[1;31mWRONG INPUT`n$esc[0m";$counter++;Choose-Option($counter)}}
     5{if($regentry){$addcounter++;$reginput = 2;CloseAppOrReg($reginput,$addcounter)} else{Write-Host "`n$esc[1;31mWRONG INPUT`n$esc[0m";$counter++;;Choose-Option($counter)}}
     default{Write-Host "$esc[1;31mWRONG INPUT`n$esc[0m";$counter++;Choose-Option($counter) }
              
}
   
}
searchforexist
Choose-Option