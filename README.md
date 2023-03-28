# Easy Wins Endpoint Defense
<img src="https://cdn.mathpix.com/cropped/2023_02_08_51d459042dcd7c2c577bg-01.jpg?height=999&amp;width=1974&amp;top_left_y=35&amp;top_left_x=419" alt="" width="889" height="450">

### Collection of scripts/resources/ideas for attack surface reduction and additional logging to enable better threat hunting on Windows endpoints.

# Changing Default File Associations

Changing default file associations is an easy win to prevent users from accidentally getting compromised. Obviously this is not bullet proof, but we're looking for quick, effective, least breakage here. See the script block below. This sets hta/wsh/wsf/js/jse/vbe files to open in notepad instead of executing :)

```powershell
ftype htafile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wshfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype wsffile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsfile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype jsefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
ftype vbefile="%SystemRoot%\system32\NOTEPAD.EXE" "%1"
```

For extra credit you can also disable ability for automatic mounting of ISO/VHD/VHDX/IMG files in file explorer. This will prevent users from doubleclick mounting these files which is are used often by threat actors for evasion. **Thanks to @Harlan Carvey for the correction on the VHD portion.

```powershell
reg add "HKEY_CLASSES_ROOT\Windows.IsoFile\shell\mount" /v "ProgrammaticAccessOnly" /t REG_SZ /d no /f
reg add "HKEY_CLASSES_ROOT\Windows.VhdFile\shell\mount" /v "ProgrammaticAccessOnly" /t REG_SZ /d no /f
```

# Adblocking Everywhere

Adblocking is becoming AS important as AV/EDR due to malicious Google ads. This can be achieved in a number of ways.

## Adblocking in the Browser

Adblocking in the web browser should be your first step as browser based adblockers have the ability to block/alter javascript in realtime thus providing better coverage. GPO deployment is relatively well documented so we'll focus on deployment via RMM/Powershell type solutions. 

For **Google Chrome**, simply run the below script and all users on the system:

```powershell
#install ublock origin in chrome for all users// meant for workgroup environments#
$regLocation = 'Software\Policies\Google\Chrome\ExtensionInstallForcelist'
$regKey = '1'
# 'cjpalhdlnbpafiamejdnhcphjbkeiagm' is the Extension ID for ublock origin#
$regData = 'cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx'
New-Item -Path "HKLM:\$regLocation" -Force
New-ItemProperty -Path "HKLM:\$regLocation" -Name $regKey -Value $regData -PropertyType STRING -Force
```

For Microsoft Edge, its essentially the same script but with different registry locations:

```powershell
#installs ublock origin in MS Edge for all users#
$regLocation = 'SOFTWARE\Policies\Microsoft\Edge\ExtensionInstallForcelist'
$regKey = '1'
# 'cjpalhdlnbpafiamejdnhcphjbkeiagm' is the Extension ID for ublock origin, easiest way to get this is from the URL of the extension
$regData = 'cjpalhdlnbpafiamejdnhcphjbkeiagm;https://clients2.google.com/service/update2/crx'
New-Item -Path "HKLM:\$regLocation" -Force
New-ItemProperty -Path "HKLM:\$regLocation" -Name $regKey -Value $regData -PropertyType STRING -Force
```

## Adblocking Network-Wide

I would use this in conjunction with adblock deployment on browsers as it would cover IOT/guest/unmanaged devices. You can do this by configuring your router's DHCP to assign adblocking DNS servers to all devices on your network. If you are running a Windows AD environment you should do this via DNS forwards as if your domain PCs don't get DNS from your Domain Controllers, you're going to have a bad time. See the projects below and pick the one that best suites your needs.

- https://pi-hole.net/
    
- https://adguard-dns.io/en/public-dns.html
    
- https://alternate-dns.com/
    

# Blocking LOLBINS with Windows Firewall

The script block below turns on Windows Firewall and associated logging. It will also enable Windows Defender's "Network Protection" feature. This will also allow you to build alerting/detections if the various LOLBINS attempt to reach the internet.

```powershell
NetSh Advfirewall set allprofiles state on
netsh advfirewall set currentprofile logging filename %systemroot%\system32\LogFiles\Firewall\pfirewall.log
netsh advfirewall set currentprofile logging maxfilesize 4096
netsh advfirewall set currentprofile logging droppedconnections enable
powershell.exe Set-MpPreference -EnableNetworkProtection Enabled
Netsh.exe advfirewall firewall add rule name="Block Notepad.exe netconns" program="%systemroot%\system32\notepad.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block regsvr32.exe netconns" program="%systemroot%\system32\regsvr32.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block calc.exe netconns" program="%systemroot%\system32\calc.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block mshta.exe netconns" program="%systemroot%\system32\mshta.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block wscript.exe netconns" program="%systemroot%\system32\wscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block cscript.exe netconns" program="%systemroot%\system32\cscript.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block runscripthelper.exe netconns" program="%systemroot%\system32\runscripthelper.exe" protocol=tcp dir=out enable=yes action=block profile=any
Netsh.exe advfirewall firewall add rule name="Block hh.exe netconns" program="%systemroot%\system32\hh.exe" protocol=tcp dir=out enable=yes action=block profile=any
```

# Earlier Detection/Prevention

## Canary Tokens 🐥

Canary Tokens are FREE from Thinkst and can be found at the URL below. You can generate various canaries depending on your use case.

https://canarytokens.org/generate

Put them EVERYWHERE you'd want to know an attacker has been. Some ideas to start:

- Root of sensitive shares
    
- Documents folder for all users (mark hidden for less false positives)
    
- Privileged folders or locations on servers
    
- Password Manager 
    

## FSRM (File Server Resource Manager)

FSRM (for windows servers only) - allows you to create "file screens" to allow or deny various types of content from being inside a network share. It will block files that are not permitted even if you are running as administrator or SYSTEM.

There are two ways to approach using FSRM for this purpose:

- Blocking known ransomware file extensions while allowing all other file types. https://github.com/nexxai/CryptoBlocker 
    
- Blocking ALL file extensions except for ones you specify. Ideal if you know with 100% what file ext should exist in a given share or location  https://github.com/biffalo/handy-posh/blob/main/fsrm-backup-protect.ps1 

## Extra Logging

Prevention is all fine and dandy, but we need to work under the assumption that your network/org WILL be compromised. So here we'll focus on additional logging options that you can ingest into your SIEM or query with your RMM of choice.

**Sysmon** \- If you don't have sysmon enabled in your environment you are very much missing out.  The sheer amount of info you can glean from parsing sysmon logs is not just great for infosec, but even application debugging. For implementation and more info please refer to https://github.com/SwiftOnSecurity/sysmon-config

**Builtin Windows Logging** \- Windows by default does not log much and what it does log... it doesn't keep for a very long time. The script block below enables larger log file sizes and additional events including Powershell script block logging. 

```powershell
wevtutil sl Security /ms:1024000
wevtutil sl Application /ms:1024000
wevtutil sl System /ms:1024000
wevtutil sl "Windows Powershell" /ms:1024000
wevtutil sl "Microsoft-Windows-PowerShell/Operational" /ms:1024000
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
Auditpol /set /subcategory:"Security Group Management" /success:enable /failure:enable
Auditpol /set /subcategory:"Process Creation" /success:enable /failure:enable
Auditpol /set /subcategory:"Logoff" /success:enable /failure:disable
Auditpol /set /subcategory:"Logon" /success:enable /failure:enable 
Auditpol /set /subcategory:"Filtering Platform Connection" /success:enable /failure:disable
Auditpol /set /subcategory:"Removable Storage" /success:enable /failure:enable
Auditpol /set /subcategory:"SAM" /success:disable /failure:disable
Auditpol /set /subcategory:"Filtering Platform Policy Change" /success:disable /failure:disable
Auditpol /set /subcategory:"IPsec Driver" /success:enable /failure:enable
Auditpol /set /subcategory:"Security State Change" /success:enable /failure:enable
Auditpol /set /subcategory:"Security System Extension" /success:enable /failure:enable
Auditpol /set /subcategory:"System Integrity" /success:enable /failure:enable
```
# Misc Hardening

### Disabling Autoplay/Autorun to Partially Disarm Malicious Storage Devices

Script block below will disable autoplay/autorun for all drives:

```powershell
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer" /v NoAutoplayfornonVolume /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\policies\Explorer" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v NoAutorun /t REG_DWORD /d 1 /f
```

### Disabling Autoplay/Autorun to Partially Disarm Malicious Storage Devices

The script block below will reduce ability of a TA to deliver malware via MS OneNote. Thanks to @keydet89 and @Purp1eW0lf @Huntress for the script! https://www.huntress.com/blog/addressing-initial-access


```powershell
#Run as Administrator, copy/paste the below
# Mount HKU  
mount -PSProvider Registry -Name HKU -Root HKEY_USERS;
# Loop through each HKU/user's HKCU, AND deploy OneNote defences 
(gci -path "HKU:\*\Software\Microsoft\Office\*\OneNote\Options\").PsPath | 
Foreach-Object {New-ItemProperty -Path $_ -Name "disableembeddedfiles" -Value 1 -type DWORD -verbose};
(gci -path "HKU:\*\Software\Microsoft\Office\*\OneNote\Options\").PsPath | 
Foreach-Object {New-Item -Path "$_\embeddedfileopenoptions" -verbose};
(gci -path "HKU:\*\Software\Microsoft\Office\*\OneNote\Options\").PsPath |
Foreach-Object {New-ItemProperty -Path "$_\embeddedfileopenoptions" -Name "blockedextensions" -type string -value ".js;.exe;.bat;.vbs;.com;.scr;.cmd;.ps1;.zip;.dll" -verbose}
```

### Enable Hardening of LSASS to Reduce Ability to Dump Creds

Script block below will harden LSASS against crendential dumping, but nothing is bulletproof:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\LSASS.exe" /v AuditLevel /t REG_DWORD /d 00000008 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 00000001 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation" /v AllowProtectedCreds /t REG_DWORD /d 1 /f
```

### Enable Hardening of AMSI

For a better explanation than I could ever hope to write myself please see https://b4rtik.github.io/posts/antimalware-scan-interface-provider-for-persistence/

To enable Authenticode + Windows Hardware Quality Labs (WHQL) signature checks for AMSI providers use the scriptblock below:

```powershell
reg add "HKLM\SOFTWARE\Microsoft\AMSI" /v FeatureBits /t REG_DWORD /d 2 /f
