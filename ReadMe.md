# Using Vulnerability Driver(CorMem.sys)

Privilege escalation was successfully achieved using the CorMem.sys(Physical Memory Read/Write) vulnerable driver, as shown in the figure below.

![image](./pics/ScreenShot_2026-05-15_194342_118.png)


Add BiosToolCommonDriver.sys

Privilege escalation
![image](./pics/ScreenShot_2026-05-17_143556_434.png)


PPL

![image](./pics/ScreenShot_2026-05-17_143717_220.png)


Kill Process
```
DriverLoader.exe <kill processid>
```
开启核晶的*60
![image](./pics/360hejing_2026-05-26_160354_877.png)

![image](./pics/kill%20360_2026-05-26_160557_313.png)

* 新增了VirtualToPhysical的函数
**代码来源于redteamfortress（https://github.com/redteamfortress）的项目PPLShade（https://github.com/redteamfortress/PPLShade）**

**The code is derived from the PPLShade project（https://github.com/redteamfortress/PPLShade）, which is authored by redteamfortress（https://github.com/redteamfortress）. Further information on this project can be found on the redteamfortress GitHub page.**


Loader mapping driver
![image](./pics/LoaderMappingDriver_2026-06-01_123521_640.png)

**代码已经更新**



add commandline 


![image](./pics/mapping%20with%20cmdline.png)

![image](./pics/Privilege%20escaption%20with%20cmdline.png)


dmp lsass (不支持Windows 11新版本)

build
![image](./pics/Tset%20build_2026-06-05_192042_837.png)

remove process protect 
![image](./pics/remove%20lsass%20protection_2026-06-05_190608_025.png)

dmp file  
![image](./pics/dmp%20file_2026-06-05_191338_890.png)  


**Update DriverSelector**  
**Just switch the BYOVD driver you want to use in the DriverSelector file.**   
只要在文件DriverSelector切换你想使用的漏洞驱动即可，注意相应的类型。  


## Syscall
使用了[SysWhispers4](https://github.com/JoasASantos/SysWhispers4)加入到了本项目

Special thanks to the author of [SysWhispers4](https://github.com/JoasASantos/SysWhispers4) for sharing this project.


# 个人DIY
修改了UTF-8编码，解决了运行时中文乱码的问题，修改了提权逻辑，如果提权位输入PID，则新开启SYSTEM权限的cmd，感谢原作者提供优质代码以供参考学习。
