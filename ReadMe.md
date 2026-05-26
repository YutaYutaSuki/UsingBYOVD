# Using Vulnerability Driver(CorMem.sys)

Privilege escalation was successfully achieved using the CorMem.sys(Physical Memory Read/Write) vulnerable driver, as shown in the figure below.

![image](./ScreenShot_2026-05-15_194342_118.png)


Add BiosToolCommonDriver.sys

Privilege escalation
![image](./ScreenShot_2026-05-17_143556_434.png)


PPL

![image](./ScreenShot_2026-05-17_143717_220.png)


Kill Process
```
DriverLoader.exe <kill processid>
```
开启核晶的*60
![image](./360hejing_2026-05-26_160354_877.png)

![image](./kill%20360_2026-05-26_160557_313.png)

* 新增了VirtualToPhysical的函数
**代码来源于redteamfortress（https://github.com/redteamfortress）的项目PPLShade（https://github.com/redteamfortress/PPLShade）**

**The code is derived from the PPLShade project（https://github.com/redteamfortress/PPLShade）, which is authored by redteamfortress（https://github.com/redteamfortress）. Further information on this project can be found on the redteamfortress GitHub page.**
