' Create automatic Windows Defender Update "WDU" task that updates Defender only if it's enabled and running.
'    Create WDU.xml
'
'
'    Creating Windows Defender Update auto renewal task
'
Set Fso=CreateObject("Scripting.FileSystemObject"):Set f=Fso.CreateTextFile(fso.GetParentFolderName(WScript.ScriptFullName) & "\task.xml",True,True)
f.write _ 
"<?xml version=""1.0"" encoding=""UTF-16""?>" &_
"<Task version=""1.2"" xmlns=""http://schemas.microsoft.com/windows/2004/02/mit/task"">" &_
"  <RegistrationInfo>" &_
"    <Date>2016-02-18T08:29:39</Date>" &_
"    <Author>pf100\rpo</Author>" &_
"    <URI>\WDU</URI>" &_
"  </RegistrationInfo>" &_
"  <Triggers>" &_
"    <CalendarTrigger>" &_
"      <StartBoundary>2016-01-01T00:01:00</StartBoundary>" &_
"      <Enabled>true</Enabled>" &_
"      <ScheduleByDay>" &_
"        <DaysInterval>1</DaysInterval>" &_
"      </ScheduleByDay>" &_
"    </CalendarTrigger>" &_
"    <CalendarTrigger>" &_
"      <StartBoundary>2016-01-01T06:01:00</StartBoundary>" &_
"      <Enabled>true</Enabled>" &_
"      <ScheduleByDay>" &_
"        <DaysInterval>1</DaysInterval>" &_
"      </ScheduleByDay>" &_
"    </CalendarTrigger>" &_
"    <CalendarTrigger>" &_
"      <StartBoundary>2016-01-01T12:01:00</StartBoundary>" &_
"      <Enabled>true</Enabled>" &_
"      <ScheduleByDay>" &_
"        <DaysInterval>1</DaysInterval>" &_
"      </ScheduleByDay>" &_
"    </CalendarTrigger>" &_
"    <CalendarTrigger>" &_
"      <StartBoundary>2016-01-01T18:01:00</StartBoundary>" &_
"      <Enabled>true</Enabled>" &_
"      <ScheduleByDay>" &_
"        <DaysInterval>1</DaysInterval>" &_
"      </ScheduleByDay>" &_
"    </CalendarTrigger>" &_
"    <BootTrigger>" &_
"      <Enabled>true</Enabled>" &_
"      <Delay>PT10M</Delay>" &_
"    </BootTrigger>" &_
"    <LogonTrigger>" &_
"      <Enabled>true</Enabled>" &_
"    </LogonTrigger>" &_
"  </Triggers>" &_
"  <Principals>" &_
"    <Principal id=""Author"">" &_
"      <LogonType>InteractiveToken</LogonType>" &_
"      <RunLevel>HighestAvailable</RunLevel>" &_
"    </Principal>" &_
"  </Principals>" &_
"  <Settings>" &_
"    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>" &_
"    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>" &_
"    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>" &_
"    <AllowHardTerminate>true</AllowHardTerminate>" &_
"    <StartWhenAvailable>false</StartWhenAvailable>" &_
"    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>" &_
"    <IdleSettings>" &_
"      <StopOnIdleEnd>false</StopOnIdleEnd>" &_
"      <RestartOnIdle>false</RestartOnIdle>" &_
"    </IdleSettings>" &_
"    <AllowStartOnDemand>true</AllowStartOnDemand>" &_
"    <Enabled>true</Enabled>" &_
"    <Hidden>false</Hidden>" &_
"    <RunOnlyIfIdle>false</RunOnlyIfIdle>" &_
"    <WakeToRun>false</WakeToRun>" &_
"    <ExecutionTimeLimit>PT72H</ExecutionTimeLimit>" &_
"    <Priority>7</Priority>" &_
"  </Settings>" &_
"  <Actions Context=""Author"">" &_
"    <Exec>" &_
"	  <Command>""" & FSO.GetParentFolderName(Wscript.ScriptFullName) & "\bin\WDU.cmd" & """</Command>" &_
"    </Exec>" &_
"  </Actions>" &_
"</Task>" 
f.Close