@echo off
SetLocal EnableExtensions EnableDelayedExpansion
SET serviceName="Diagnostic Workbench"
echo Building the service %serviceName%
SET PATH=%PATH%;C:\Windows\Microsoft.NET\Framework\v4.0.30319\
SET SolutionPath=C:\Users\itsdevazrapp002_svc\source\repos\ChatBotApi\ChatBotApi.sln
Echo Start Time - %Time%
MSbuild %SolutionPath% /p:Configuration=Release /p:Platform="Any CPU" /p:VisualStudioVersion=14.0
Echo End Time - %Time%
echo build succeeded .
REM Set /p Wait=Build Process Completed...
REM copy /y "$(TargetPath)" "C:\"
echo creating destination folder in C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation\build
if not exist "C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation\build\ChatBotApi" mkdir C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation\build\ChatBotApi
echo folder created successfully
echo preparing to copy file to the destination
xcopy /s C:\Users\itsdevazrapp002_svc\source\repos\ChatBotApi\ChatBotApi\bin C:\Users\itsdevazrapp002_svc\Desktop\deployment_automation\build\ChatBotApi
echo file copied successfully
Set /p Wait=process completed ...

