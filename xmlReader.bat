@echo off & setlocal
setlocal enabledelayedexpansion
FOR /F "tokens=*" %%i IN (buildConfig.xml) DO (
	for %%a IN (%%i) do (
		echo %%a
	)
)