@echo off
%1 mshta vbscript:CreateObject("Shell.Application").ShellExecute("taskmgrpro.exe","/c %~s0 ::","","runas",1)(window.close)&&exit
cd /d %~dp0
PsExec.exe -i -s -d taskmgrpro.exe