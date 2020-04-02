@echo off
rem build by Visual Studio 2015
cmake .. -G"Visual Studio 14 2015" -A x64
MSBuild Project.sln /t:Rebuild /p:Configuration=Release /p:Platform="x64"
