@echo off

rem Script to generate dfVFS test files on Windows.
rem Copied with permission from: https://github.com/log2timeline/dfvfs/blob/main/utils/generate_test_data_windows.bat
rem Requires Windows 7 or later

rem Split the output of ver e.g. "Microsoft Windows [Version 10.0.10586]"
rem and keep the last part "10.0.10586]".
for /f "tokens=1,2,3,4" %%a in ('ver') do (
	set version=%%d
)

rem Replace dots by spaces "10 0 10586]".
set version=%version:.= %

rem Split the last part of the ver output "10 0 10586]" and keep the first
rem 2 values formatted with a dot as separator "10.0".
for /f "tokens=1,2,*" %%a in ("%version%") do (
	set version=%%a.%%b
)

rem TODO add check for other supported versions of Windows
rem Also see: https://en.wikipedia.org/wiki/Ver_(command)

if not "%version%" == "10.0" (
	echo Unsupported Windows version: %version%

	exit /b 1
)

if not exist "test_data" (
	mkdir "test_data"
)

rem Create a fixed-size VHD image with a NTFS file system
set unitsize=4096
set imagename=ntfs-fixed.vhd
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart
echo convert mbr >> CreateVHD.diskpart
echo create partition primary >> CreateVHD.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHD.diskpart

echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

rem Create a dynamic-size VHD image with a NTFS file system
set unitsize=4096
set imagename=ntfs-dynamic.vhd
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=expandable > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart
echo convert mbr >> CreateVHD.diskpart
echo create partition primary >> CreateVHD.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHD.diskpart

echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

rem Create a differential-size VHD image with a NTFS file system
set unitsize=4096
set imagename=ntfs-parent.vhd
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart
echo convert mbr >> CreateVHD.diskpart
echo create partition primary >> CreateVHD.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHD.diskpart

echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

for /f "tokens=2,3" %%a in ('echo list volume ^| diskpart') do (
    if %%b==X set volumenumber=%%a
)

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

set imagename=ntfs-differential.vhd

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% parent=%cd%\test_data\ntfs-parent.vhd > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart

echo select volume=%volumenumber% >> CreateVHD.diskpart
echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

rem Create a differential-size VHD image with a FAT file system
set imagename=fat-parent.vhd
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart
echo convert mbr >> CreateVHD.diskpart
echo create partition primary >> CreateVHD.diskpart

echo format fs=fat label="TestVolume" quick >> CreateVHD.diskpart

echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

for /f "tokens=2,3" %%a in ('echo list volume ^| diskpart') do (
    if %%b==X set volumenumber=%%a
)

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

set imagename=fat-differential.vhd

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% parent=%cd%\test_data\fat-parent.vhd > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart

echo select volume=%volumenumber% >> CreateVHD.diskpart
echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

rem Create a fixed-size VHDX image with a NTFS file system
set unitsize=4096
set imagename=ntfs-fixed.vhdx
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHDX.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHDX.diskpart
echo attach vdisk >> CreateVHDX.diskpart
echo convert mbr >> CreateVHDX.diskpart
echo create partition primary >> CreateVHDX.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHDX.diskpart

echo assign letter=x >> CreateVHDX.diskpart

call :run_diskpart CreateVHDX.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHDX.diskpart
echo detach vdisk >> UnmountVHDX.diskpart

call :run_diskpart UnmountVHDX.diskpart

rem Create a dynamic-size VHDX image with a NTFS file system
set unitsize=4096
set imagename=ntfs-dynamic.vhdx
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=expandable > CreateVHDX.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHDX.diskpart
echo attach vdisk >> CreateVHDX.diskpart
echo convert mbr >> CreateVHDX.diskpart
echo create partition primary >> CreateVHDX.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHDX.diskpart

echo assign letter=x >> CreateVHDX.diskpart

call :run_diskpart CreateVHDX.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHDX.diskpart
echo detach vdisk >> UnmountVHDX.diskpart

call :run_diskpart UnmountVHDX.diskpart

rem Create a differential-size VHDX image with a NTFS file system
set unitsize=4096
set imagename=ntfs-parent.vhdx
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHDX.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHDX.diskpart
echo attach vdisk >> CreateVHDX.diskpart
echo convert mbr >> CreateVHDX.diskpart
echo create partition primary >> CreateVHDX.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHDX.diskpart

echo assign letter=x >> CreateVHDX.diskpart

call :run_diskpart CreateVHDX.diskpart

for /f "tokens=2,3" %%a in ('echo list volume ^| diskpart') do (
    if %%b==X set volumenumber=%%a
)

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHDX.diskpart
echo detach vdisk >> UnmountVHDX.diskpart

call :run_diskpart UnmountVHDX.diskpart

set imagename=ntfs-differential.vhdx

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% parent=%cd%\test_data\ntfs-parent.vhdx > CreateVHDX.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHDX.diskpart
echo attach vdisk >> CreateVHDX.diskpart

echo select volume=%volumenumber% >> CreateVHDX.diskpart
echo assign letter=x >> CreateVHDX.diskpart

call :run_diskpart CreateVHDX.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHDX.diskpart
echo detach vdisk >> UnmountVHDX.diskpart

call :run_diskpart UnmountVHDX.diskpart

rem Create a differential-size VHDX image with a FAT file system
set imagename=fat-parent.vhdx
set imagesize=4

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHDX.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHDX.diskpart
echo attach vdisk >> CreateVHDX.diskpart
echo convert mbr >> CreateVHDX.diskpart
echo create partition primary >> CreateVHDX.diskpart

echo format fs=fat label="TestVolume" quick >> CreateVHDX.diskpart

echo assign letter=x >> CreateVHDX.diskpart

call :run_diskpart CreateVHDX.diskpart

for /f "tokens=2,3" %%a in ('echo list volume ^| diskpart') do (
    if %%b==X set volumenumber=%%a
)

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHDX.diskpart
echo detach vdisk >> UnmountVHDX.diskpart

call :run_diskpart UnmountVHDX.diskpart

set imagename=fat-differential.vhdx

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% parent=%cd%\test_data\fat-parent.vhdx > CreateVHDX.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHDX.diskpart
echo attach vdisk >> CreateVHDX.diskpart

echo select volume=%volumenumber% >> CreateVHDX.diskpart
echo assign letter=x >> CreateVHDX.diskpart

call :run_diskpart CreateVHDX.diskpart

call :create_test_file_entries x

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHDX.diskpart
echo detach vdisk >> UnmountVHDX.diskpart

call :run_diskpart UnmountVHDX.diskpart

rem Create a fixed-size VHD image with an AES 128-bit BDE encrypted volume with a password
set unitsize=4096
set imagename=bde_aes_128bit.vhd
set imagesize=64

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart
echo convert mbr >> CreateVHD.diskpart
echo create partition primary >> CreateVHD.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHD.diskpart

echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

call :create_test_file_entries x

rem This will ask for a password
manage-bde -On x: -DiscoveryVolumeType "[none]" -EncryptionMethod aes128 -Password -Synchronous

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

rem Create a fixed-size VHD image with a NTFS file system and unit size 512 and 2 volume snapshots
set unitsize=512
set imagename=ntfs_%unitsize%_with_2_vss.vhd
set imagesize=80

del /f %cd%\test_data\%imagename%

echo Creating: %imagename%

echo create vdisk file=%cd%\test_data\%imagename% maximum=%imagesize% type=fixed > CreateVHD.diskpart
echo select vdisk file=%cd%\test_data\%imagename% >> CreateVHD.diskpart
echo attach vdisk >> CreateVHD.diskpart
echo convert mbr >> CreateVHD.diskpart
echo create partition primary >> CreateVHD.diskpart

echo format fs=ntfs label="TestVolume" unit=%unitsize% quick >> CreateVHD.diskpart

echo assign letter=x >> CreateVHD.diskpart

call :run_diskpart CreateVHD.diskpart

call :create_test_file_entries x

for /l %%i in (1, 1, 2) do (
        "C:\Program Files (x86)\Windows Kits\10\bin\10.0.19041.0\x64\vshadow.exe" -p x:

        echo VSS%%i > x:\vss%%i
)

echo select vdisk file=%cd%\test_data\%imagename% > UnmountVHD.diskpart
echo detach vdisk >> UnmountVHD.diskpart

call :run_diskpart UnmountVHD.diskpart

exit /b 0

rem Creates test file entries
:create_test_file_entries
SETLOCAL
SET driveletter=%1

rem Create a directory
mkdir %driveletter%:\a_directory

echo This is a text file. > %driveletter%:\a_directory\a_file
echo We should be able to parse it. >> %driveletter%:\a_directory\a_file

echo place,user,password > %driveletter%:\passwords.txt
echo bank,joesmith,superrich >> %driveletter%:\passwords.txt
echo alarm system,-,1234 >> %driveletter%:\passwords.txt
echo treasure chest,-,1111 >> %driveletter%:\passwords.txt
echo uber secret laire,admin,admin >> %driveletter%:\passwords.txt

echo This is another file. > %driveletter%:\a_directory\another_file

mklink %driveletter%:\a_link %driveletter%:\a_directory\another_file

ENDLOCAL
exit /b 0

rem Runs diskpart with a script
rem Note that diskpart requires Administrator privileges to run
:run_diskpart
SETLOCAL
set diskpartscript=%1

rem Note that diskpart requires Administrator privileges to run
diskpart /s %diskpartscript%

if %errorlevel% neq 0 (
	echo Failed to run: "diskpart /s %diskpartscript%"

	exit /b 1
)

del /q %diskpartscript%

rem Give the system a bit of time to adjust
timeout /t 1 > nul

ENDLOCAL
exit /b 0
