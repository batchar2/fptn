# Setup Guide

##3 Python 3.13

1. Install Python 3.13 as admin.
2. Add Python and `pip` to the global `PATH` environment variable.
3. Install the required Python packages:

```bash

pip install requests conan==2.9.2 numpy
pip install clang-tidy
pip install clang-format
pip install cmake-format
```


### Inno Setup

1. Download and install [Inno Setup](https://jrsoftware.org/download.php/is.exe?site=1).
2. Add the Inno Setup installer folder to the global PATH environment variable. By default, this is: `C:\Program Files (x86)\Inno Setup 6`


### Visual Studio Community

1. Download and install [Visual Studio Community 2022](https://visualstudio.microsoft.com/vs/community/).
2. During installation, ensure you select the C++ development tools and CMake components.
3. Add cmake to the global PATH environment variable. By default, this is: `C:\Program Files\Microsoft Visual Studio\2022\Community\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin`


### Windows SDK

Download and install the [Windows SDK](https://go.microsoft.com/fwlink/?linkid=2272610).


### Remove python aliases


1. Open Settings
2. Search for 'Manage app execution alias'
3. Turn Off the python aliases
4. Run powershell as Admin and run 

```
Set-ExecutionPolicy Unrestricted

Remove-Item $env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\python*.exe
Remove-Item $env:USERPROFILE\AppData\Local\Microsoft\WindowsApps\Microsoft.DesktopAppInstaller_*\python*.exe
```

# Install Powershell

Download and install [PowerShell](https://github.com/PowerShell/PowerShell/releases/download/v7.4.6/PowerShell-7.4.6-win-x64.msi)


### Add conanan 

Need to add conan to global PATH, for example `C:\Users\user\AppData\Local\Programs\Python\Python313\Scripts`


### Install Cppcheck

Install and need to add to global PATH https://cppcheck.sourceforge.io/

### Restart computer 


#### Github CI

It needs to run as a service under the current user.


### Test Build

Clone the project repository and its submodules:

```
git submodule update --init --recursive
conan profile detect --force
```
