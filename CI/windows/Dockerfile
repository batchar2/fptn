FROM mcr.microsoft.com/windows/servercore:ltsc2019

RUN powershell -Command \
    Set-ExecutionPolicy Bypass -Scope Process -Force; \
    iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))

RUN choco install python --version=3.10.11 -y && \
    choco install cmake --version=3.24.2 -y && \
    choco install make -y && \
    choco install visualstudio-build-tools --version=16.11.22 -y
