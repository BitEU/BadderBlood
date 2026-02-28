BadderBlood
========
BadderBlood is designed to be an improvement on BadBlood by Secframe. BadBlood randomly fills a Microsoft Active Directory Domain with a structure and thousands of objects. The original tool is very good at what it does, but make an AD with an unrealistically abysmal configuration. While I won't say such a deployment is impossible, certaintly any company that resembles BadBlood deserves to be swept into the dustbin of history.

BadderBlood distinguishes itself in another key area: It adds heavily misconfigured GPOs. Nothing fancy, but it rounds out a terrible domain configuration.


## Acknowledgments

SecFrame/David Rowe for making [BadBlood](https://www.secframe.com/badblood/).


## Installation (on a freshly installed Windows Server)


1. ```Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools```
2. ```Install-ADDSForest -DomainName "contoso.com"```
3. Wait for the machine to restart
4. ```Set-MpPreference -DisableRealtimeMonitoring $true```
5. Download this repo, extract it to the C drive with a path of ```C:\BadderBlood```
6. ```Run Get-ChildItem -Path C:\BadderBlood -Recurse | Unblock-File```
7. ```powershell.exe -ExecutionPolicy Bypass -File C:\BadderBlood\BadBlood\Invoke-BadBlood.ps1```
8. Once BadBlood is complete, run ```powershell.exe -ExecutionPolicy Bypass -File C:\BadderBlood\BadBlood\BadBloodAnswerKey.ps1``` to generate the answer key files for what is grossly misconfigured.


## License
This project is licensed under the gplv3 License - see the LICENSE.md file for details


## Disclaimer
Please note: all tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. We disclaim any and all warranties, either express or implied, including but not limited to any warranty of noninfringement, merchantability, and/ or fitness for a particular purpose. We do not warrant that the technology will meet your requirements, that the operation thereof will be uninterrupted or error-free, or that any errors will be corrected.

Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss or time loss incurred with their use.

You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.  This tool is not designed for a production environment.