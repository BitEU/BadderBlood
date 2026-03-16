BadderBlood
========
BadderBlood is designed to be an improvement on BadBlood by Secframe. BadBlood randomly fills a Microsoft Active Directory Domain with a structure and thousands of objects. The original tool is very good at what it does, but make an AD with an unrealistically abysmal configuration. While I won't say such a deployment is impossible, certaintly any company that resembles BadBlood deserves to be swept into the dustbin of history.

BadderBlood distinguishes itself in another key area: It adds heavily misconfigured GPOs. Nothing fancy, but it rounds out a terrible domain configuration.


## Acknowledgments

SecFrame/David Rowe for making [BadBlood](https://www.secframe.com/badblood/).


## Installation (on a freshly installed Windows Server)

1. ```Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools```
2. ```Install-ADDSForest -DomainName "spboxfactory.com"```
3. Wait for the machine to restart
4. ```Set-MpPreference -DisableRealtimeMonitoring $true```
5. ```Install-WindowsFeature -Name ADCS-Cert-Authority -IncludeManagementTools```
6. ```Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CryptoProviderName "RSA#Microsoft Software Key Storage Provider" -KeyLength 2048 -HashAlgorithmName SHA256 -Force```
5. Download this repo, extract it to the C drive with a path of ```C:\BadderBlood```
6. Run ```Get-ChildItem -Path C:\BadderBlood -Recurse | Unblock-File```
7. ```powershell.exe -ExecutionPolicy Bypass -File C:\BadderBlood\Invoke-BadderBlood.ps1```
8. Once BadderBlood is complete, run ```powershell.exe -ExecutionPolicy Bypass -File C:\BadderBlood\BadderBlood\BadderBloodAnswerKey.ps1``` to generate the answer key files for what is grossly misconfigured.


## Instalation on QEMU

1. Download virtio-win.iso rom https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/latest-virtio/
2. Download and install QEMU from https://qemu.weilnetz.de/w64/
3. Download the win server eval ISO you want
4. You can now cd to the QEMU dir and run this, changing the paths to reflect your install: 
```.\qemu-system-x86_64.exe -m 16G -smp 8,sockets=1,cores=8,threads=1 -cpu Haswell-v4,vendor=GenuineIntel,+hypervisor,+kvm_pv_unhalt -machine q35 -accel whpx -drive file="C:\Users\wcdaht-srs\Downloads\ws2022.qcow2",format=qcow2,if=virtio -cdrom "C:\Users\wcdaht-srs\Downloads\SERVER_EVAL_x64FRE_en-us.iso" -drive file="C:\Users\wcdaht-srs\Downloads\virtio-win.iso",media=cdrom -boot d -vga std -net nic,model=e1000 -net user```
5. Go through all the install steps, load storage drivers with virtio, etc
6. Once the machine restarts, you can now use this cmd:
```.\qemu-system-x86_64.exe -m 16G -smp 8,sockets=1,cores=8,threads=1 -cpu Haswell-v4,vendor=GenuineIntel,+hypervisor,+kvm_pv_unhalt -machine q35 -accel whpx -drive file="C:\Users\wcdaht-srs\Downloads\ws2022.qcow2",format=qcow2,if=virtio -vga std -net nic,model=e1000 -net user,hostfwd=tcp::3390-:3389```
7. Now you can rdp into it via localhost:3390


## Math

~35sec per dept folder (~6-7.5min with CORP folder)
~20sec per 10 user folders ()
~35min for the whole BadFS deployment


## Nuking your AD (Just use snapshots instead, really dont do this)

If you want to nuke AD:
1. Run ```Uninstall-ADDSDomainController -LastDomainControllerInDomain -RemoveApplicationPartitions -IgnoreLastDnsServerForZone -LocalAdministratorPassword $LocalAdminPass -Force```
2. ```Restart-Computer -Force```
3. ```Install-ADDSForest -DomainName "contoso.com" -Force```
3. Start from Step 7


## License
This project is licensed under the gplv3 License - see the LICENSE.md file for details


## Disclaimer
Please note: all tools/ scripts in this repo are released for use "AS IS" without any warranties of any kind, including, but not limited to their installation, use, or performance. We disclaim any and all warranties, either express or implied, including but not limited to any warranty of noninfringement, merchantability, and/ or fitness for a particular purpose. We do not warrant that the technology will meet your requirements, that the operation thereof will be uninterrupted or error-free, or that any errors will be corrected.

Any use of these scripts and tools is at your own risk. There is no guarantee that they have been through thorough testing in a comparable environment and we are not responsible for any damage or data loss or time loss incurred with their use.

You are responsible for reviewing and testing any scripts you run thoroughly before use in any non-testing environment.  This tool is not designed for a production environment.



Prevent no missing managers (I suggest 1500):


percentile	accounts required
50 % (median)	787
75 %	912
90 %	1 056
95 %	1 163
99 %	1 401
maximum seen (50 000 trials)	2 575
(mean ≈ 818)