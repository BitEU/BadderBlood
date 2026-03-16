For VirtualBox:

1. IN Virtualbox Manager, click file -> Tools -> Network Manager
2. Click NAT Networks bar and click Create
3. On both your DC and client VMs, open settings, change network option from NAT to NAT Network, and select the single NATNetwork name you should see


Join domain:

1. netsh interface ip set dns "Ethernet" static (IPaddrofDC)