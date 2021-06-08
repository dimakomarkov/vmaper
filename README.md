# vmapertool

Hello everyone!

Here you can download my little tool, which is designed to collect nmap-fingerprints from your IP range in order to monitor changes. It is also possible to pass information to your vulnerability scanners connected via python, such as Nessus or OpenVAS.

This uses Pandas and Numpy to organize storage, but it is recommended (and possibly fixed in the future) to use databases such as MySQL, because information is sensitive and needs to be protected.

What the tool can do:
- detection of new hosts and ports;
- opening / closing ports;
- change of service versions;
- search for similar host prints*;
- missing hosts and ports.

*useful from the point of view of VM process - if there was a similar fingerprint, then it may be a migrated host (similarity measure is selected as a percentage of similar records)

There are two operating modes manual and automatic. in the first case, the user himself determines when the next study of hosts will be, in the second case it is set by the time interval.

lib/tool:
- python 3.8.0;
- nmap 7.80;
- numpy 1.18.2;
- pandas 1.0.3.





