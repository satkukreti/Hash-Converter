# Hash Converter 
![Pls load](HashConverterSmall.png) 

A simple application that takes any identifiable information of a malicious file, ideally its SHA1 hash, and uses VirusTotal's API to scrape and collect either the SHA256 or MD5 alternative.

I made Hash Converter because many cybersecurity tools that manage firewalls and proxys (CheckPoint, NetSkope, etc.) can only filter hashes that are SHA256 or MD5. Often, however, SOC Threat Landscape Updates report only SHA1 hashes in their list of IOCs. It can take cyber teams hours to manually search for other hash equivalents, copy, paste, delete - rinse and repeat - to properly patch their network. Instead, Hash Converter can speed up this process to take only a few seconds.

To use Hash Converter, get a list of SHA1 hashes and paste them into a text file. Select whether you want a SHA256 or MD5 conversion, and then choose the file via a GUI. Wait until the text box says that it is finished, and then search for an outputed text file called "hashconversion.txt". This file contains the newly converted hashes, and will let you know whether the hashes were found by indicating "Not Found" is an equivalent was not found.

I hope this tool is useful to you, please let other teams know about Hash Converter if you agree!
