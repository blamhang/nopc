# nopc
NOPC, the Nessus-based offline UNIX patch checker.

## Prerequisites
To run the nopc.sh script, the script needs to be on system that contains both the nasl command and plugins from nessus.
The usual case is for nopc.sh to be run on a unix build that has Nessus install.

## Usage
The following are optional parameters:
    -d ‘nessus plugin dir’
    -l ‘output type’
    -n ‘location of nasl command’
    -s ‘system type’

## Output Type (-l)
Basically, there are raw and CSV output types. There are different output variations available particularly for CSV as follows:
* -l ’0′ = Displays outdated package information only. This is the Installed and Fixed version for each outdated package
* -l ’1′ = Displays NASL name and outdated packages
* -l ’2′ = Displays CVEs for each affected package in (CSV comma separated format)
* -l ’3′ = Displays CVEs and CVSSv2 score for each affected package (CSV comma separated format)
* -l ’4′ = Displays CVE for each affected package (tab separated format)
* -l ’5′ = Displays CVE and CVSSv2 score for each affected package (tab separated format)

## System Type (-s)
```
 1 - AIX
 2 - HP-UX
 3 - MacOS X *
 4 - Solaris (!11) *
 5 - Debian
 6 - FreeBSD
 7 - Gentoo
 8 - Mandrake
 9 - Redhat
10 - Redhat (Centos)
11 - Redhat (Fedora)
12 - Slackware
13 - SuSE *
14 - Ubuntu
15 - Cisco IOS/ASA *
16 - OpenSuSE *
```

## Examples
```
$ nopc.sh -l 3
[+] What type of system have you got the patch output for?
 1 - AIX
 2 - HP-UX
 3 - MacOS X *
 4 - Solaris (!11) *
 5 - Debian
 6 - FreeBSD
 7 - Gentoo
 8 - Mandrake
 9 - Redhat
10 - Redhat (Centos)
11 - Redhat (Fedora)
12 - Slackware
13 - SuSE *
14 - Ubuntu
15 - Cisco IOS/ASA *
16 - OpenSuSE *
 
 * EXPERIMENTAL!!
 
Enter 1-16? 14
[+] Ubuntu Selected
[+] Run 'dpkg -l|cat > patchlist.txt'
[+] Enter Location of file: patch-ubuntu-krb5-2.txt
[+] Enter the Value of DISTRIB_RELEASE=() from /etc/lsb-release e.g. 11.10
[+] Enter Text Requested: 10.04
[+] Enter value of 'uname -m' e.g. x86_64, i686
[+] Enter Text Requested: i586
[+] To run this in a script the command would be:
 
/opt/bin/nopc.sh -l '3' -s '14' 'patch-ubuntu-krb5-2.txt' '10.04' 'i586'
 
[+] Locating Nasls
[+] Checking for 2314 Missing Patches
NOPC, Ubuntu
Plugin ID, CVE, CVSSv2, Severity, KB, Title
61379, "CVE-2012-1012, CVE-2012-1013, CVE-2012-1014, CVE-2012-1015", 9.3, High, "USN-1520-1", "Ubuntu 10.04 LTS / 11.04 / 11.10 / 12.04 LTS : krb5 vulnerabilities (USN-1520-1)"
51116, "CVE-2010-1323, CVE-2010-1324, CVE-2010-4020, CVE-2010-4021", 4.3, Medium, "USN-1030-1", "Ubuntu 6.06 LTS / 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : krb5 vulnerabilities (USN-1030-1)"
52682, "CVE-2011-0284", 7.6, High, "USN-1088-1", "Ubuntu 9.10 / 10.04 LTS / 10.10 : krb5 vulnerability (USN-1088-1)"
55074, "CVE-2011-0285", 10, High, "USN-1116-1", "Ubuntu 9.10 / 10.04 LTS / 10.10 : krb5 vulnerability (USN-1116-1)"
51985, "CVE-2010-4022, CVE-2011-0281, CVE-2011-0282", 5, Medium, "USN-1062-1", "Ubuntu 8.04 LTS / 9.10 / 10.04 LTS / 10.10 : krb5 vulnerabilities (USN-1062-1)"
49772, "CVE-2010-1322", 6.5, Medium, "USN-999-1", "Ubuntu 10.04 LTS / 10.10 : krb5 vulnerability (USN-999-1)"
```
