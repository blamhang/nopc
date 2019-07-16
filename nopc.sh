#!/bin/bash

###############################################################################
#
# Nessus Offline Patch Checker
#
# An offline patch checker using Nessus nasls and a manually created KB file.
#
# Copyright (C) 2012-2014 - rid@portcullis-security.com / ridean@cisco.com
# Copyright (C) 2014-2017 - blamhang@cisco.com
#
#	* This program is free software; you can redistribute it and/or modify
#	* it under the terms of the GNU General Public License as published by
#	* the Free Software Foundation; either version 2 of the License, or
#	* (at your option) any later version.
#	*
#	* This program is distributed in the hope that it will be useful,
#	* but WITHOUT ANY WARRANTY; without even the implied warranty of
#	* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	* GNU General Public License for more details.
#	*
#	* You should have received a copy of the GNU General Public License
#	* along with this program; if not, write to the Free Software
#	* Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.     
#
###############################################################################
#
# VERSION HISTORY
#  0.5.0	Released 24/03/2017 
#		Add OpenSuSE checks
#		Major release after multiple bug fixes from 0.4.7 release
#  0.4.7	Released 09/2015
#		Shell script consolidated back into 1 file
#		Improvements to interactive mode
#		OS/Distro types reordered
#		Default location for nasl and plugins added
#		Script checked against shellcheck
#  0.4.5	Released 02/2014
#		Added CSV format to include CVEv2 scores
#		Bug fixes to Ubuntu, Redhat, MacOSX, HP-UX
#  0.4.2	Released 09/2012
#  0.4.1	Released 07/2012
#  0.4.0	Released 06/2012
#
# (See also: http://labs.portcullis.co.uk/tools/nopc)
#
###############################################################################

# Latest version (0.5.0) released on March 24 2017
# nopc.sh - 0.5.0 (a)
nopc_version="nopc.sh  0.5.0a"

#
# The following OS/Distros are potentially supported:
# (* means further testing required)
#
# ####################### AIX #################################################
# ####################### HP-UX ###############################################
# ####################### MacOS X * ###########################################
# ####################### Solaris * ###########################################
# ####################### Debian ##############################################
# ####################### FreeBSD #############################################
# ####################### Gentoo ##############################################
# ####################### Mandrake ############################################
# ####################### RedHat ##############################################
# ####################### RedHat (Centos) #####################################
# ####################### RedHat (Fedora) #####################################
# ####################### Slackware ###########################################
# ####################### SuSE * ##############################################
# ####################### Ubuntu ##############################################
# ####################### Cisco IOS/ASA * #####################################
# ####################### OpenSuSE * ##########################################

# Options:
# -s 'system_type' = See printSystems() function for available system types.
# -d 'dir' = Directory for Nessus Plugins
# (e.g. -d '/opt/nessus/lib/nessus/plugins')
# -n 'nasl cmd' = Location of nasl command
# (e.g. -n '/opt/nessus/bin/nasl')
# -l 'output type' = Different OUTPUT formats
# 
# Output stage is a bit better now.
# There is a flag (-l) that can select the different output
# The original raw output is still included.
# The new output takes the form of CSV tab limited output and includes more
# information such as CVE, CVSS Score, Severity rating.
#
# -l '0' = Displays Outdated Packages only (Installed/Fixed Packages)
# -l '1' = Displays NASL name and Outdated Packages
# -l '2' = Displays Plugin ID, CVEs, CVSSv2 string, KB#, Description (comma separated)
# -l '3' = Displays Plugin ID, CVEs, CVSSv2 score, Severity, KB#, Description (comma separated)
# -l '4' = Displays Plugin ID, CVEs, CVSSv2 string, KB#, Description (tab separated)
# -l '5' = Displays Plugin ID, CVEs, CVSSv2 score, Severity, KB#, Description (tab separated)
#
# -l '0'
# This is quick as runs the nasl command once against the list of nasl files.
# It only displays outdated packages but not missing security patches.
# Remaining output options runs a nasl command for EACH nasl file. (~x5 slower)
# It will show the nasl name from which you get the security advisory name.
# You will have to tailor this for each OS tested as name format is different.
#
# -l '1'
# It displays outdated packages and missing security patches.
#
# -l '2'
# It displays plugin id, CVEs, CVSSv2 string, KB#/NASL name, description.
# It uses the NASL name and information from the NASL to generate display.
#
# -l '3'
# It displays plugin id, CVEs, CVSSv2 score, Severity, KB#/NASL name, description.
# It uses the NASL name and information from the NASL to generate display.
# NASL file only displays the CVSSv2 string and hence have to calculate the
# CVSSv2 score. This is generated with an accompanied cvss_lookup.txt file.
# Also the severity risk rating has to be calculated from the score.
# Oddly if there is no CVSSv2 string, it looks like that nasl sets a risk_factor.
#
# -l '4'
# (tab separated version of -l '2')
#
# -l '5'
# (tab separated version of -l '3')
#
# To add more checks look at the plugin:
#		
#		ssh_get_info.nasl
#
# Default nasl plugins location set. May want to change if stored elsewhere.
# nessus_dir='/Library/Nessus/run/lib/nessus/plugins/'
nessus_dir='/opt/nessus/lib/nessus/plugins/'
# nasl=`which nasl`
nasl='/opt/nessus/bin/nasl'

printSystems(){
	printf " 1 - AIX\n"
	printf " 2 - HP-UX\n"
	printf " 3 - MacOS X *\n"
	printf " 4 - Solaris (!11) *\n"
	printf " 5 - Debian\n"
	printf " 6 - FreeBSD\n"
	printf " 7 - Gentoo\n"
	printf " 8 - Mandrake\n"
	printf " 9 - Redhat\n"
	printf " 10 - Redhat (Centos)\n"
	printf " 11 - Redhat (Fedora)\n"
	printf " 12 - Slackware\n"
	printf " 13 - SuSE *\n"
	printf " 14 - Ubuntu\n"
	printf " 15 - Cisco IOS/ASA *\n"
	printf " 16 - OpenSuSE *\n"

	printf "\n * EXPERIMENTAL!!\n\n"
}

outputTypes(){
	printf " 0 - Displays Outdated Packages only\n"
	printf " 1 - Displays NASL name and Outdated Packages\n"
	printf " 2 - CSV output of CVE, KB and description (comma)\n"
	printf " 3 - CSV output of CVE, CVSSv2, Severity, KB, Description (comma)\n"
	printf " 4 - CSV output of CVE, KB and description (tab)\n"
	printf " 5 - CSV output of CVE, CVSSv2, Severity, KB, Description (tab)\n\n"
}

usage(){
	printf "%b [Options]\n" "$0"
	printf "Version: %s\n" "$nopc_version"
	printf "OPTIONS:\n"
	printf "  -?: This usage page\n"
	printf "  -d: Location of Nessus Plugins directory\n"
	printf "  -n: Location of nasl program directory\n"
	printf "  -s: System Type (with optional arguments)\n"
	printf "  -l: Output Type\n"
	printf "  -v: Version of NOPC\n\n"

	printf "Where system type is one of:\n"
	printSystems
	#printf "`printSystems`\n\n"

	printf "Where output type is one of:\n"
	outputTypes
	#printf "`outputTypes`\n\n"

	printf "** Entering no parameters will run this in wizard mode walking you through the data collection for your desired system\n"
}

# function to print command line running if questions need to be asked.
printCMD(){
	if [ "$alloncmd" -gt 0 ]
	then 
		printf "[+] To run this in a script the command would be:\n\n"
		cmd="$0"

		if [ ! -z "$cmdnasl" ]
		then
			cmd="$cmd -n '$nasl'"
		fi
			
		if [ ! -z "$cmddir" ]
		then
			cmd="$cmd -d '$nessus_dir'"
		fi

		if [ ! -z "$cmdout" ]
		then
			cmd="$cmd -l '$output'"
		fi
	
		cmd="$cmd -s"

		for arg in "$@"
		do
			cmd="$cmd '$arg'"
		done
	
		printf "%s\n\n" "$cmd"
	fi
}

# function to determine what kind of system patch parsing for.
getSystem(){
	let alloncmd++
	printf "[+] What type of system have you got the patch output for?\n"
	printSystems
	read -p "Enter 1-16? " choice
	system="$choice"
	return
}

# function to determine what kind of system patch parsing for.
getOutput(){
	printf "[+] Which output format would you like to use?\n"
	outputTypes
	read -p "Enter 1-5? " choice

	# Check that choice is firstly a number and if is between 1-5
	# Otherwise use default of 0
	re='^[0-9]+$'
	if [[ $choice =~ $re ]] ; then
		if [ "$choice" -ge 0 -a "$choice" -le 5 ]; then
			output="$choice";
		fi;
	else output=0; fi
	return
}

# function to get a file input from user.
# first arg is the instruction for user.
# second arg is prepopulated value from command line.
getFile(){
	text="$1"
	file="$2"
	while [ ! -e "$file" ]
	do 
		let alloncmd++
		printf "[+] %b \n" "$text"
		read -p "[+] Enter Location of file: " file
	done
}

# function to get a version input from user.
# first arg is the instruction for user.
# second arg is prepopulated value from command line.
getString(){ 
	text="$1"
	string="$2"
	if [ -z "$string" ]
	then
		let alloncmd++
		printf "[+] %b \n" "$text"
		read -p "[+] Enter Text Requested: " string
	fi
}

# Additional processing where looking into the nasl to gather details such as
# severity/cve
#
# The output is:
# Nessus ID	CVE	CVSS_Code	KB#	Description
getNaslDetails() {
	# Set Delimiter. Default is comma delimited.
	delim=$1;
	if [[ -z $delim ]]; then delim=', '; fi
	# Keys to grep for to get necessary info
	pluginstr="script_id"
	cvestr="script_cve_id"
	cvsstr="CVSS2#AV"
	descstr="script_name"

	# echo "grep $cvestr" "$a"
	nessusid=$(grep "$pluginstr" "$a" | perl -pe 's/\s*script_id\(//g' | perl -pe 's/\);//g')
	cve=$(grep "$cvestr" "$a" | perl -pe 's/\s*script_cve_id\(//g' | perl -pe 's/\);//g' | perl -pe 's/", "/, /g')
	cvss=$(grep "$cvsstr" "$a" | perl -ne 'print $1 if m/(CVSS2#\S+)\"/')
	# kb1=`echo "$a" | perl -pe 's/\.nasl//g' | cut -f2 -d '_'`
	kb1=$(echo "$a" | perl -pe 's/\.nasl//g' | perl -pe 's/.*?\_//')
	desc=$(grep "$descstr" "$a" | perl -ne 'print $1 if m/(\".+\")/')
	printf "%s%s%s%s%s%s%s%s%s\n" "$nessusid" "$delim" "$cve" "$delim" "$cvss" "$delim" "$kb1" "$delim" "$desc"
	return
}

# Additional processing where looking into the nasl to gather details such as
# severity/cve
#
# As the nasl files do not include actual CVSS scores, they are generated
# A "cvss_lookup.txt" file is used to obtain a CVSS score.
# Severity only appears (need to confirm this) as the Risk_Factor attribute 
# if no CVSS details appear in the nasl. Otherwise severity has to be
# calculated from the CVSS score.
# See: https://qualysguard.qualys.com/qwebhelp/fo_portal/module_pci/pci_risk_ratings.htm
# 0.0 - 3.9	Low
# 4.0 - 6.9	Medium
# 7.0 - 10.0	High
#
# The output is:
# Nessus ID	CVE	CVSS_Score	Severity	KB#	Description
getNaslSeverity() {
	# Set Delimiter. Default is comma delimited.
	delim=$1;
	if [[ -z $delim ]]; then delim=', '; fi
	# Keys to grep for to get necessary info
	b=$(echo "$0" | perl -pe 's/[^\/]*$/cvss_lookup.txt/')
	#b=$cvss_lookup
	pluginstr="script_id"
	cvestr="script_cve_id"
	cvsstr="CVSS2#AV"
	# Note: the risk_factor will not pick up the value if they are on separate lines.	
	riskfactorstr="attribute: *\"risk_factor\""
	descstr="script_name"

	# echo "grep $cvestr" "$a"
	nessusid=$(grep "$pluginstr" "$a" | perl -pe 's/\s*script_id\(//g' | perl -pe 's/\);//g')
	cve=$(grep "$cvestr" "$a" | perl -pe 's/\s*script_cve_id\(//g' | perl -pe 's/\);//g' | perl -pe 's/", "/, /g')
	cvss=$(grep "$cvsstr" "$a" | perl -ne 'print $1 if m/CVSS2#(\S+)\"/')
	risk=$(grep "$riskfactorstr" "$a" | perl -ne 'print $1 if m/value:\s*\"(\w+)\"/')
	# kb1=`echo "$a" | perl -pe 's/\.nasl//g' | cut -f2 -d '_'`
	kb1=$(echo "$a" | perl -pe 's/.*\///' | perl -pe 's/\.nasl//g' | perl -pe 's/.*?\_//')
	kb1=\"$kb1\"
	desc=$(grep "$descstr" "$a" | perl -ne 'print $1 if m/(\".+\")/')

	# echo "$b"
	# echo "$kb1: $cvss\n"
	#
	# Check for $cvss being empty as some NASLs do not have a CVE/CVSS score.
	# [ $cvss != "" ] [ -z $cvss]
	# http://stackoverflow.com/questions/6852612/bash-test-for-empty-string-with-x
	if [[ X"" = X"$cvss" ]] 
	then
		cvssscore='N/A'
		if [[ X"" = X"$risk" ]]; then severity='N/A'; else severity=$risk; fi;
	else
		#echo "$cvss_lookup"
		cvssscore=$(echo "$cvss_lookup" | grep "$cvss" | cut -f2)
		severity=$(echo "$cvss_lookup" | grep "$cvss" | cut -f3)
		#cvssscore=`grep "$cvss" "$b" | cut -f2`
		#severity=`grep "$cvss" "$b" | cut -f3`
	fi
	printf "%s%s%s%s%s%s%s%s%s%s%s\n" "$nessusid" "$delim" "$cve" "$delim" "$cvssscore" "$delim" "$severity" "$delim" "$kb1" "$delim" "$desc"
	# dumper=`echo "$dumper" "$nessusid\t$cve\t$cvssscore\t$severity\t$kb1\t$desc\n"`
	return
}



###############################################################################
# setXXX() - Each OS has a call back function selected from a case.
#


# setAIX() - Need to get one file (lslpp) and two strings (version,oslevel).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/aix_* | grep Host/local_checks_enabled | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/AIX/lslpp", "Host/local_checks_enabled", "Host/AIX/version");
# script_require_keys("Host/local_checks_enabled", "Host/AIX/oslevel", "Host/AIX/version", "Host/AIX/lslpp");
#
# Example Plugins: (10976)
# aix_IV01118.nasl
# aix_IZ99391.nasl
setAIX(){ 
	
	system=1
	system_name="AIX"
	nessus_filematch="aix_"
	
	# Instructions String
	patch_ins="Run 'lslpp -Lc > patchlist.txt'"
	version_ins="Enter the AIX Release e.g. 6.1"
	oslevelsp_ins="Enter the output of 'oslevel -s' e.g. 6100-04-04-1441"
	
	# Info to be included in KB header
	patchline="Host/AIX/lslpp="
	versionline="Host/AIX/version="
	oslevelline="Host/AIX/oslevel="
	oslevelspline="Host/AIX/oslevelsp="
	
	# get patch file/version/cpu from command line
	patch="${args[0]}"
	version="${args[1]}"
	oslevelsp="${args[2]}"
	oslevel=$(echo "$oslevelsp" | cut -f "1 2" -d"-")

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getString "$version_ins" "$version"
	version="$string"
	getString "$oslevelsp_ins" "$oslevelsp"
	oslevelsp="$string"
	
	printCMD "$system" "$patch" "$version" "$oslevelsp"
 	
	# remove newlines
	v=$(echo "$version" |perl -p -e 's/\n/\\n/g')
	o=$(echo "$oslevel" |perl -p -e 's/\n/\\n/g')
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	osp=$(echo "$oslevelsp" |perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$oslevelline$o";
	echo "$fileheader$oslevelspline$osp";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setCentOS - Need to get one file (rpm-list).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/centos_RHSA* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/CentOS/rpm-list");
#
# Example Plugins: (1417)
# centos_RHSA-2013-0663.nasl
# centos_update_level.nasl
#
setCentOS(){ 

	system=10
	system_name="Centos"
	nessus_filematch="centos_"
	nessus_filematch="centos_RHSA"

	# Instructions String
	patch_ins="Run '/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\\\n' > patchlist.txt'"
	version_ins="Enter the contents of /etc/redhat-release"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/CentOS/rpm-list="
	versionline="Host/CentOS/release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line 
	patch="${args[0]}"
	version="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file" 
	getString "$version_ins" "$version"
	version="$string"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$version" "$cpu";
	
	# remove newlines
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setCisco() - Need to get one file and one string (version).
# UNTESTED
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/cisco_* | grep Host/local_checks_enabled | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/Cisco/ASA", "Host/Cisco/ASA/model");
# script_require_keys("Host/Cisco/IOS/version");
# script_require_keys("Host/Cisco/IOS/Version");
# script_require_keys("Host/Cisco/IOS/version", "Host/Cisco/IOS/Platform");
# script_require_keys("SMB/ARF Player/path");
# script_require_keys("SMB/WRF Player/path");
#
# Example Plugins: (162)
# cisco-sa-20120328-ssh.nasl
# cisco-sa-20121010-asa.nasl
setCisco(){
	
	# Host/Cisco/IOS
	# Host/Cisco/ASA
	# Host/Cisco/show_ver
	
	system=15
	system_name="Cisco"
	nessus_filematch="cisco-sa-"

	# Instructions String
	version_ins="Run 'show version'"

	# Info to be included in KB header
	versionline="Host/Cisco/show_ver="

	# get version from command line
	version="${args[0]}"
	
	# get version from user input
	getFile "$version_ins" "$version"
	version="$file"
	
	ios_line="Host/Cisco/IOS/Version="
	asa_line="Host/Cisco/ASA/Version="
	
	printCMD "$system" "$version"
 	
	# remove newlines
	v=$(perl -p -e 's/\n/\\n/g' < "$version")

	# create the kb file
	echo "$fileheader$versionline$v" >> "$kb"
	
 	#IOS=`cat ios_version | egrep '^.*IOS.*Version'`
 	#ASA=`cat ios_version | egrep '^Cisco Adaptive Security Appliance Software Version'`
	IOS=$(egrep '^.*IOS.*Version' < "$version")
	ASA=$(egrep '^Cisco Adaptive Security Appliance Software Version' < "$version")

	if [ "$IOS" ] 
		then
			printf "[+] IOS Detected '%b'" "$IOS\n"
			echo "$fileheader$ios_line$IOS" >> "$kb"
	elif [ "$ASA" ]
		then
			printf "[+] ASA Detected '%b'" "$ASA\n"
			echo "$fileheader$asa_line$ASA" >> "$kb"
			
	else
			echo "[!] No Version information Found, exciting"
			exit
			rm "$kb"
	fi
}

# setDebian() - Need to get one file (dpkg-l) and two strings (release/cpu).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/debian_DSA* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");
# 
# Example plugins: (2639)
# debian_DSA-1999.nasl
setDebian(){
	
	system=5
	system_name="Debian"
	nessus_filematch="debian_DSA"
	
	# Instructions String
	patch_ins="Run 'dpkg -l|cat > patchlist.txt'"
	version_ins="Enter contents of /etc/debian_version"
#	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/Debian/dpkg-l="
	versionline="Host/Debian/release="
#	cpuline="Host/cpu="

	# get patch file/version/cpu from command line
	patch="${args[0]}"
	version="${args[1]}"
#	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getString "$version_ins" "$version"
	version="$string"
#	getString "$cpu_ins" "$cpu"
#	cpu="$string"
	
	printCMD "$system" "$patch" "$version" # "$cpu" 
		
	# remove newlines
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
#	c=`echo "$cpu" | perl -p -e 's/\n/\\n/g'`

	# create the kb file
	echo "$fileheader$versionline$v" >> "$kb"
#	echo "$fileheader$cpuline$c" >> $kb
	echo "$fileheader$patchline$p" >> "$kb"
}

# setFedora - Need to get one file (rpm-list) and one string (release).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/fedora* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/RedHat/rpm-list");
# script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");
#
# Example Plugins: (5579)
# fedora_2013-4012.nasl
# fedora_extras_2007-005.nasl
# fedora_ds_pass_disclosure.nasl
#
setFedora(){ 

	system=11
	system_name="Fedora"
	nessus_filematch="fedora_"

	# Instructions String
	patch_ins="Run '/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\\\n' > patchlist.txt'"
	version_ins="Enter the contents of /etc/redhat-release"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/RedHat/rpm-list="
	versionline="Host/RedHat/release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line 
	patch="${args[0]}"
	version="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file" 
	getString "$version_ins" "$version"
	version="$string"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$version" "$cpu";
	
	# remove newlines
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setFreeBSD() - Need to get one file (pkg_info) and one string (release).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/freebsd_* | grep Host/local_checks_enabled | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/FreeBSD/release", "Host/FreeBSD/pkg_info");
#
# Example Plugins: (2237)
# freebsd_ethereal_0105.nasl
# freebsd_linux.nasl
setFreeBSD(){

	system=6
	system_name="Free BSD"
	nessus_filematch="freebsd_"

	# Instructions String
	patch_ins="Run '/usr/sbin/pkg_info > patchlist.txt'"
	version_ins="Enter the FreeBSD release in the format '6.1_15' for 'FreeBSD 6.1-RELEASE-p15'"

	# Info to be included in KB header
	patchline="Host/FreeBSD/pkg_info="
	versionline="Host/FreeBSD/release="

	# get patch file/version/cpu from command line
	patch="${args[0]}"
	version="${args[1]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getString "$version_ins" "$version"
	version="$string"
	
	printCMD "$system" "$patch" "$version"
 	
	# remove newlines
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setGentoo - Need to get one file (qpkg-list) and one string (release).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/gentoo_GLSA* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys('Host/Gentoo/qpkg-list');
# script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");
#
# Example Plugins: (1719)
# gentoo_GLSA-201301-07.nasl
# gentoo_not_up_to_date.nasl
#
setGentoo(){ 

	system=7
	system_name="Gentoo"
	nessus_filematch="gentoo_"
	nessus_filematch="gentoo_GLSA-"

	# Instructions String
	patch_ins="Run '/bin/qpkg -I -v' > patchlist.txt"
	version_ins="Enter the contents of /etc/gentoo-release"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/Gentoo/qpkg-list="
	versionline="Host/Gentoo/release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line 
	patch="${args[0]}"
	version="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file" 
	getString "$version_ins" "$version"
	version="$string"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$version" "$cpu";
	
	# remove newlines
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setHPUX() - Need to get one file (swlist) and two strings (version,processor).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/hpux_* | grep Host/local_checks_enabled | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/HP-UX/version", "Host/HP-UX/swlist");
#
# Example Plugins: (1963)
# hpux_PHCO_42317.nasl
# hpux_PHNE_9771.nasl
setHPUX(){ 
	
	system=2
	system_name="HP-UX"
	nessus_filematch="hpux_"
	
	# Instructions String
	patch_ins="Run '/usr/sbin/swlist -l fileset -a revision > patchlist.txt'"
	version_ins="Enter the HP-UX Release"
	proc_ins="Enter the processor type, ia64, parisc-700, parisc-800"

	# Info to be included in KB header
	patchline="Host/HP-UX/swlist="
	versionline="Host/HP-UX/version="
	procline="Host/HP-UX/processor="
	hwline="Host/HP-UX/hardware="
	hw=800

	# get patch file/version/cpu from command line
	patch="${args[0]}"
	version="${args[1]}"
	proc="${args[2]}"
	if [[ $proc == *-* ]]; then
	   hw=$(echo "$proc" | cut -f2 -d'-');
	   proc=$(echo "$proc" | cut -f1 -d'-');
	fi;
	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getString "$version_ins" "$version"
	version="$string"
	getString "$proc_ins" "$proc"
	proc="$string"
	
	printCMD "$system" "$patch" "$version" "$proc"
 	
	# remove newlines
	#v=`echo "$version" |perl -p -e 's/\n/\\\\n/g'`
	#o=`echo "$proc" | perl -p -e 's/\n/\\\\n/g'`
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	v=$version
	o=$proc
	# p=`cat "$patch"`

	# create the kb file
	{ echo "$fileheader$patchline$p";
	echo "$fileheader$versionline$v";
	echo "$fileheader$procline$o";
	echo "$fileheader$hwline$hw"; } >> "$kb"
}

# setMandrake - Need to get one file (rpm-list) and two strings (release/cpu).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/mandr* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");
# script_require_keys("Host/Mandrake/release", "Host/Mandrake/rpm-list");
#
# Example Plugins: (1329)
# mandrake_MDKA-2007-137.nasl
# mandrake_MDKSA-2007-246.nasl
setMandrake(){ 

	system=8
	system_name="Mandrake_"
	# nessus_filematch="mandrake_"
	# nessus_filematch="mandriva_"
	# BETTER HOPE NESSUS DON'T ADD NASLS starting with mandr
	nessus_filematch="mandr"

	# Instructions String
	patch_ins="Run '/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\\\n' > patchlist.txt'"
	version_ins="Enter the contents of /etc/mandrake-release"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/Mandrake/rpm-list="
	versionline="Host/Mandrake/release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line 
	patch="${args[0]}"
	version="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file" 
	getString "$version_ins" "$version"
	version="$string"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$version" "$cpu";

	# $version  modified into MDKXXX format
	if [[ $version != MDK* ]]; then
	   version=$(echo "$version" | perl -ne 'print "MDK".$2 if m/(Mandrake Linux|Mandrakelinux|Mandriva Linux)\s+release\s+([0-9]+\.[0-9])/')
	fi;

	# remove newlines
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	#v=`echo "$version" | perl -p -e 's/\n/\\n/g'`
	v=$version
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setOSX - Need to get two files and one string (version).
# UNTESTED
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/macosx* | grep Host/local_checks_enabled | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/packages", "Host/MacOSX/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages/boms");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages", "Host/MacOSX/packages/boms");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "Host/MacOSX/packages", "Host/uname");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Adobe Flash Professional/Installed");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Adobe Photoshop/Installed");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Adobe_Reader/Installed");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Firefox/Installed");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Flash_Player/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Fusion/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/iTunes/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/QuickTime/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Safari/Installed");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Server/Version");
# script_require_keys("Host/local_checks_enabled", "Host/MacOSX/Version", "MacOSX/Silverlight/Installed");
# script_require_keys("Host/local_checks_enabled", "Host/uname", "Host/MacOSX/Version", "MacOSX/Safari/Installed");
# script_require_keys("Host/local_checks_enabled", "MacOSX/Fusion/Version");
#
# Example plugins: (416)
# macosx_ms12-076.nasl
# macosx_SecUpd2012-001.nasl
setOSX(){
	
	system=3
	system_name="OS X"
	nessus_filematch="macosx"

	# Instructions String
	patch_ins="Run 'grep -A 1 displayName /Library/Receipts/InstallHistory.plist 2>/dev/null| grep string | sed 's/<string>\(.*\)<\/string>.*/\1/g'  | sed 's/^[      ]*//g'|tr  -d -c 'a-zA-Z0-9\n _-'|sort|uniq > patchlist.txt'"
	bom_ins="Run \"ls -1 /Library/Receipts/boms /private/var/db/receipts 2>/dev/null | grep '\.bom$'\" > bomlist.txt"
	version_ins="Enter OS X Version\n (e.g. 10.6.8)"
	
	# Info to be included in KB header
	patchline="Host/MacOSX/packages="
	bomline="Host/MacOSX/packages/boms="
	versionline="Host/MacOSX/Version=Mac OS X "
	
	# get patch file/version/cpu from command line 
	installed="${args[0]}"
	boms="${args[1]}"
	version="${args[2]}"
	
	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$installed"
	patch="$file"
	getFile "$bom_ins" "$boms"
	bom="$file"
	getString "$version_ins" "$version"
	version="$string"
	
	printCMD "$system" "$patch" "$bom" "$version"

	# remove newlines
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	b=$(perl -p -e 's/\n/\\n/g' < "$bom")
	
	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$bomline$b";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setRedHat - Need to get one file and two strings (version/cpu).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/redhat-RHSA* | grep Host/local_checks_enabled | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys ("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");
#
# Example Plugins: (2590)
# redhat-RHSA-2013-0661.nasl
setRedHat(){ 

	system=9  # System number not important
	system_name="Redhat"  # System name not important
	nessus_filematch="redhat-RHSA"  # Format of nasls that this check needs. See find command later.
	
	# Instructions String
	patch_ins="Run '/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\\\n' > patchlist.txt'"  # command to run to get the patch info
	version_ins="Enter the contents of /etc/redhat-release"  # string to put in for version info
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"  # string to put in for cpu info

	# Info to be included in KB header
	patchline="Host/RedHat/rpm-list="  # KB header for patch info
	versionline="Host/RedHat/release="  # KB header for version info
	cpuline="Host/cpu="  # KB header for cpu info

	# get patch file/version/cpu from command line 
	patch="${args[0]}"  # get patch if passed via command line
	version="${args[1]}"  # get version if passed via command line
	cpu="${args[2]}"  # get cpu if passed via command line

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file" 
	getString "$version_ins" "$version"
	version="$string"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$version" "$cpu";
	
	# remove newlines
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setSlackware() - Need to get one file (packages) and one string (release).
#
# Required Information:
# script_require_keys("Host/local_checks_enabled", "Host/Slackware/release", "Host/Slackware/packages");
# 
# Example plugins: (593)
# Slackware_SSA_2013-042-01.nasl
setSlackware(){
	
	system=12
	system_name="Slackware"
	nessus_filematch="Slackware_SSA"
	
	# Instructions String
	patch_ins="Run 'ls -1 /var/log/packages > patchlist.txt'"
	version_ins="Enter the Contents of /etc/slackware-version"

	# Info to be included in KB header
	patchline="Host/Slackware/packages="
	versionline="Host/Slackware/release="

	# get patch file/version/cpu from command line
	patch="${args[0]}"
	version="${args[1]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getString "$version_ins" "$version"
	version="$string"
	
	printCMD "$system" "$patch" "$version"
	 	
	# remove newlines
	v=$(echo "$version" | perl -p -e 's/^Slackware //' | perl -p -e 's/\n/\\n/g')
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setSolaris() - Need to get two files (pkginfo/revision) and one string (version).
# UNTESTED / Require a kb from an authenticated nessus solaris scan to help. 
#
# Required Information:
# script_require_keys("Host/Solaris/showrev");
# script_require_keys("Host/Solaris/pkginfo"); (only for solaris_enum_packages.nasl)
#
# Example plugins: (3274)
# solaris10_150123.nasl solaris10_x86_150124.nasl
# solaris23_104748.nasl	solaris23_x86_104749.nasl
# solaris24_108636.nasl	solaris24_x86_108637.nasl
# solaris251_112891.nasl	solaris251_x86_124945.nasl
# solaris26_121332.nasl	solaris26_x86_115564.nasl
# solaris5.2_102381.nasl
# solaris7_124520.nasl	solaris7_x86_120652.nasl
# solaris8_142294.nasl	solaris8_x86_142295.nasl
# solaris9_147264.nasl	solaris9_x86_147265.nasl
#
# Host/Solaris/Version=5.7\r\n
# Solaris/Packages/Versions/SUNWxfb=7.0.0,REV=1998.08.11\r
# Host/Solaris/showrev=Hostname: havefun\r\nHostid: 80f9249b\r\nRelease: 5.7\r\nKernel architecture: sun4u\r\nApplication architecture: sparc\r\nHardware provider: Sun_Microsystems\r\nDomain: 6     5535.com\r\nKernel version: SunOS 5.7 Generic 106541-08 October 1999\r\n\r\nOpenWindows version: \r\nOpenWindows Version 3.6.1  2 September 1999\r\n\r\nPatch: 107648-09 Obsoletes:  Requires: 107078-17 Inc     ompatibles:  Packages: SUNWxwrtx, SUNWxwrtl, SUNWxwice, SUNWxwplt, SUNWxwicx, SUNWxwplx, SUNWxwinc, SUNWxwman, SUNWxwpmn, SUNWxwslb, SUNWxwslx\r\nPatch: 107656-05 Obsoletes:  Requires: 107648-06 Incompati     bles:  Packages: SUNWxwrtx, SUNWxwrtl, SUNWxwplt, SUNWxwplx, SUNWxwpmn, SUNWxwslb, SUNWxwslx\r\nPatch: 107430-01 Obsoletes:  Requires:  Incompatibles:  Packages: SUNWwsr\r\nPatch: 108029-02 Obsoletes:  Re     quires:  Incompatibles:  Packages: SUNWwsr\r\nPatch: 107063-01 Obsoletes:  Requires:  Incompatibles:  Packages: SUNWtleux\r\nPatch: 107437-03 Obsoletes:  Requires:  Incompatibles:  Packages: SUNWtiu8x, SU     NWtiu8\r\nPatch: 107316-01 Obsoletes:  Requires:  Incompatibles:  Packages: SUNWploc,
# Host/Solaris/pkginfo=SMCbash                 (sparc) 4.1\r\nSMCgcc                 (sparc) 3.4.6\r\nSMCgzip                 (sparc) 1.4\r\nSMClgc346                 (sparc) 3.4.6\r\nSMCliconv                      (sparc) 1.9.2\r\nSMClintl                 (sparc) 3.4.0\r\nSUNW5xmft                 (sparc) 7.0,REV=1.0.6\r\nSUNWab2m                 (sparc) 2.00,REV=19980819\r\nSUNWaccr                      (sparc) 11.7.0,REV=1998.09.01.04.16\r\nSUNWaccu 
# /usr/bin/pkginfo -x | awk '{ if ( NR % 2 ) { prev = $1 } else  { print prev" "$0  } }'
# /usr/bin/showrev -a
# /usr/bin/pkginfo -x | awk '{ if ( NR % 2 ) { prev = $1 } else  { print prev" "$0  } }' | awk '{print $1"="$3}'
#
setSolaris(){
	
	system=4
	system_name="Solaris"
	#nessus_filematch="solaris9"
	nessus_filematch="solaris"
	
	# Instructions String
	pkg_ins="Run '/usr/bin/pkginfo -x | awk '{ if ( NR % 2 ) { prev = \$1 } else  { print prev\" \"\$0  } }' > pkginfo.txt'"
	revision_ins="Run '/usr/bin/showrev -a > revision.txt'"
	version_ins="Enter the Solaris Release e.g 5.7"

	# Info to be included in KB header
	pkgline="Host/Solaris/pkginfo="
	revisionline="Host/Solaris/showrev="
	versionline="Host/Solaris/Version="

	# get patch version/pkg/revision from command line
	version="${args[0]}"
	pkg="${args[1]}"
	revision="${args[2]}"

	# get patch version/pkg/revision from user input
	getString "$version_ins" "$version"
	version="$string"
	getFile "$pkg_ins" "$pkg"
	pkg="$file"
	getFile "$revision_ins" "$revision"
	revision="$file"
	
	printCMD "$system" "$version" "$pkg" "$revision"
	 	
	# remove newlines
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	p=$(perl -p -e 's/\n/\\n/g' < "$pkg")
	r=$(perl -p -e 's/\n/\\r\\n/g' < "$revision")

	# set nessus_filematch to represent
	# if [ "$version" -eq "5.2" ] then let nessus_filematch="solaris5.2" fi
	# if [ "$version" -eq "5.4" ] then let nessus_filematch="solaris24" fi
	# if [ "$version" -eq "5.5.1" ] then let nessus_filematch="solaris251" fi
	# if [ "$version" -eq "5.6" ] then let nessus_filematch="solaris26" fi
	# if [ "$version" -eq "5.7" ] then let nessus_filematch="solaris7" fi
	# if [ "$version" -eq "5.8" ] then let nessus_filematch="solaris8" fi
	# if [ "$version" -eq "5.9" ] then let nessus_filematch="solaris9" fi
	# if [ "$version" -eq "5.10" ] then let nessus_filematch="solaris10" fi
	
	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$pkgline$p";
	echo "$fileheader$revisionline$r"; } >> "$kb"
	
	awk '{print "1323253913 1 Solaris/Packages/Versions/"$1"="$3}' < "$pkg" >> "$kb"	
}

# setSuSE - Need to get two file (rpm-list/release) and two strings (cpu).
# UNTESTED / Require a kb from an authenticated nessus solaris scan to help. 
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/suse* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");
# script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");
# script_require_keys("Host/SuSE/rpm-list");
# script_require_keys("Settings/ParanoidReport");
#
# Example Plugins: (4660)
# suse_SA_2007_052.nasl
# suse_zmd-7857.nasl
#
setSuSE(){ 

	system=13
	system_name="Suse"
	nessus_filematch="suse_"

	# Instructions String
	patch_ins="Run '/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\\\n' > patchlist.txt'"
	release_ins="Run 'cat /etc/SuSE-release > release.txt"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/SuSE/rpm-list="
	releaseline="Host/SuSE/release="
	patchlevelline="Host/SuSE/patchlevel="
	etcreleaseline="Host/etc/suse-release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line 
	patch="${args[0]}"
	release="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getFile "$release_ins" "$release"
	release="$file"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$release" "$cpu";
	
	# remove newlines
	#p=`cat "$patch" | perl -p -e 's/\n/\\\\n/g'`
	#r=`cat "$release" | perl -p -e 's/\n/\\\\n/g'`
	#c=`echo "$cpu" | perl -p -e 's/\n/\\\\n/g'`
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	e=$(perl -p -e 's/\n/\\n/g' < "$release")
	l=$(grep PATCHLEVEL "$release" | cut -c 14-)
	r=$(grep VERSION "$release" | cut -c 11-)
	r="SLES$r"
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$releaseline$r";
	echo "$fileheader$patchlevelline$l";
	echo "$fileheader$etcreleaseline$e";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setOpenSuSE - Need to get two file (rpm-list/release) and two strings (cpu).
# UNTESTED / Require a kb from an authenticated nessus solaris scan to help. 
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/suse* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");
# script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");
# script_require_keys("Host/SuSE/rpm-list");
# script_require_keys("Settings/ParanoidReport");
#
# Example Plugins: (2368)
# openSUSE-2015-499.nasl
#
setOpenSuSE(){ 

	system=16
	system_name="Suse"
	nessus_filematch="openSUSE-"

	# Instructions String
	patch_ins="Run '/bin/rpm -qa --qf '%{NAME}-%{VERSION}-%{RELEASE}|%{EPOCH}\\\n' > patchlist.txt'"
	release_ins="Run 'cat /etc/SuSE-release > release.txt"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/SuSE/rpm-list="
	releaseline="Host/SuSE/release="
	patchlevelline="Host/SuSE/patchlevel="
	etcreleaseline="Host/etc/suse-release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line 
	patch="${args[0]}"
	release="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getFile "$release_ins" "$release"
	release="$file"
	getString "$cpu_ins" "$cpu"
	cpu="$string"

	printCMD "$system" "$patch" "$release" "$cpu";
	
	# remove newlines
	#p=`cat "$patch" | perl -p -e 's/\n/\\\\n/g'`
	#r=`cat "$release" | perl -p -e 's/\n/\\\\n/g'`
	#c=`echo "$cpu" | perl -p -e 's/\n/\\\\n/g'`
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	e=$(perl -p -e 's/\n/\\n/g' < "$release")
	l=$(grep PATCHLEVEL "$release" | cut -c 14-)
	r=$(grep VERSION "$release" | cut -c 11-)
	r="SUSE$r"
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$releaseline$r";
	echo "$fileheader$patchlevelline$l";
	echo "$fileheader$etcreleaseline$e";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}

# setUbuntu() - Need to get one file and two strings (version/cpu).
#
# Required Information:
# grep script_require_keys /opt/nessus/lib/nessus/plugins/ubuntu_USN* | cut -f2 -d ":" | perl -p -e 's/^\s*//g' | sort | uniq
# script_require_keys("Host/cpu", "Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
# script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");
#
# Example plugins: (2019)
# ubuntu_USN-999-1.nasl
# ubuntu_USN-1520-1.nasl
setUbuntu(){
	
	system=14
	system_name="Ubuntu"
	nessus_filematch="ubuntu_USN"
	
	# Instructions String
	patch_ins="Run 'dpkg -l|cat > patchlist.txt'"
	version_ins="Enter the Value of DISTRIB_RELEASE=() from /etc/lsb-release e.g. 11.10"
	cpu_ins="Enter value of 'uname -m' e.g. x86_64, i686"

	# Info to be included in KB header
	patchline="Host/Debian/dpkg-l="
	versionline="Host/Ubuntu/release="
	cpuline="Host/cpu="

	# get patch file/version/cpu from command line
	patch="${args[0]}"
	version="${args[1]}"
	cpu="${args[2]}"

	# get patch file/version/cpu from user input
	getFile "$patch_ins" "$patch"
	patch="$file"
	getString "$version_ins" "$version"
	version="$string"
	getString "$cpu_ins" "$cpu"
	cpu="$string"
	
	printCMD "$system" "$patch" "$version" "$cpu"	
	
	# remove newlines
	v=$(echo "$version" | perl -p -e 's/\n/\\n/g')
	p=$(perl -p -e 's/\n/\\n/g' < "$patch")
	c=$(echo "$cpu" | perl -p -e 's/\n/\\n/g')

	# create the kb file
	{ echo "$fileheader$versionline$v";
	echo "$fileheader$cpuline$c";
	echo "$fileheader$patchline$p"; } >> "$kb"
}


###############################################################################
# CVSS_lookup tab matrix now included as $cvss_lookup
# See: http://stackoverflow.com/questions/15429330/how-to-specify-a-multi-line-shell-variable
read -d '' cvss_lookup << "EOF"
(AV:L/AC:H/Au:N/C:N/I:N/A:N)	0	Low
(AV:L/AC:H/Au:N/C:N/I:N/A:P)	1.2	Low
(AV:L/AC:H/Au:N/C:N/I:N/A:C)	4	Medium
(AV:L/AC:H/Au:N/C:N/I:P/A:N)	1.2	Low
(AV:L/AC:H/Au:N/C:N/I:P/A:P)	2.6	Low
(AV:L/AC:H/Au:N/C:N/I:P/A:C)	4.7	Medium
(AV:L/AC:H/Au:N/C:N/I:C/A:N)	4	Medium
(AV:L/AC:H/Au:N/C:N/I:C/A:P)	4.7	Medium
(AV:L/AC:H/Au:N/C:N/I:C/A:C)	5.6	Medium
(AV:L/AC:H/Au:N/C:P/I:N/A:N)	1.2	Low
(AV:L/AC:H/Au:N/C:P/I:N/A:P)	2.6	Low
(AV:L/AC:H/Au:N/C:P/I:N/A:C)	4.7	Medium
(AV:L/AC:H/Au:N/C:P/I:P/A:N)	2.6	Low
(AV:L/AC:H/Au:N/C:P/I:P/A:P)	3.7	Low
(AV:L/AC:H/Au:N/C:P/I:P/A:C)	5.2	Medium
(AV:L/AC:H/Au:N/C:P/I:C/A:N)	4.7	Medium
(AV:L/AC:H/Au:N/C:P/I:C/A:P)	5.2	Medium
(AV:L/AC:H/Au:N/C:P/I:C/A:C)	5.9	Medium
(AV:L/AC:H/Au:N/C:C/I:N/A:N)	4	Medium
(AV:L/AC:H/Au:N/C:C/I:N/A:P)	4.7	Medium
(AV:L/AC:H/Au:N/C:C/I:N/A:C)	5.6	Medium
(AV:L/AC:H/Au:N/C:C/I:P/A:N)	4.7	Medium
(AV:L/AC:H/Au:N/C:C/I:P/A:P)	5.2	Medium
(AV:L/AC:H/Au:N/C:C/I:P/A:C)	5.9	Medium
(AV:L/AC:H/Au:N/C:C/I:C/A:N)	5.6	Medium
(AV:L/AC:H/Au:N/C:C/I:C/A:P)	5.9	Medium
(AV:L/AC:H/Au:N/C:C/I:C/A:C)	6.2	Medium
(AV:L/AC:H/Au:S/C:N/I:N/A:N)	0	Low
(AV:L/AC:H/Au:S/C:N/I:N/A:P)	1	Low
(AV:L/AC:H/Au:S/C:N/I:N/A:C)	3.8	Low
(AV:L/AC:H/Au:S/C:N/I:P/A:N)	1	Low
(AV:L/AC:H/Au:S/C:N/I:P/A:P)	2.4	Low
(AV:L/AC:H/Au:S/C:N/I:P/A:C)	4.5	Medium
(AV:L/AC:H/Au:S/C:N/I:C/A:N)	3.8	Low
(AV:L/AC:H/Au:S/C:N/I:C/A:P)	4.5	Medium
(AV:L/AC:H/Au:S/C:N/I:C/A:C)	5.5	Medium
(AV:L/AC:H/Au:S/C:P/I:N/A:N)	1	Low
(AV:L/AC:H/Au:S/C:P/I:N/A:P)	2.4	Low
(AV:L/AC:H/Au:S/C:P/I:N/A:C)	4.5	Medium
(AV:L/AC:H/Au:S/C:P/I:P/A:N)	2.4	Low
(AV:L/AC:H/Au:S/C:P/I:P/A:P)	3.5	Low
(AV:L/AC:H/Au:S/C:P/I:P/A:C)	5	Medium
(AV:L/AC:H/Au:S/C:P/I:C/A:N)	4.5	Medium
(AV:L/AC:H/Au:S/C:P/I:C/A:P)	5	Medium
(AV:L/AC:H/Au:S/C:P/I:C/A:C)	5.7	Medium
(AV:L/AC:H/Au:S/C:C/I:N/A:N)	3.8	Low
(AV:L/AC:H/Au:S/C:C/I:N/A:P)	4.5	Medium
(AV:L/AC:H/Au:S/C:C/I:N/A:C)	5.5	Medium
(AV:L/AC:H/Au:S/C:C/I:P/A:N)	4.5	Medium
(AV:L/AC:H/Au:S/C:C/I:P/A:P)	5	Medium
(AV:L/AC:H/Au:S/C:C/I:P/A:C)	5.7	Medium
(AV:L/AC:H/Au:S/C:C/I:C/A:N)	5.5	Medium
(AV:L/AC:H/Au:S/C:C/I:C/A:P)	5.7	Medium
(AV:L/AC:H/Au:S/C:C/I:C/A:C)	6	Medium
(AV:L/AC:H/Au:M/C:N/I:N/A:N)	0	Low
(AV:L/AC:H/Au:M/C:N/I:N/A:P)	0.8	Low
(AV:L/AC:H/Au:M/C:N/I:N/A:C)	3.7	Low
(AV:L/AC:H/Au:M/C:N/I:P/A:N)	0.8	Low
(AV:L/AC:H/Au:M/C:N/I:P/A:P)	2.3	Low
(AV:L/AC:H/Au:M/C:N/I:P/A:C)	4.4	Medium
(AV:L/AC:H/Au:M/C:N/I:C/A:N)	3.7	Low
(AV:L/AC:H/Au:M/C:N/I:C/A:P)	4.4	Medium
(AV:L/AC:H/Au:M/C:N/I:C/A:C)	5.3	Medium
(AV:L/AC:H/Au:M/C:P/I:N/A:N)	0.8	Low
(AV:L/AC:H/Au:M/C:P/I:N/A:P)	2.3	Low
(AV:L/AC:H/Au:M/C:P/I:N/A:C)	4.4	Medium
(AV:L/AC:H/Au:M/C:P/I:P/A:N)	2.3	Low
(AV:L/AC:H/Au:M/C:P/I:P/A:P)	3.4	Low
(AV:L/AC:H/Au:M/C:P/I:P/A:C)	4.9	Medium
(AV:L/AC:H/Au:M/C:P/I:C/A:N)	4.4	Medium
(AV:L/AC:H/Au:M/C:P/I:C/A:P)	4.9	Medium
(AV:L/AC:H/Au:M/C:P/I:C/A:C)	5.6	Medium
(AV:L/AC:H/Au:M/C:C/I:N/A:N)	3.7	Low
(AV:L/AC:H/Au:M/C:C/I:N/A:P)	4.4	Medium
(AV:L/AC:H/Au:M/C:C/I:N/A:C)	5.3	Medium
(AV:L/AC:H/Au:M/C:C/I:P/A:N)	4.4	Medium
(AV:L/AC:H/Au:M/C:C/I:P/A:P)	4.9	Medium
(AV:L/AC:H/Au:M/C:C/I:P/A:C)	5.6	Medium
(AV:L/AC:H/Au:M/C:C/I:C/A:N)	5.3	Medium
(AV:L/AC:H/Au:M/C:C/I:C/A:P)	5.6	Medium
(AV:L/AC:H/Au:M/C:C/I:C/A:C)	5.9	Medium
(AV:L/AC:M/Au:N/C:N/I:N/A:N)	0	Low
(AV:L/AC:M/Au:N/C:N/I:N/A:P)	1.9	Low
(AV:L/AC:M/Au:N/C:N/I:N/A:C)	4.7	Medium
(AV:L/AC:M/Au:N/C:N/I:P/A:N)	1.9	Low
(AV:L/AC:M/Au:N/C:N/I:P/A:P)	3.3	Low
(AV:L/AC:M/Au:N/C:N/I:P/A:C)	5.4	Medium
(AV:L/AC:M/Au:N/C:N/I:C/A:N)	4.7	Medium
(AV:L/AC:M/Au:N/C:N/I:C/A:P)	5.4	Medium
(AV:L/AC:M/Au:N/C:N/I:C/A:C)	6.3	Medium
(AV:L/AC:M/Au:N/C:P/I:N/A:N)	1.9	Low
(AV:L/AC:M/Au:N/C:P/I:N/A:P)	3.3	Low
(AV:L/AC:M/Au:N/C:P/I:N/A:C)	5.4	Medium
(AV:L/AC:M/Au:N/C:P/I:P/A:N)	3.3	Low
(AV:L/AC:M/Au:N/C:P/I:P/A:P)	4.4	Medium
(AV:L/AC:M/Au:N/C:P/I:P/A:C)	5.9	Medium
(AV:L/AC:M/Au:N/C:P/I:C/A:N)	5.4	Medium
(AV:L/AC:M/Au:N/C:P/I:C/A:P)	5.9	Medium
(AV:L/AC:M/Au:N/C:P/I:C/A:C)	6.6	Medium
(AV:L/AC:M/Au:N/C:C/I:N/A:N)	4.7	Medium
(AV:L/AC:M/Au:N/C:C/I:N/A:P)	5.4	Medium
(AV:L/AC:M/Au:N/C:C/I:N/A:C)	6.3	Medium
(AV:L/AC:M/Au:N/C:C/I:P/A:N)	5.4	Medium
(AV:L/AC:M/Au:N/C:C/I:P/A:P)	5.9	Medium
(AV:L/AC:M/Au:N/C:C/I:P/A:C)	6.6	Medium
(AV:L/AC:M/Au:N/C:C/I:C/A:N)	6.3	Medium
(AV:L/AC:M/Au:N/C:C/I:C/A:P)	6.6	Medium
(AV:L/AC:M/Au:N/C:C/I:C/A:C)	6.9	Medium
(AV:L/AC:M/Au:S/C:N/I:N/A:N)	0	Low
(AV:L/AC:M/Au:S/C:N/I:N/A:P)	1.5	Low
(AV:L/AC:M/Au:S/C:N/I:N/A:C)	4.4	Medium
(AV:L/AC:M/Au:S/C:N/I:P/A:N)	1.5	Low
(AV:L/AC:M/Au:S/C:N/I:P/A:P)	3	Low
(AV:L/AC:M/Au:S/C:N/I:P/A:C)	5	Medium
(AV:L/AC:M/Au:S/C:N/I:C/A:N)	4.4	Medium
(AV:L/AC:M/Au:S/C:N/I:C/A:P)	5	Medium
(AV:L/AC:M/Au:S/C:N/I:C/A:C)	6	Medium
(AV:L/AC:M/Au:S/C:P/I:N/A:N)	1.5	Low
(AV:L/AC:M/Au:S/C:P/I:N/A:P)	3	Low
(AV:L/AC:M/Au:S/C:P/I:N/A:C)	5	Medium
(AV:L/AC:M/Au:S/C:P/I:P/A:N)	3	Low
(AV:L/AC:M/Au:S/C:P/I:P/A:P)	4.1	Medium
(AV:L/AC:M/Au:S/C:P/I:P/A:C)	5.5	Medium
(AV:L/AC:M/Au:S/C:P/I:C/A:N)	5	Medium
(AV:L/AC:M/Au:S/C:P/I:C/A:P)	5.5	Medium
(AV:L/AC:M/Au:S/C:P/I:C/A:C)	6.2	Medium
(AV:L/AC:M/Au:S/C:C/I:N/A:N)	4.4	Medium
(AV:L/AC:M/Au:S/C:C/I:N/A:P)	5	Medium
(AV:L/AC:M/Au:S/C:C/I:N/A:C)	6	Medium
(AV:L/AC:M/Au:S/C:C/I:P/A:N)	5	Medium
(AV:L/AC:M/Au:S/C:C/I:P/A:P)	5.5	Medium
(AV:L/AC:M/Au:S/C:C/I:P/A:C)	6.2	Medium
(AV:L/AC:M/Au:S/C:C/I:C/A:N)	6	Medium
(AV:L/AC:M/Au:S/C:C/I:C/A:P)	6.2	Medium
(AV:L/AC:M/Au:S/C:C/I:C/A:C)	6.6	Medium
(AV:L/AC:M/Au:M/C:N/I:N/A:N)	0	Low
(AV:L/AC:M/Au:M/C:N/I:N/A:P)	1.3	Low
(AV:L/AC:M/Au:M/C:N/I:N/A:C)	4.1	Medium
(AV:L/AC:M/Au:M/C:N/I:P/A:N)	1.3	Low
(AV:L/AC:M/Au:M/C:N/I:P/A:P)	2.7	Low
(AV:L/AC:M/Au:M/C:N/I:P/A:C)	4.8	Medium
(AV:L/AC:M/Au:M/C:N/I:C/A:N)	4.1	Medium
(AV:L/AC:M/Au:M/C:N/I:C/A:P)	4.8	Medium
(AV:L/AC:M/Au:M/C:N/I:C/A:C)	5.8	Medium
(AV:L/AC:M/Au:M/C:P/I:N/A:N)	1.3	Low
(AV:L/AC:M/Au:M/C:P/I:N/A:P)	2.7	Low
(AV:L/AC:M/Au:M/C:P/I:N/A:C)	4.8	Medium
(AV:L/AC:M/Au:M/C:P/I:P/A:N)	2.7	Low
(AV:L/AC:M/Au:M/C:P/I:P/A:P)	3.8	Low
(AV:L/AC:M/Au:M/C:P/I:P/A:C)	5.3	Medium
(AV:L/AC:M/Au:M/C:P/I:C/A:N)	4.8	Medium
(AV:L/AC:M/Au:M/C:P/I:C/A:P)	5.3	Medium
(AV:L/AC:M/Au:M/C:P/I:C/A:C)	6	Medium
(AV:L/AC:M/Au:M/C:C/I:N/A:N)	4.1	Medium
(AV:L/AC:M/Au:M/C:C/I:N/A:P)	4.8	Medium
(AV:L/AC:M/Au:M/C:C/I:N/A:C)	5.8	Medium
(AV:L/AC:M/Au:M/C:C/I:P/A:N)	4.8	Medium
(AV:L/AC:M/Au:M/C:C/I:P/A:P)	5.3	Medium
(AV:L/AC:M/Au:M/C:C/I:P/A:C)	6	Medium
(AV:L/AC:M/Au:M/C:C/I:C/A:N)	5.8	Medium
(AV:L/AC:M/Au:M/C:C/I:C/A:P)	6	Medium
(AV:L/AC:M/Au:M/C:C/I:C/A:C)	6.3	Medium
(AV:L/AC:L/Au:N/C:N/I:N/A:N)	0	Low
(AV:L/AC:L/Au:N/C:N/I:N/A:P)	2.1	Low
(AV:L/AC:L/Au:N/C:N/I:N/A:C)	4.9	Medium
(AV:L/AC:L/Au:N/C:N/I:P/A:N)	2.1	Low
(AV:L/AC:L/Au:N/C:N/I:P/A:P)	3.6	Low
(AV:L/AC:L/Au:N/C:N/I:P/A:C)	5.6	Medium
(AV:L/AC:L/Au:N/C:N/I:C/A:N)	4.9	Medium
(AV:L/AC:L/Au:N/C:N/I:C/A:P)	5.6	Medium
(AV:L/AC:L/Au:N/C:N/I:C/A:C)	6.6	Medium
(AV:L/AC:L/Au:N/C:P/I:N/A:N)	2.1	Low
(AV:L/AC:L/Au:N/C:P/I:N/A:P)	3.6	Low
(AV:L/AC:L/Au:N/C:P/I:N/A:C)	5.6	Medium
(AV:L/AC:L/Au:N/C:P/I:P/A:N)	3.6	Low
(AV:L/AC:L/Au:N/C:P/I:P/A:P)	4.6	Medium
(AV:L/AC:L/Au:N/C:P/I:P/A:C)	6.1	Medium
(AV:L/AC:L/Au:N/C:P/I:C/A:N)	5.6	Medium
(AV:L/AC:L/Au:N/C:P/I:C/A:P)	6.1	Medium
(AV:L/AC:L/Au:N/C:P/I:C/A:C)	6.8	Medium
(AV:L/AC:L/Au:N/C:C/I:N/A:N)	4.9	Medium
(AV:L/AC:L/Au:N/C:C/I:N/A:P)	5.6	Medium
(AV:L/AC:L/Au:N/C:C/I:N/A:C)	6.6	Medium
(AV:L/AC:L/Au:N/C:C/I:P/A:N)	5.6	Medium
(AV:L/AC:L/Au:N/C:C/I:P/A:P)	6.1	Medium
(AV:L/AC:L/Au:N/C:C/I:P/A:C)	6.8	Medium
(AV:L/AC:L/Au:N/C:C/I:C/A:N)	6.6	Medium
(AV:L/AC:L/Au:N/C:C/I:C/A:P)	6.8	Medium
(AV:L/AC:L/Au:N/C:C/I:C/A:C)	7.2	High
(AV:L/AC:L/Au:S/C:N/I:N/A:N)	0	Low
(AV:L/AC:L/Au:S/C:N/I:N/A:P)	1.7	Low
(AV:L/AC:L/Au:S/C:N/I:N/A:C)	4.6	Medium
(AV:L/AC:L/Au:S/C:N/I:P/A:N)	1.7	Low
(AV:L/AC:L/Au:S/C:N/I:P/A:P)	3.2	Low
(AV:L/AC:L/Au:S/C:N/I:P/A:C)	5.2	Medium
(AV:L/AC:L/Au:S/C:N/I:C/A:N)	4.6	Medium
(AV:L/AC:L/Au:S/C:N/I:C/A:P)	5.2	Medium
(AV:L/AC:L/Au:S/C:N/I:C/A:C)	6.2	Medium
(AV:L/AC:L/Au:S/C:P/I:N/A:N)	1.7	Low
(AV:L/AC:L/Au:S/C:P/I:N/A:P)	3.2	Low
(AV:L/AC:L/Au:S/C:P/I:N/A:C)	5.2	Medium
(AV:L/AC:L/Au:S/C:P/I:P/A:N)	3.2	Low
(AV:L/AC:L/Au:S/C:P/I:P/A:P)	4.3	Medium
(AV:L/AC:L/Au:S/C:P/I:P/A:C)	5.7	Medium
(AV:L/AC:L/Au:S/C:P/I:C/A:N)	5.2	Medium
(AV:L/AC:L/Au:S/C:P/I:C/A:P)	5.7	Medium
(AV:L/AC:L/Au:S/C:P/I:C/A:C)	6.4	Medium
(AV:L/AC:L/Au:S/C:C/I:N/A:N)	4.6	Medium
(AV:L/AC:L/Au:S/C:C/I:N/A:P)	5.2	Medium
(AV:L/AC:L/Au:S/C:C/I:N/A:C)	6.2	Medium
(AV:L/AC:L/Au:S/C:C/I:P/A:N)	5.2	Medium
(AV:L/AC:L/Au:S/C:C/I:P/A:P)	5.7	Medium
(AV:L/AC:L/Au:S/C:C/I:P/A:C)	6.4	Medium
(AV:L/AC:L/Au:S/C:C/I:C/A:N)	6.2	Medium
(AV:L/AC:L/Au:S/C:C/I:C/A:P)	6.4	Medium
(AV:L/AC:L/Au:S/C:C/I:C/A:C)	6.8	Medium
(AV:L/AC:L/Au:M/C:N/I:N/A:N)	0	Low
(AV:L/AC:L/Au:M/C:N/I:N/A:P)	1.4	Low
(AV:L/AC:L/Au:M/C:N/I:N/A:C)	4.3	Medium
(AV:L/AC:L/Au:M/C:N/I:P/A:N)	1.4	Low
(AV:L/AC:L/Au:M/C:N/I:P/A:P)	2.9	Low
(AV:L/AC:L/Au:M/C:N/I:P/A:C)	5	Medium
(AV:L/AC:L/Au:M/C:N/I:C/A:N)	4.3	Medium
(AV:L/AC:L/Au:M/C:N/I:C/A:P)	5	Medium
(AV:L/AC:L/Au:M/C:N/I:C/A:C)	5.9	Medium
(AV:L/AC:L/Au:M/C:P/I:N/A:N)	1.4	Low
(AV:L/AC:L/Au:M/C:P/I:N/A:P)	2.9	Low
(AV:L/AC:L/Au:M/C:P/I:N/A:C)	5	Medium
(AV:L/AC:L/Au:M/C:P/I:P/A:N)	2.9	Low
(AV:L/AC:L/Au:M/C:P/I:P/A:P)	4	Medium
(AV:L/AC:L/Au:M/C:P/I:P/A:C)	5.5	Medium
(AV:L/AC:L/Au:M/C:P/I:C/A:N)	5	Medium
(AV:L/AC:L/Au:M/C:P/I:C/A:P)	5.5	Medium
(AV:L/AC:L/Au:M/C:P/I:C/A:C)	6.2	Medium
(AV:L/AC:L/Au:M/C:C/I:N/A:N)	4.3	Medium
(AV:L/AC:L/Au:M/C:C/I:N/A:P)	5	Medium
(AV:L/AC:L/Au:M/C:C/I:N/A:C)	5.9	Medium
(AV:L/AC:L/Au:M/C:C/I:P/A:N)	5	Medium
(AV:L/AC:L/Au:M/C:C/I:P/A:P)	5.5	Medium
(AV:L/AC:L/Au:M/C:C/I:P/A:C)	6.2	Medium
(AV:L/AC:L/Au:M/C:C/I:C/A:N)	5.9	Medium
(AV:L/AC:L/Au:M/C:C/I:C/A:P)	6.2	Medium
(AV:L/AC:L/Au:M/C:C/I:C/A:C)	6.5	Medium
(AV:A/AC:H/Au:N/C:N/I:N/A:N)	0	Low
(AV:A/AC:H/Au:N/C:N/I:N/A:P)	1.8	Low
(AV:A/AC:H/Au:N/C:N/I:N/A:C)	4.6	Medium
(AV:A/AC:H/Au:N/C:N/I:P/A:N)	1.8	Low
(AV:A/AC:H/Au:N/C:N/I:P/A:P)	3.2	Low
(AV:A/AC:H/Au:N/C:N/I:P/A:C)	5.3	Medium
(AV:A/AC:H/Au:N/C:N/I:C/A:N)	4.6	Medium
(AV:A/AC:H/Au:N/C:N/I:C/A:P)	5.3	Medium
(AV:A/AC:H/Au:N/C:N/I:C/A:C)	6.2	Medium
(AV:A/AC:H/Au:N/C:P/I:N/A:N)	1.8	Low
(AV:A/AC:H/Au:N/C:P/I:N/A:P)	3.2	Low
(AV:A/AC:H/Au:N/C:P/I:N/A:C)	5.3	Medium
(AV:A/AC:H/Au:N/C:P/I:P/A:N)	3.2	Low
(AV:A/AC:H/Au:N/C:P/I:P/A:P)	4.3	Medium
(AV:A/AC:H/Au:N/C:P/I:P/A:C)	5.8	Medium
(AV:A/AC:H/Au:N/C:P/I:C/A:N)	5.3	Medium
(AV:A/AC:H/Au:N/C:P/I:C/A:P)	5.8	Medium
(AV:A/AC:H/Au:N/C:P/I:C/A:C)	6.5	Medium
(AV:A/AC:H/Au:N/C:C/I:N/A:N)	4.6	Medium
(AV:A/AC:H/Au:N/C:C/I:N/A:P)	5.3	Medium
(AV:A/AC:H/Au:N/C:C/I:N/A:C)	6.2	Medium
(AV:A/AC:H/Au:N/C:C/I:P/A:N)	5.3	Medium
(AV:A/AC:H/Au:N/C:C/I:P/A:P)	5.8	Medium
(AV:A/AC:H/Au:N/C:C/I:P/A:C)	6.5	Medium
(AV:A/AC:H/Au:N/C:C/I:C/A:N)	6.2	Medium
(AV:A/AC:H/Au:N/C:C/I:C/A:P)	6.5	Medium
(AV:A/AC:H/Au:N/C:C/I:C/A:C)	6.8	Medium
(AV:A/AC:H/Au:S/C:N/I:N/A:N)	0	Low
(AV:A/AC:H/Au:S/C:N/I:N/A:P)	1.4	Low
(AV:A/AC:H/Au:S/C:N/I:N/A:C)	4.3	Medium
(AV:A/AC:H/Au:S/C:N/I:P/A:N)	1.4	Low
(AV:A/AC:H/Au:S/C:N/I:P/A:P)	2.9	Low
(AV:A/AC:H/Au:S/C:N/I:P/A:C)	5	Medium
(AV:A/AC:H/Au:S/C:N/I:C/A:N)	4.3	Medium
(AV:A/AC:H/Au:S/C:N/I:C/A:P)	5	Medium
(AV:A/AC:H/Au:S/C:N/I:C/A:C)	5.9	Medium
(AV:A/AC:H/Au:S/C:P/I:N/A:N)	1.4	Low
(AV:A/AC:H/Au:S/C:P/I:N/A:P)	2.9	Low
(AV:A/AC:H/Au:S/C:P/I:N/A:C)	5	Medium
(AV:A/AC:H/Au:S/C:P/I:P/A:N)	2.9	Low
(AV:A/AC:H/Au:S/C:P/I:P/A:P)	4	Medium
(AV:A/AC:H/Au:S/C:P/I:P/A:C)	5.5	Medium
(AV:A/AC:H/Au:S/C:P/I:C/A:N)	5	Medium
(AV:A/AC:H/Au:S/C:P/I:C/A:P)	5.5	Medium
(AV:A/AC:H/Au:S/C:P/I:C/A:C)	6.2	Medium
(AV:A/AC:H/Au:S/C:C/I:N/A:N)	4.3	Medium
(AV:A/AC:H/Au:S/C:C/I:N/A:P)	5	Medium
(AV:A/AC:H/Au:S/C:C/I:N/A:C)	5.9	Medium
(AV:A/AC:H/Au:S/C:C/I:P/A:N)	5	Medium
(AV:A/AC:H/Au:S/C:C/I:P/A:P)	5.5	Medium
(AV:A/AC:H/Au:S/C:C/I:P/A:C)	6.2	Medium
(AV:A/AC:H/Au:S/C:C/I:C/A:N)	5.9	Medium
(AV:A/AC:H/Au:S/C:C/I:C/A:P)	6.2	Medium
(AV:A/AC:H/Au:S/C:C/I:C/A:C)	6.5	Medium
(AV:A/AC:H/Au:M/C:N/I:N/A:N)	0	Low
(AV:A/AC:H/Au:M/C:N/I:N/A:P)	1.2	Low
(AV:A/AC:H/Au:M/C:N/I:N/A:C)	4	Medium
(AV:A/AC:H/Au:M/C:N/I:P/A:N)	1.2	Low
(AV:A/AC:H/Au:M/C:N/I:P/A:P)	2.7	Low
(AV:A/AC:H/Au:M/C:N/I:P/A:C)	4.7	Medium
(AV:A/AC:H/Au:M/C:N/I:C/A:N)	4	Medium
(AV:A/AC:H/Au:M/C:N/I:C/A:P)	4.7	Medium
(AV:A/AC:H/Au:M/C:N/I:C/A:C)	5.7	Medium
(AV:A/AC:H/Au:M/C:P/I:N/A:N)	1.2	Low
(AV:A/AC:H/Au:M/C:P/I:N/A:P)	2.7	Low
(AV:A/AC:H/Au:M/C:P/I:N/A:C)	4.7	Medium
(AV:A/AC:H/Au:M/C:P/I:P/A:N)	2.7	Low
(AV:A/AC:H/Au:M/C:P/I:P/A:P)	3.7	Low
(AV:A/AC:H/Au:M/C:P/I:P/A:C)	5.2	Medium
(AV:A/AC:H/Au:M/C:P/I:C/A:N)	4.7	Medium
(AV:A/AC:H/Au:M/C:P/I:C/A:P)	5.2	Medium
(AV:A/AC:H/Au:M/C:P/I:C/A:C)	5.9	Medium
(AV:A/AC:H/Au:M/C:C/I:N/A:N)	4	Medium
(AV:A/AC:H/Au:M/C:C/I:N/A:P)	4.7	Medium
(AV:A/AC:H/Au:M/C:C/I:N/A:C)	5.7	Medium
(AV:A/AC:H/Au:M/C:C/I:P/A:N)	4.7	Medium
(AV:A/AC:H/Au:M/C:C/I:P/A:P)	5.2	Medium
(AV:A/AC:H/Au:M/C:C/I:P/A:C)	5.9	Medium
(AV:A/AC:H/Au:M/C:C/I:C/A:N)	5.7	Medium
(AV:A/AC:H/Au:M/C:C/I:C/A:P)	5.9	Medium
(AV:A/AC:H/Au:M/C:C/I:C/A:C)	6.2	Medium
(AV:A/AC:M/Au:N/C:N/I:N/A:N)	0	Low
(AV:A/AC:M/Au:N/C:N/I:N/A:P)	2.9	Low
(AV:A/AC:M/Au:N/C:N/I:N/A:C)	5.7	Medium
(AV:A/AC:M/Au:N/C:N/I:P/A:N)	2.9	Low
(AV:A/AC:M/Au:N/C:N/I:P/A:P)	4.3	Medium
(AV:A/AC:M/Au:N/C:N/I:P/A:C)	6.4	Medium
(AV:A/AC:M/Au:N/C:N/I:C/A:N)	5.7	Medium
(AV:A/AC:M/Au:N/C:N/I:C/A:P)	6.4	Medium
(AV:A/AC:M/Au:N/C:N/I:C/A:C)	7.3	High
(AV:A/AC:M/Au:N/C:P/I:N/A:N)	2.9	Low
(AV:A/AC:M/Au:N/C:P/I:N/A:P)	4.3	Medium
(AV:A/AC:M/Au:N/C:P/I:N/A:C)	6.4	Medium
(AV:A/AC:M/Au:N/C:P/I:P/A:N)	4.3	Medium
(AV:A/AC:M/Au:N/C:P/I:P/A:P)	5.4	Medium
(AV:A/AC:M/Au:N/C:P/I:P/A:C)	6.9	Medium
(AV:A/AC:M/Au:N/C:P/I:C/A:N)	6.4	Medium
(AV:A/AC:M/Au:N/C:P/I:C/A:P)	6.9	Medium
(AV:A/AC:M/Au:N/C:P/I:C/A:C)	7.6	High
(AV:A/AC:M/Au:N/C:C/I:N/A:N)	5.7	Medium
(AV:A/AC:M/Au:N/C:C/I:N/A:P)	6.4	Medium
(AV:A/AC:M/Au:N/C:C/I:N/A:C)	7.3	High
(AV:A/AC:M/Au:N/C:C/I:P/A:N)	6.4	Medium
(AV:A/AC:M/Au:N/C:C/I:P/A:P)	6.9	Medium
(AV:A/AC:M/Au:N/C:C/I:P/A:C)	7.6	High
(AV:A/AC:M/Au:N/C:C/I:C/A:N)	7.3	High
(AV:A/AC:M/Au:N/C:C/I:C/A:P)	7.6	High
(AV:A/AC:M/Au:N/C:C/I:C/A:C)	7.9	High
(AV:A/AC:M/Au:S/C:N/I:N/A:N)	0	Low
(AV:A/AC:M/Au:S/C:N/I:N/A:P)	2.3	Low
(AV:A/AC:M/Au:S/C:N/I:N/A:C)	5.2	Medium
(AV:A/AC:M/Au:S/C:N/I:P/A:N)	2.3	Low
(AV:A/AC:M/Au:S/C:N/I:P/A:P)	3.8	Low
(AV:A/AC:M/Au:S/C:N/I:P/A:C)	5.8	Medium
(AV:A/AC:M/Au:S/C:N/I:C/A:N)	5.2	Medium
(AV:A/AC:M/Au:S/C:N/I:C/A:P)	5.8	Medium
(AV:A/AC:M/Au:S/C:N/I:C/A:C)	6.8	Medium
(AV:A/AC:M/Au:S/C:P/I:N/A:N)	2.3	Low
(AV:A/AC:M/Au:S/C:P/I:N/A:P)	3.8	Low
(AV:A/AC:M/Au:S/C:P/I:N/A:C)	5.8	Medium
(AV:A/AC:M/Au:S/C:P/I:P/A:N)	3.8	Low
(AV:A/AC:M/Au:S/C:P/I:P/A:P)	4.9	Medium
(AV:A/AC:M/Au:S/C:P/I:P/A:C)	6.3	Medium
(AV:A/AC:M/Au:S/C:P/I:C/A:N)	5.8	Medium
(AV:A/AC:M/Au:S/C:P/I:C/A:P)	6.3	Medium
(AV:A/AC:M/Au:S/C:P/I:C/A:C)	7	High
(AV:A/AC:M/Au:S/C:C/I:N/A:N)	5.2	Medium
(AV:A/AC:M/Au:S/C:C/I:N/A:P)	5.8	Medium
(AV:A/AC:M/Au:S/C:C/I:N/A:C)	6.8	Medium
(AV:A/AC:M/Au:S/C:C/I:P/A:N)	5.8	Medium
(AV:A/AC:M/Au:S/C:C/I:P/A:P)	6.3	Medium
(AV:A/AC:M/Au:S/C:C/I:P/A:C)	7	High
(AV:A/AC:M/Au:S/C:C/I:C/A:N)	6.8	Medium
(AV:A/AC:M/Au:S/C:C/I:C/A:P)	7	High
(AV:A/AC:M/Au:S/C:C/I:C/A:C)	7.4	High
(AV:A/AC:M/Au:M/C:N/I:N/A:N)	0	Low
(AV:A/AC:M/Au:M/C:N/I:N/A:P)	1.9	Low
(AV:A/AC:M/Au:M/C:N/I:N/A:C)	4.8	Medium
(AV:A/AC:M/Au:M/C:N/I:P/A:N)	1.9	Low
(AV:A/AC:M/Au:M/C:N/I:P/A:P)	3.4	Low
(AV:A/AC:M/Au:M/C:N/I:P/A:C)	5.4	Medium
(AV:A/AC:M/Au:M/C:N/I:C/A:N)	4.8	Medium
(AV:A/AC:M/Au:M/C:N/I:C/A:P)	5.4	Medium
(AV:A/AC:M/Au:M/C:N/I:C/A:C)	6.4	Medium
(AV:A/AC:M/Au:M/C:P/I:N/A:N)	1.9	Low
(AV:A/AC:M/Au:M/C:P/I:N/A:P)	3.4	Low
(AV:A/AC:M/Au:M/C:P/I:N/A:C)	5.4	Medium
(AV:A/AC:M/Au:M/C:P/I:P/A:N)	3.4	Low
(AV:A/AC:M/Au:M/C:P/I:P/A:P)	4.5	Medium
(AV:A/AC:M/Au:M/C:P/I:P/A:C)	5.9	Medium
(AV:A/AC:M/Au:M/C:P/I:C/A:N)	5.4	Medium
(AV:A/AC:M/Au:M/C:P/I:C/A:P)	5.9	Medium
(AV:A/AC:M/Au:M/C:P/I:C/A:C)	6.6	Medium
(AV:A/AC:M/Au:M/C:C/I:N/A:N)	4.8	Medium
(AV:A/AC:M/Au:M/C:C/I:N/A:P)	5.4	Medium
(AV:A/AC:M/Au:M/C:C/I:N/A:C)	6.4	Medium
(AV:A/AC:M/Au:M/C:C/I:P/A:N)	5.4	Medium
(AV:A/AC:M/Au:M/C:C/I:P/A:P)	5.9	Medium
(AV:A/AC:M/Au:M/C:C/I:P/A:C)	6.6	Medium
(AV:A/AC:M/Au:M/C:C/I:C/A:N)	6.4	Medium
(AV:A/AC:M/Au:M/C:C/I:C/A:P)	6.6	Medium
(AV:A/AC:M/Au:M/C:C/I:C/A:C)	7	High
(AV:A/AC:L/Au:N/C:N/I:N/A:N)	0	Low
(AV:A/AC:L/Au:N/C:N/I:N/A:P)	3.3	Low
(AV:A/AC:L/Au:N/C:N/I:N/A:C)	6.1	Medium
(AV:A/AC:L/Au:N/C:N/I:P/A:N)	3.3	Low
(AV:A/AC:L/Au:N/C:N/I:P/A:P)	4.8	Medium
(AV:A/AC:L/Au:N/C:N/I:P/A:C)	6.8	Medium
(AV:A/AC:L/Au:N/C:N/I:C/A:N)	6.1	Medium
(AV:A/AC:L/Au:N/C:N/I:C/A:P)	6.8	Medium
(AV:A/AC:L/Au:N/C:N/I:C/A:C)	7.8	High
(AV:A/AC:L/Au:N/C:P/I:N/A:N)	3.3	Low
(AV:A/AC:L/Au:N/C:P/I:N/A:P)	4.8	Medium
(AV:A/AC:L/Au:N/C:P/I:N/A:C)	6.8	Medium
(AV:A/AC:L/Au:N/C:P/I:P/A:N)	4.8	Medium
(AV:A/AC:L/Au:N/C:P/I:P/A:P)	5.8	Medium
(AV:A/AC:L/Au:N/C:P/I:P/A:C)	7.3	High
(AV:A/AC:L/Au:N/C:P/I:C/A:N)	6.8	Medium
(AV:A/AC:L/Au:N/C:P/I:C/A:P)	7.3	High
(AV:A/AC:L/Au:N/C:P/I:C/A:C)	8	High
(AV:A/AC:L/Au:N/C:C/I:N/A:N)	6.1	Medium
(AV:A/AC:L/Au:N/C:C/I:N/A:P)	6.8	Medium
(AV:A/AC:L/Au:N/C:C/I:N/A:C)	7.8	High
(AV:A/AC:L/Au:N/C:C/I:P/A:N)	6.8	Medium
(AV:A/AC:L/Au:N/C:C/I:P/A:P)	7.3	High
(AV:A/AC:L/Au:N/C:C/I:P/A:C)	8	High
(AV:A/AC:L/Au:N/C:C/I:C/A:N)	7.8	High
(AV:A/AC:L/Au:N/C:C/I:C/A:P)	8	High
(AV:A/AC:L/Au:N/C:C/I:C/A:C)	8.3	High
(AV:A/AC:L/Au:S/C:N/I:N/A:N)	0	Low
(AV:A/AC:L/Au:S/C:N/I:N/A:P)	2.7	Low
(AV:A/AC:L/Au:S/C:N/I:N/A:C)	5.5	Medium
(AV:A/AC:L/Au:S/C:N/I:P/A:N)	2.7	Low
(AV:A/AC:L/Au:S/C:N/I:P/A:P)	4.1	Medium
(AV:A/AC:L/Au:S/C:N/I:P/A:C)	6.2	Medium
(AV:A/AC:L/Au:S/C:N/I:C/A:N)	5.5	Medium
(AV:A/AC:L/Au:S/C:N/I:C/A:P)	6.2	Medium
(AV:A/AC:L/Au:S/C:N/I:C/A:C)	7.1	High
(AV:A/AC:L/Au:S/C:P/I:N/A:N)	2.7	Low
(AV:A/AC:L/Au:S/C:P/I:N/A:P)	4.1	Medium
(AV:A/AC:L/Au:S/C:P/I:N/A:C)	6.2	Medium
(AV:A/AC:L/Au:S/C:P/I:P/A:N)	4.1	Medium
(AV:A/AC:L/Au:S/C:P/I:P/A:P)	5.2	Medium
(AV:A/AC:L/Au:S/C:P/I:P/A:C)	6.7	Medium
(AV:A/AC:L/Au:S/C:P/I:C/A:N)	6.2	Medium
(AV:A/AC:L/Au:S/C:P/I:C/A:P)	6.7	Medium
(AV:A/AC:L/Au:S/C:P/I:C/A:C)	7.4	High
(AV:A/AC:L/Au:S/C:C/I:N/A:N)	5.5	Medium
(AV:A/AC:L/Au:S/C:C/I:N/A:P)	6.2	Medium
(AV:A/AC:L/Au:S/C:C/I:N/A:C)	7.1	High
(AV:A/AC:L/Au:S/C:C/I:P/A:N)	6.2	Medium
(AV:A/AC:L/Au:S/C:C/I:P/A:P)	6.7	Medium
(AV:A/AC:L/Au:S/C:C/I:P/A:C)	7.4	High
(AV:A/AC:L/Au:S/C:C/I:C/A:N)	7.1	High
(AV:A/AC:L/Au:S/C:C/I:C/A:P)	7.4	High
(AV:A/AC:L/Au:S/C:C/I:C/A:C)	7.7	High
(AV:A/AC:L/Au:M/C:N/I:N/A:N)	0	Low
(AV:A/AC:L/Au:M/C:N/I:N/A:P)	2.2	Low
(AV:A/AC:L/Au:M/C:N/I:N/A:C)	5	Medium
(AV:A/AC:L/Au:M/C:N/I:P/A:N)	2.2	Low
(AV:A/AC:L/Au:M/C:N/I:P/A:P)	3.7	Low
(AV:A/AC:L/Au:M/C:N/I:P/A:C)	5.7	Medium
(AV:A/AC:L/Au:M/C:N/I:C/A:N)	5	Medium
(AV:A/AC:L/Au:M/C:N/I:C/A:P)	5.7	Medium
(AV:A/AC:L/Au:M/C:N/I:C/A:C)	6.7	Medium
(AV:A/AC:L/Au:M/C:P/I:N/A:N)	2.2	Low
(AV:A/AC:L/Au:M/C:P/I:N/A:P)	3.7	Low
(AV:A/AC:L/Au:M/C:P/I:N/A:C)	5.7	Medium
(AV:A/AC:L/Au:M/C:P/I:P/A:N)	3.7	Low
(AV:A/AC:L/Au:M/C:P/I:P/A:P)	4.7	Medium
(AV:A/AC:L/Au:M/C:P/I:P/A:C)	6.2	Medium
(AV:A/AC:L/Au:M/C:P/I:C/A:N)	5.7	Medium
(AV:A/AC:L/Au:M/C:P/I:C/A:P)	6.2	Medium
(AV:A/AC:L/Au:M/C:P/I:C/A:C)	6.9	Medium
(AV:A/AC:L/Au:M/C:C/I:N/A:N)	5	Medium
(AV:A/AC:L/Au:M/C:C/I:N/A:P)	5.7	Medium
(AV:A/AC:L/Au:M/C:C/I:N/A:C)	6.7	Medium
(AV:A/AC:L/Au:M/C:C/I:P/A:N)	5.7	Medium
(AV:A/AC:L/Au:M/C:C/I:P/A:P)	6.2	Medium
(AV:A/AC:L/Au:M/C:C/I:P/A:C)	6.9	Medium
(AV:A/AC:L/Au:M/C:C/I:C/A:N)	6.7	Medium
(AV:A/AC:L/Au:M/C:C/I:C/A:P)	6.9	Medium
(AV:A/AC:L/Au:M/C:C/I:C/A:C)	7.2	High
(AV:N/AC:H/Au:N/C:N/I:N/A:N)	0	Low
(AV:N/AC:H/Au:N/C:N/I:N/A:P)	2.6	Low
(AV:N/AC:H/Au:N/C:N/I:N/A:C)	5.4	Medium
(AV:N/AC:H/Au:N/C:N/I:P/A:N)	2.6	Low
(AV:N/AC:H/Au:N/C:N/I:P/A:P)	4	Medium
(AV:N/AC:H/Au:N/C:N/I:P/A:C)	6.1	Medium
(AV:N/AC:H/Au:N/C:N/I:C/A:N)	5.4	Medium
(AV:N/AC:H/Au:N/C:N/I:C/A:P)	6.1	Medium
(AV:N/AC:H/Au:N/C:N/I:C/A:C)	7.1	High
(AV:N/AC:H/Au:N/C:P/I:N/A:N)	2.6	Low
(AV:N/AC:H/Au:N/C:P/I:N/A:P)	4	Medium
(AV:N/AC:H/Au:N/C:P/I:N/A:C)	6.1	Medium
(AV:N/AC:H/Au:N/C:P/I:P/A:N)	4	Medium
(AV:N/AC:H/Au:N/C:P/I:P/A:P)	5.1	Medium
(AV:N/AC:H/Au:N/C:P/I:P/A:C)	6.6	Medium
(AV:N/AC:H/Au:N/C:P/I:C/A:N)	6.1	Medium
(AV:N/AC:H/Au:N/C:P/I:C/A:P)	6.6	Medium
(AV:N/AC:H/Au:N/C:P/I:C/A:C)	7.3	High
(AV:N/AC:H/Au:N/C:C/I:N/A:N)	5.4	Medium
(AV:N/AC:H/Au:N/C:C/I:N/A:P)	6.1	Medium
(AV:N/AC:H/Au:N/C:C/I:N/A:C)	7.1	High
(AV:N/AC:H/Au:N/C:C/I:P/A:N)	6.1	Medium
(AV:N/AC:H/Au:N/C:C/I:P/A:P)	6.6	Medium
(AV:N/AC:H/Au:N/C:C/I:P/A:C)	7.3	High
(AV:N/AC:H/Au:N/C:C/I:C/A:N)	7.1	High
(AV:N/AC:H/Au:N/C:C/I:C/A:P)	7.3	High
(AV:N/AC:H/Au:N/C:C/I:C/A:C)	7.6	High
(AV:N/AC:H/Au:S/C:N/I:N/A:N)	0	Low
(AV:N/AC:H/Au:S/C:N/I:N/A:P)	2.1	Low
(AV:N/AC:H/Au:S/C:N/I:N/A:C)	4.9	Medium
(AV:N/AC:H/Au:S/C:N/I:P/A:N)	2.1	Low
(AV:N/AC:H/Au:S/C:N/I:P/A:P)	3.6	Low
(AV:N/AC:H/Au:S/C:N/I:P/A:C)	5.6	Medium
(AV:N/AC:H/Au:S/C:N/I:C/A:N)	4.9	Medium
(AV:N/AC:H/Au:S/C:N/I:C/A:P)	5.6	Medium
(AV:N/AC:H/Au:S/C:N/I:C/A:C)	6.6	Medium
(AV:N/AC:H/Au:S/C:P/I:N/A:N)	2.1	Low
(AV:N/AC:H/Au:S/C:P/I:N/A:P)	3.6	Low
(AV:N/AC:H/Au:S/C:P/I:N/A:C)	5.6	Medium
(AV:N/AC:H/Au:S/C:P/I:P/A:N)	3.6	Low
(AV:N/AC:H/Au:S/C:P/I:P/A:P)	4.6	Medium
(AV:N/AC:H/Au:S/C:P/I:P/A:C)	6.1	Medium
(AV:N/AC:H/Au:S/C:P/I:C/A:N)	5.6	Medium
(AV:N/AC:H/Au:S/C:P/I:C/A:P)	6.1	Medium
(AV:N/AC:H/Au:S/C:P/I:C/A:C)	6.8	Medium
(AV:N/AC:H/Au:S/C:C/I:N/A:N)	4.9	Medium
(AV:N/AC:H/Au:S/C:C/I:N/A:P)	5.6	Medium
(AV:N/AC:H/Au:S/C:C/I:N/A:C)	6.6	Medium
(AV:N/AC:H/Au:S/C:C/I:P/A:N)	5.6	Medium
(AV:N/AC:H/Au:S/C:C/I:P/A:P)	6.1	Medium
(AV:N/AC:H/Au:S/C:C/I:P/A:C)	6.8	Medium
(AV:N/AC:H/Au:S/C:C/I:C/A:N)	6.6	Medium
(AV:N/AC:H/Au:S/C:C/I:C/A:P)	6.8	Medium
(AV:N/AC:H/Au:S/C:C/I:C/A:C)	7.1	High
(AV:N/AC:H/Au:M/C:N/I:N/A:N)	0	Low
(AV:N/AC:H/Au:M/C:N/I:N/A:P)	1.7	Low
(AV:N/AC:H/Au:M/C:N/I:N/A:C)	4.6	Medium
(AV:N/AC:H/Au:M/C:N/I:P/A:N)	1.7	Low
(AV:N/AC:H/Au:M/C:N/I:P/A:P)	3.2	Low
(AV:N/AC:H/Au:M/C:N/I:P/A:C)	5.3	Medium
(AV:N/AC:H/Au:M/C:N/I:C/A:N)	4.6	Medium
(AV:N/AC:H/Au:M/C:N/I:C/A:P)	5.3	Medium
(AV:N/AC:H/Au:M/C:N/I:C/A:C)	6.2	Medium
(AV:N/AC:H/Au:M/C:P/I:N/A:N)	1.7	Low
(AV:N/AC:H/Au:M/C:P/I:N/A:P)	3.2	Low
(AV:N/AC:H/Au:M/C:P/I:N/A:C)	5.3	Medium
(AV:N/AC:H/Au:M/C:P/I:P/A:N)	3.2	Low
(AV:N/AC:H/Au:M/C:P/I:P/A:P)	4.3	Medium
(AV:N/AC:H/Au:M/C:P/I:P/A:C)	5.8	Medium
(AV:N/AC:H/Au:M/C:P/I:C/A:N)	5.3	Medium
(AV:N/AC:H/Au:M/C:P/I:C/A:P)	5.8	Medium
(AV:N/AC:H/Au:M/C:P/I:C/A:C)	6.4	Medium
(AV:N/AC:H/Au:M/C:C/I:N/A:N)	4.6	Medium
(AV:N/AC:H/Au:M/C:C/I:N/A:P)	5.3	Medium
(AV:N/AC:H/Au:M/C:C/I:N/A:C)	6.2	Medium
(AV:N/AC:H/Au:M/C:C/I:P/A:N)	5.3	Medium
(AV:N/AC:H/Au:M/C:C/I:P/A:P)	5.8	Medium
(AV:N/AC:H/Au:M/C:C/I:P/A:C)	6.4	Medium
(AV:N/AC:H/Au:M/C:C/I:C/A:N)	6.2	Medium
(AV:N/AC:H/Au:M/C:C/I:C/A:P)	6.4	Medium
(AV:N/AC:H/Au:M/C:C/I:C/A:C)	6.8	Medium
(AV:N/AC:M/Au:N/C:N/I:N/A:N)	0	Low
(AV:N/AC:M/Au:N/C:N/I:N/A:P)	4.3	Medium
(AV:N/AC:M/Au:N/C:N/I:N/A:C)	7.1	High
(AV:N/AC:M/Au:N/C:N/I:P/A:N)	4.3	Medium
(AV:N/AC:M/Au:N/C:N/I:P/A:P)	5.8	Medium
(AV:N/AC:M/Au:N/C:N/I:P/A:C)	7.8	High
(AV:N/AC:M/Au:N/C:N/I:C/A:N)	7.1	High
(AV:N/AC:M/Au:N/C:N/I:C/A:P)	7.8	High
(AV:N/AC:M/Au:N/C:N/I:C/A:C)	8.8	High
(AV:N/AC:M/Au:N/C:P/I:N/A:N)	4.3	Medium
(AV:N/AC:M/Au:N/C:P/I:N/A:P)	5.8	Medium
(AV:N/AC:M/Au:N/C:P/I:N/A:C)	7.8	High
(AV:N/AC:M/Au:N/C:P/I:P/A:N)	5.8	Medium
(AV:N/AC:M/Au:N/C:P/I:P/A:P)	6.8	Medium
(AV:N/AC:M/Au:N/C:P/I:P/A:C)	8.3	High
(AV:N/AC:M/Au:N/C:P/I:C/A:N)	7.8	High
(AV:N/AC:M/Au:N/C:P/I:C/A:P)	8.3	High
(AV:N/AC:M/Au:N/C:P/I:C/A:C)	9	High
(AV:N/AC:M/Au:N/C:C/I:N/A:N)	7.1	High
(AV:N/AC:M/Au:N/C:C/I:N/A:P)	7.8	High
(AV:N/AC:M/Au:N/C:C/I:N/A:C)	8.8	High
(AV:N/AC:M/Au:N/C:C/I:P/A:N)	7.8	High
(AV:N/AC:M/Au:N/C:C/I:P/A:P)	8.3	High
(AV:N/AC:M/Au:N/C:C/I:P/A:C)	9	High
(AV:N/AC:M/Au:N/C:C/I:C/A:N)	8.8	High
(AV:N/AC:M/Au:N/C:C/I:C/A:P)	9	High
(AV:N/AC:M/Au:N/C:C/I:C/A:C)	9.3	High
(AV:N/AC:M/Au:S/C:N/I:N/A:N)	0	Low
(AV:N/AC:M/Au:S/C:N/I:N/A:P)	3.5	Low
(AV:N/AC:M/Au:S/C:N/I:N/A:C)	6.3	Medium
(AV:N/AC:M/Au:S/C:N/I:P/A:N)	3.5	Low
(AV:N/AC:M/Au:S/C:N/I:P/A:P)	4.9	Medium
(AV:N/AC:M/Au:S/C:N/I:P/A:C)	7	High
(AV:N/AC:M/Au:S/C:N/I:C/A:N)	6.3	Medium
(AV:N/AC:M/Au:S/C:N/I:C/A:P)	7	High
(AV:N/AC:M/Au:S/C:N/I:C/A:C)	7.9	High
(AV:N/AC:M/Au:S/C:P/I:N/A:N)	3.5	Low
(AV:N/AC:M/Au:S/C:P/I:N/A:P)	4.9	Medium
(AV:N/AC:M/Au:S/C:P/I:N/A:C)	7	High
(AV:N/AC:M/Au:S/C:P/I:P/A:N)	4.9	Medium
(AV:N/AC:M/Au:S/C:P/I:P/A:P)	6	Medium
(AV:N/AC:M/Au:S/C:P/I:P/A:C)	7.5	High
(AV:N/AC:M/Au:S/C:P/I:C/A:N)	7	High
(AV:N/AC:M/Au:S/C:P/I:C/A:P)	7.5	High
(AV:N/AC:M/Au:S/C:P/I:C/A:C)	8.2	High
(AV:N/AC:M/Au:S/C:C/I:N/A:N)	6.3	Medium
(AV:N/AC:M/Au:S/C:C/I:N/A:P)	7	High
(AV:N/AC:M/Au:S/C:C/I:N/A:C)	7.9	High
(AV:N/AC:M/Au:S/C:C/I:P/A:N)	7	High
(AV:N/AC:M/Au:S/C:C/I:P/A:P)	7.5	High
(AV:N/AC:M/Au:S/C:C/I:P/A:C)	8.2	High
(AV:N/AC:M/Au:S/C:C/I:C/A:N)	7.9	High
(AV:N/AC:M/Au:S/C:C/I:C/A:P)	8.2	High
(AV:N/AC:M/Au:S/C:C/I:C/A:C)	8.5	High
(AV:N/AC:M/Au:M/C:N/I:N/A:N)	0	Low
(AV:N/AC:M/Au:M/C:N/I:N/A:P)	2.8	Low
(AV:N/AC:M/Au:M/C:N/I:N/A:C)	5.7	Medium
(AV:N/AC:M/Au:M/C:N/I:P/A:N)	2.8	Low
(AV:N/AC:M/Au:M/C:N/I:P/A:P)	4.3	Medium
(AV:N/AC:M/Au:M/C:N/I:P/A:C)	6.4	Medium
(AV:N/AC:M/Au:M/C:N/I:C/A:N)	5.7	Medium
(AV:N/AC:M/Au:M/C:N/I:C/A:P)	6.4	Medium
(AV:N/AC:M/Au:M/C:N/I:C/A:C)	7.3	High
(AV:N/AC:M/Au:M/C:P/I:N/A:N)	2.8	Low
(AV:N/AC:M/Au:M/C:P/I:N/A:P)	4.3	Medium
(AV:N/AC:M/Au:M/C:P/I:N/A:C)	6.4	Medium
(AV:N/AC:M/Au:M/C:P/I:P/A:N)	4.3	Medium
(AV:N/AC:M/Au:M/C:P/I:P/A:P)	5.4	Medium
(AV:N/AC:M/Au:M/C:P/I:P/A:C)	6.9	Medium
(AV:N/AC:M/Au:M/C:P/I:C/A:N)	6.4	Medium
(AV:N/AC:M/Au:M/C:P/I:C/A:P)	6.9	Medium
(AV:N/AC:M/Au:M/C:P/I:C/A:C)	7.5	High
(AV:N/AC:M/Au:M/C:C/I:N/A:N)	5.7	Medium
(AV:N/AC:M/Au:M/C:C/I:N/A:P)	6.4	Medium
(AV:N/AC:M/Au:M/C:C/I:N/A:C)	7.3	High
(AV:N/AC:M/Au:M/C:C/I:P/A:N)	6.4	Medium
(AV:N/AC:M/Au:M/C:C/I:P/A:P)	6.9	Medium
(AV:N/AC:M/Au:M/C:C/I:P/A:C)	7.5	High
(AV:N/AC:M/Au:M/C:C/I:C/A:N)	7.3	High
(AV:N/AC:M/Au:M/C:C/I:C/A:P)	7.5	High
(AV:N/AC:M/Au:M/C:C/I:C/A:C)	7.9	High
(AV:N/AC:L/Au:N/C:N/I:N/A:N)	0	Low
(AV:N/AC:L/Au:N/C:N/I:N/A:P)	5	Medium
(AV:N/AC:L/Au:N/C:N/I:N/A:C)	7.8	High
(AV:N/AC:L/Au:N/C:N/I:P/A:N)	5	Medium
(AV:N/AC:L/Au:N/C:N/I:P/A:P)	6.4	Medium
(AV:N/AC:L/Au:N/C:N/I:P/A:C)	8.5	High
(AV:N/AC:L/Au:N/C:N/I:C/A:N)	7.8	High
(AV:N/AC:L/Au:N/C:N/I:C/A:P)	8.5	High
(AV:N/AC:L/Au:N/C:N/I:C/A:C)	9.4	High
(AV:N/AC:L/Au:N/C:P/I:N/A:N)	5	Medium
(AV:N/AC:L/Au:N/C:P/I:N/A:P)	6.4	Medium
(AV:N/AC:L/Au:N/C:P/I:N/A:C)	8.5	High
(AV:N/AC:L/Au:N/C:P/I:P/A:N)	6.4	Medium
(AV:N/AC:L/Au:N/C:P/I:P/A:P)	7.5	High
(AV:N/AC:L/Au:N/C:P/I:P/A:C)	9	High
(AV:N/AC:L/Au:N/C:P/I:C/A:N)	8.5	High
(AV:N/AC:L/Au:N/C:P/I:C/A:P)	9	High
(AV:N/AC:L/Au:N/C:P/I:C/A:C)	9.7	High
(AV:N/AC:L/Au:N/C:C/I:N/A:N)	7.8	High
(AV:N/AC:L/Au:N/C:C/I:N/A:P)	8.5	High
(AV:N/AC:L/Au:N/C:C/I:N/A:C)	9.4	High
(AV:N/AC:L/Au:N/C:C/I:P/A:N)	8.5	High
(AV:N/AC:L/Au:N/C:C/I:P/A:P)	9	High
(AV:N/AC:L/Au:N/C:C/I:P/A:C)	9.7	High
(AV:N/AC:L/Au:N/C:C/I:C/A:N)	9.4	High
(AV:N/AC:L/Au:N/C:C/I:C/A:P)	9.7	High
(AV:N/AC:L/Au:N/C:C/I:C/A:C)	10	High
(AV:N/AC:L/Au:S/C:N/I:N/A:N)	0	Low
(AV:N/AC:L/Au:S/C:N/I:N/A:P)	4	Medium
(AV:N/AC:L/Au:S/C:N/I:N/A:C)	6.8	Medium
(AV:N/AC:L/Au:S/C:N/I:P/A:N)	4	Medium
(AV:N/AC:L/Au:S/C:N/I:P/A:P)	5.5	Medium
(AV:N/AC:L/Au:S/C:N/I:P/A:C)	7.5	High
(AV:N/AC:L/Au:S/C:N/I:C/A:N)	6.8	Medium
(AV:N/AC:L/Au:S/C:N/I:C/A:P)	7.5	High
(AV:N/AC:L/Au:S/C:N/I:C/A:C)	8.5	High
(AV:N/AC:L/Au:S/C:P/I:N/A:N)	4	Medium
(AV:N/AC:L/Au:S/C:P/I:N/A:P)	5.5	Medium
(AV:N/AC:L/Au:S/C:P/I:N/A:C)	7.5	High
(AV:N/AC:L/Au:S/C:P/I:P/A:N)	5.5	Medium
(AV:N/AC:L/Au:S/C:P/I:P/A:P)	6.5	Medium
(AV:N/AC:L/Au:S/C:P/I:P/A:C)	8	High
(AV:N/AC:L/Au:S/C:P/I:C/A:N)	7.5	High
(AV:N/AC:L/Au:S/C:P/I:C/A:P)	8	High
(AV:N/AC:L/Au:S/C:P/I:C/A:C)	8.7	High
(AV:N/AC:L/Au:S/C:C/I:N/A:N)	6.8	Medium
(AV:N/AC:L/Au:S/C:C/I:N/A:P)	7.5	High
(AV:N/AC:L/Au:S/C:C/I:N/A:C)	8.5	High
(AV:N/AC:L/Au:S/C:C/I:P/A:N)	7.5	High
(AV:N/AC:L/Au:S/C:C/I:P/A:P)	8	High
(AV:N/AC:L/Au:S/C:C/I:P/A:C)	8.7	High
(AV:N/AC:L/Au:S/C:C/I:C/A:N)	8.5	High
(AV:N/AC:L/Au:S/C:C/I:C/A:P)	8.7	High
(AV:N/AC:L/Au:S/C:C/I:C/A:C)	9	High
(AV:N/AC:L/Au:M/C:N/I:N/A:N)	0	Low
(AV:N/AC:L/Au:M/C:N/I:N/A:P)	3.3	Low
(AV:N/AC:L/Au:M/C:N/I:N/A:C)	6.1	Medium
(AV:N/AC:L/Au:M/C:N/I:P/A:N)	3.3	Low
(AV:N/AC:L/Au:M/C:N/I:P/A:P)	4.7	Medium
(AV:N/AC:L/Au:M/C:N/I:P/A:C)	6.5	Medium
(AV:N/AC:L/Au:M/C:N/I:C/A:N)	6.1	Medium
(AV:N/AC:L/Au:M/C:N/I:C/A:P)	6.5	Medium
(AV:N/AC:L/Au:M/C:N/I:C/A:C)	7.7	High
(AV:N/AC:L/Au:M/C:P/I:N/A:N)	3.3	Low
(AV:N/AC:L/Au:M/C:P/I:N/A:P)	4.7	Medium
(AV:N/AC:L/Au:M/C:P/I:N/A:C)	6.5	Medium
(AV:N/AC:L/Au:M/C:P/I:P/A:N)	4.7	Medium
(AV:N/AC:L/Au:M/C:P/I:P/A:P)	5.8	Medium
(AV:N/AC:L/Au:M/C:P/I:P/A:C)	7.3	High
(AV:N/AC:L/Au:M/C:P/I:C/A:N)	6.5	Medium
(AV:N/AC:L/Au:M/C:P/I:C/A:P)	7.3	High
(AV:N/AC:L/Au:M/C:P/I:C/A:C)	8	High
(AV:N/AC:L/Au:M/C:C/I:N/A:N)	6.1	Medium
(AV:N/AC:L/Au:M/C:C/I:N/A:P)	6.5	Medium
(AV:N/AC:L/Au:M/C:C/I:N/A:C)	7.7	High
(AV:N/AC:L/Au:M/C:C/I:P/A:N)	6.5	Medium
(AV:N/AC:L/Au:M/C:C/I:P/A:P)	7.3	High
(AV:N/AC:L/Au:M/C:C/I:P/A:C)	8	High
(AV:N/AC:L/Au:M/C:C/I:C/A:N)	7.7	High
(AV:N/AC:L/Au:M/C:C/I:C/A:P)	8	High
(AV:N/AC:L/Au:M/C:C/I:C/A:C)	8.3	High
EOF


###############################################################################
# Setup Defaults

fileheader='1323253913 1 '
localchecks="Host/local_checks_enabled=1"
output=-1
kb=$(mktemp /tmp/kb.XXXXXXXXXX)
a=0
b=1
x=0
alloncmd=0

echo "$fileheader$localchecks" > "$kb"

# read in normal options from command line
while getopts "s:n:d:l:v?" o
do
	case "$o" in
		s)     	system="$OPTARG";let a+=2;;
		n)	nasl="$OPTARG";let a+=2;cmdnasl=1;;
		d)     	nessus_dir="$OPTARG";let a+=2;cmddir=1;;
		l)     	output="$OPTARG";let a+=2;cmdout=1;;
		v)	printf "%s\n" "$nopc_version";exit 1;;

		[?])   	printf "%s\n" "$(usage)";
		exit 1;;
	esac
done

# State the version of nopc (use stderr so that it doesn't mess with piped output
printf "Version: %s\n" "$nopc_version" >&2;
        
# Parse all the other arguments into an array
for arg in "$@"
do
	if [ $b -gt  $a ]
	then
		args[$x]="$arg"
		let x++
	fi
	let b++
done

# checking to see if we have Nessus nasl in our path.
if [ ! -x "$nasl" ]
then
	printf "[!] Cannot find nasl (%b), pass as -n argument\n" "$nasl" >&2
	exit 1;
fi

# checking to see if we have a Nessus Directory
if [ ! -d "$nessus_dir" ]
then
	printf "[!] Cannot find Nessus plugin dir (%b), pass as -d argument\n" "$nessus_dir" >&2
	exit 1;
fi

# what output type?
if [ "$output" -eq -1 ]
then
        cmdout=1;getOutput >&2;
fi

# what system do you want?
while [ -z "$system_name" ]
do
	case "$system" in 
		1) printf "[+] AIX Selected\n">&2;setAIX>&2;;
		2) printf "[+] HP-UX Selected\n">&2;setHPUX>&2;;
		3) printf "[+] MacOS X Selected\n">&2;setOSX>&2;;
		4) printf "[+] Solaris (!11) Selected\n">&2;setSolaris>&2;;
		5) printf "[+] Debian Selected\n">&2;setDebian>&2;;
		6) printf "[+] FreeBSD Selected\n">&2;setFreeBSD>&2;;
		7) printf "[+] Gentoo Selected\n">&2;setGentoo>&2;;
		8) printf "[+] Mandrake Selected\n">&2;setMandrake>&2;;
		9) printf "[+] Redhat Selected\n">&2;setRedHat>&2;;
		10) printf "[+] Redhat (Centos) Selected\n">&2;setCentOS>&2;;
		11) printf "[+] Redhat (Fedora) Selected\n">&2;setFedora>&2;;
		12) printf "[+] Slackware Selected\n">&2;setSlackware>&2;;
		13) printf "[+] SuSE Selected\n">&2;setSuSE>&2;;
		14) printf "[+] Ubuntu Selected\n">&2;setUbuntu>&2;;
		15) printf "[+] Cisco IOS/ASA Selected\n">&2;setCisco>&2;;
		16) printf "[+] OpenSuSE Selected\n">&2;setOpenSuSE>&2;;
  		*) if [ ! -z "$system" ]; then printf "[!] Invalid System (%b) - try again\n" "$system" >&2;fi;getSystem >&2;;
	esac
done

# find the nasls to use
printf "[+] Locating Nasls\n" >&2
nasls=$(find "$nessus_dir" -iname "*$nessus_filematch*") 

# run the checker on your kb file.
if [ -z "$nasls" ]
then
	printf "[!] No Nasls found to test, check your Nessus dir is correct '%b'\n" "$nessus_dir"
	exit 1
fi

printf "[+] Checking for %s Missing Patches\n" "$(echo "$nasls" | wc -l)" >&2

# The following section used to print the nasl that produced the output.
# Quite slow as nasl run every time to get name that produced the output.
# '0' = Displays Outdated Packages only (Installed/Fixed Packages)
# '1' = Displays NASL name and Outdated Packages
# '2' = Displays Plugin ID, CVEs, CVSSv2 string, KB#, Description (in comma separated csv format)
# '3' = Displays Plugin ID, CVEs, CVSSv2 score, Severity, KB#, Description (in comma separated csv format)
# '4' = Displays Plugin ID, CVEs, CVSSv2 string, KB#, Description (in tab separated csv format)
# '5' = Displays Plugin ID, CVEs, CVSSv2 score, Severity, KB#, Description (in tab separated csv format)

#kb="/tmp/kb.123"

if [ "$output" -eq 0 ]
then
	# Run nasl quickly, lists packages no nasls.
	mp=$("$nasl" -k "$kb" $nasls)
	printf "%s\n" "$mp";
else
	# Print out header depending on output type:
	#
	if [ "$output" -eq 1 ]; then
		dumper="NOPC, $system_name";
		printf "%s\n" "$dumper";
	elif [ "$output" -eq 2 ]; then
		dumper="NOPC, $system_name"$'\n'"Plugin ID, CVE, CVSSv2 String, KB, Title"
		printf "%s\n" "$dumper";
	elif [ "$output" -eq 3 ]; then
		dumper="NOPC, $system_name"$'\n'"Plugin ID, CVE, CVSSv2, Severity, KB, Title"
		printf "%s\n" "$dumper";
	elif [ "$output" -eq 4 ]; then
		dumper="NOPC"$'\t'"$system_name"$'\n'"Plugin ID"$'\t'"CVE"$'\t'"CVSSv2"$'\t'"String"$'\t'"KB"$'\t'"Title"
		printf "%s\n" "$dumper";
	elif [ "$output" -eq 5 ]; then
		dumper="NOPC"$'\t'"$system_name"$'\n'"Plugin ID"$'\t'"CVE"$'\t'"CVSSv2"$'\t'"Severity"$'\t'"KB"$'\t'"Title"
		printf "%s\n" "$dumper";
	fi;

	echo "$nasls" | while read a;
	do
		# run nasl
		#echo "$nasl -k $kb $a"
		mp=$($nasl -k "$kb" "$a" | perl -p -e 's/\n//' | perl -p -e 's/Remote package/, Remote package/g' | perl -p -e 's/Should be/, Should be/g' | perl -p -e 's/Update to/, Update to/g' | perl -p -e 's/Missing patch/, Missing patch/g');

		# check for any output from nasl
		if [ ! -z "$mp" ]; then 
		   case $output in
		      2) getNaslDetails;;
		      3) getNaslSeverity;;
		      4) getNaslDetails '\t';;
		      5) getNaslSeverity '\t';;
		      # print name and output. Not that useful but works.
		      *) printf "%s%s\n" "$(basename "$a" .nasl)" "$mp";;
		   esac
		fi;
	done;
fi

# Clean up by removing temp files.
# echo $kb 
# cp $kb .
# echo "$dumper"
rm "$kb"

