#!/bin/bash

function Print_header()
{
	echo ""
	echo -e "\033[1;31m
     _______               _            _
  _____  __ \___ _____    /_/__    ____/ /_____
      / /_/ / ___/ __ \  / / __ \/ ___/ __/
  __ / ____/ /  / /_/ / / /   __/ /__/ /___  
    /_/   /_/   \____/_/ /_\___/\___/\__/
           | |  / /_\___/ /___   __    _______
           | | / / / / / / __ \/ __ \/ ___/
           | |/ / /_/ / / / / /   __/ /
       ____|___/\__,_/_/_/ /_/ \___/_/                                         
	\033[0m"
	sleep 1
	echo ""
}

#Set up the penetration testing environment
function Setup_dir()
{
    #Variable for directory
    output_dir=ProjVulner

    #Create a directory to store all results and reports
    echo -e "\033[1;94m[+]\033[0m New directory has been created: \033[1;94mProjVulner\033[0m" 
    sleep 1
    mkdir -p $output_dir
    echo ""

    #Change to newly created directory
    echo "[*] Changing directory to "$output_dir"..." 
    cd $output_dir
    sleep 1
    echo ""

    #Print out the current working directory path
    echo "[*] Your current working directory:"
    pwd 
    sleep 1
    echo ""
}

#Display the LAN network range
function Display_network_range()
{
	echo "[*] Identifying the LAN network range..." && sleep 1
	echo ""
	echo "[*] Your network range is:"
	
	#Synxtax to grep for the network range
	echo -e "\033[1;93m[+]\033[0m $(ip a | grep eth0 | grep inet | awk '{print $2}')" 
	sleep 1
    echo ""
}

#Run Netdiscover on the network range and stop after active scan
function Netdiscover_Scan()
{
	#Displayed network range stored as a variable
	NETWORK_RANGE=$(ip a | grep eth0 | grep inet | awk '{print $2}')
	echo "[*] Scanning for active host, standby..."
    sudo netdiscover -r $NETWORK_RANGE -P > netdiscover_results.txt
	
	#Print out netdiscover results
	cat netdiscover_results.txt && sleep 1.5
    echo ""
}

#Function to validate IP address format
#credit: Mitch Frazier - 26 June 2008
#https://www.linuxjournal.com/content/validating-ip-address-bash-script
function Validate_IP_Address()
{
    local  stat=1
    local  ip=$1

    if [[ $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        OIFS=$IFS
        IFS='.'
        ip=($TARGET_IP)
        IFS=$OIFS
		[[ ${ip[0]} -le 255 && ${ip[1]} -le 255 \
            && ${ip[2]} -le 255 && ${ip[3]} -le 255 ]]
        stat=$?
    fi
    return $stat
}

#Run Masscan on target's UDP open ports
function Masscan_UDP()
{
	echo "[*] Running Masscan on UDP ports..." && sleep 1
	echo ""
	
	while true; do
	read -p "[*] Enter target IP address: " TARGET_IP
	echo ""

    if Validate_IP_Address "$TARGET_IP"; then
		echo "[*] This might take a few minutes, please standby..." && sleep 1
		echo ""
		sudo masscan $TARGET_IP -pU:1-65535 --rate=50000 > masscan_results.txt
		
		#Print out masscan results
		cat masscan_results.txt && sleep 1.5
		echo ""
        break
    else
        echo -e "\033[1;31m[-]\033[0m Invalid IP address format! Please try again"
        sleep 1
        echo ""
    fi
done
}

#Run Nmap scan on UDP open ports for Service detection
function Nmap_UDP_scan()
{
	echo "[*] Running Nmap scan on UDP ports..." && sleep 1
	echo ""
	read -p "[*] Enter target UDP port: " TARGET_UDP_PORT
	echo ""
	echo "[*] This might take a few minutes, please standby..." && sleep 1
	echo ""
	sudo nmap $TARGET_IP -sU -sV -p $TARGET_UDP_PORT -oN nmap_udp_results.txt -oX nmap_udp_scan.xml
	echo ""
	
	#Convert nmap UDP scan results XML format to HTML format using xsltproc
	echo "[*] Generating Nmap scan xml file for Searchsploit and html report file..." && sleep 1.5
	xsltproc nmap_udp_scan.xml -o nmap_report.html
	echo ""
	echo "[*] Report generated!" && sleep 1.5
	echo ""
}

#Run Nmap scan on TCP open ports for Service and OS detection
function Nmap_TCP_scan()
{
	echo "[*] Running Nmap scan on TCP ports..." && sleep 1
	echo ""
	echo "[*] This might take a few minutes, please standby.." && sleep 1
	echo ""
	sudo nmap $TARGET_IP -sS -sV -O -T4 -p- --open -oN nmap_tcp_results.txt -oX nmap_tcp_scan.xml
	echo ""
	
	#Convert nmap TCP scan results XML format to HTML format using xsltproc
	echo "[*] Generating Nmap scan xml file for Searchsploit and html report file..." && sleep 1.5
	xsltproc nmap_tcp_scan.xml -o nmap_report.html
	echo ""
	echo "[*] Report generated!" && sleep 1.5
	echo ""
}

#Function to update Searchsploit
function Update_searchsploit()
{
	#Update Searchsploit in quiet output
	echo "[*] Updating Searchsploit..." && sleep 1.5
	echo ""
	echo "[*] This might take a few minutes, please standby.." && sleep 1
	
	#Run searchsploit update in quiet output
	sudo searchsploit --update > /dev/null 2>&1
	echo ""
	echo -e "\033[1;94m[+]\033[0m Update complete!" && sleep 1.5
	echo ""
}

#Function to run Searchsploit
function Run_searchsploit()
{
	echo "[*] Running Searchsploit..." && sleep 1
    echo ""
    echo "[*] Searching vulnerabilities on Nmap scan xml results, please standby..."
    sleep 1.5
    echo ""

    #Scan and save Searchsploit exploit database into a file in quiet output
    searchsploit --nmap nmap_udp_scan.xml -o searchsploit_results.txt > /dev/null 2>&1
	searchsploit --nmap nmap_tcp_scan.xml >> searchsploit_results.txt 2>&1

	echo -e "\033[1;94m[+]\033[0m Output saved in searchsploit_results.txt" && sleep 1.5
	echo ""
	echo "Vulnerabilities List"
	echo "====================" && sleep 1.5
	echo ""

	#Print out the searchsploit results
	cat searchsploit_results.txt
	
	while true; do
		#Read -r flag ensures that input is treated as raw text
		read -rp "[*] Enter a exploit/keywords ID (type 'exit' to quit): " keyword
		echo ""

		if [[ "$keyword" == "exit" ]]; then
			echo "[*] Exiting vulnerabilities search..." && sleep 1
			echo ""
			break
		else
			echo "[*] Running Searchsploit for '$keyword'..."
			searchsploit -x "$keyword"
			echo ""
		fi
	done
}

#Display Searchsploit Menu
function Searchsploit_menu()
{
	while true; do
		echo "Searchsploit Menu"
		echo "================="
		echo ""
		echo "#   Descriptions"
		echo "—   ————————————"
		echo "1   Update Searchsploit database"
		echo "2   Run Searchsploit - search the Exploit Database via Nmap XML file."
		echo "3   Exit Searchsploit Menu"
		echo ""
		read -p "[*] Select your option (1|2|3): " choice
		echo ""

		case $choice in
			1)
				Update_searchsploit
				;;
			2)
				Run_searchsploit
				;;
			3)
				echo "[*] Exiting Searchsploit Menu..." && sleep 1
				echo ""
				break
				;;
			*)
				echo -e "\033[1;31m[-]\033[0m Invalid option! Please try again."
				sleep 1
				echo ""
				;;
		esac
	done
}

#Create user/password list using Crunch
function Create_password_list()
{
	echo "[*] Running Crunch to generate password lists..." && sleep 1.5
	echo ""
    read -p "[*] Enter the minimum password length: " MIN_LENGTH
    read -p "[*] Enter the maximum password length: " MAX_LENGTH
    echo ""
    echo "Characters/patterns sets"
    echo "————————————————————————"
    echo "(example: abc123)"
    echo -e "\033[1;97mOR\033[0m"
    echo "(@ - will insert lower case characters)"
    echo "(, - will insert upper case characters)"
    echo "(% - will insert numbers)"
    echo "(^ - will insert symbols)" && sleep 1.5
    echo ""
    read -p "[*] Enter characters/patterns: " CHAR_SET
    read -p "[*] Enter the output filename: " CRUNCH_OUTPUT_FILE
    echo ""
    echo "[*] Generating password list..." && sleep 1.5
    crunch $MIN_LENGTH $MAX_LENGTH -t $CHAR_SET > $CRUNCH_OUTPUT_FILE
    echo ""
    echo -e "\033[1;94m[+]\033[0m Password list generated: $CRUNCH_OUTPUT_FILE."
    sleep 1.5
    echo ""
}

#Run Brute-Force attack using Hydra with given password list
function Brute_force_attack()
{
	echo "[*] Running Brute-Force attack with Hydra..." && sleep 1
	echo ""
	read -p "[*] Enter target port number: " TPORT
	read -p "[*] Enter service protocol (eg: ssh/ftp/rdp/smb): " SVC_PRTCL
	echo ""
	echo "[*] Starting Brute-Force attack, please standby..."
	sleep 1
	hydra -L $USRLST -P $PASSLST $TARGET_IP -s $TPORT $SVC_PRTCL -t4 -vV -o bf_results.txt
	echo ""
	echo "[*] Brute-Force attack complete!" && sleep 1
	echo ""
	
	#Print out bruteforce results
	echo -e " \033[1;97mBrute-Force results:\033[0m"
	echo -e " \033[1;97m————————————————————\033[0m"
	cat bf_results.txt && sleep 1.5
	echo ""
}

#Display brute force attack menu
function Brute_force_menu
{
	while true; do
		echo "Brute-Force Menu"
		echo "================"
		echo ""
		echo "#   Descriptions"
		echo "—   ————————————"
        echo "1   Specify a user list/filename for Hydra"
        echo "2   Specify a password list/filename for Hydra"
        echo "3   Run Crunch to generate a password list"
        echo "4   Run Hydra to brute force with the password list"
        echo "5   Exit Brute-Force Menu"
        echo ""
        read -p "[*] Select your option (1|2|3|4|5): " OPTION
        echo ""
    
		case $OPTION in
			1)
				read -p "[*] Enter the user filename: " USRLST
                echo ""
                echo -e "\033[1;94m[+]\033[0m User filename specified: "$USRLST""
                sleep 1
                echo ""
                ;;
            2)
                read -p "[*] Enter the password filename: " PASSLST
                echo ""
                echo -e "\033[1;94m[+]\033[0m Password filename specified: "$PASSLST"" 
                sleep 1
                echo ""
                ;;
            3)
                Create_password_list
                ;;
            4)
                if [ -z "$PASSLST" ]; then
                    echo -e "\033[1;31m[-]\033[0m Please specify a password list before running Hydra."
                    sleep 1
                    echo ""
                else
                    Brute_force_attack
                fi
                ;;
            5)
                echo "[*] Exiting Brute-Force Menu..." && sleep 1
                echo ""
                break
                ;;
            *)
                echo -e "\033[1;31m[-]\033[0m Invalid option! Please try again." && sleep 1
                echo ""
                ;;
        esac
    done
}

#Save all the results into a report and display it
function Generate_report()
{
		#Injecting all results in a report file
	echo "[*] Compiling all results into a report..." && sleep 1
	echo ""
	echo "Penetration Testing Report" > pentest_report.txt
	echo "——————————————————————————" >> pentest_report.txt
	echo "Network Mapping and Vulnerability Scanning Results:" >> pentest_report.txt
	echo "———————————————————————————————————————————————————" >> pentest_report.txt
	echo "Scan Date: $(date)" >> pentest_report.txt
	cat netdiscover_results.txt >> pentest_report.txt
	
	echo "Masscan results:" >> pentest_report.txt
	echo "————————————————" >> pentest_report.txt
	cat masscan_results.txt >> pentest_report.txt
	
	echo "Nmap UDP scan results:" >> pentest_report.txt
	echo "——————————————————————" >> pentest_report.txt
	cat nmap_udp_results.txt >> pentest_report.txt
	
	echo "Nmap TCP scan results:" >> pentest_report.txt
	echo "——————————————————————" >> pentest_report.txt
	cat nmap_tcp_results.txt >> pentest_report.txt
	
	echo "Searchsploit results:" >> pentest_report.txt
	echo "—————————————————————" >> pentest_report.txt
	cat searchsploit_results.txt >> pentest_report.txt
	
	echo "Hydra brute-force results:" >> pentest_report.txt
	echo "——————————————————————————" >> pentest_report.txt
	cat bf_results.txt >> pentest_report.txt
	
	#Remove scans result to clear up clutter
	echo "[*] Clearing file clutters..."
	echo ""
	rm -f netdiscover_results.txt
	rm -f masscan_results.txt
	rm -f nmap_udp_results.txt
	rm -f nmap_tcp_results.txt
	rm -f searchsploit_results.txt
	rm -f bf_results.txt
	
	echo -e "\033[1;94m[+]\033[0m Report saved in 'pentest_report.txt' for review!" && sleep 1
	echo ""
	echo "[*] Exiting script..." && sleep 1
	echo ""
	echo "[*] Goodbye!" 
	echo ""
}

#Main function to execute the script
function Main_Script()
{
	Print_header
	Setup_dir
	Display_network_range
	Netdiscover_Scan
	Masscan_UDP
    Nmap_UDP_scan
    Nmap_TCP_scan
    Searchsploit_menu
    Brute_force_menu
    Generate_report
}
Main_Script


