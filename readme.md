# Network Attack Simulation Script

## Project Overview
This Bash script automates **network attack simulations** for security testing and analysis. It includes attacks like **Ping Flood (hping3), Metasploit scanning, and ARP Spoofing (MITM)**. The script allows users to select attack types, target specific IPs, and log all activities. Designed for **Kali Linux**, it helps ethical hackers and security professionals understand network vulnerabilities.

## Features
- **Root Privilege Verification**: Ensures the script runs with the necessary permissions.
- **Network Scanning**: Uses **Nmap** to detect active hosts and services.
- **Attack Selection Menu**: Provides options for different attack methods.
- **Ping Flood Attack**: Overloads a target with ICMP requests using **hping3**.
- **Metasploit Attack**: Scans and identifies vulnerabilities using the **Metasploit Framework**.
- **ARP Spoofing (MITM)**: Redirects network traffic using **arpspoof**.
- **Attack Logging**: Saves attack details (type, target IP, timestamp) to `/var/log/attack_log.txt`.

## Prerequisites
Before running the script, ensure the following:
- You are using **Kali Linux**.
- You have **root privileges**.
- Required tools are installed (**hping3, metasploit-framework, dsniff, xterm, and nmap**).

## Installation
Clone this repository and navigate into the directory:
```bash
 git clone https://github.com/yourusername/network-attack-script.git
 cd network-attack-script
```

## Usage
1. Grant execute permissions to the script:
```bash
chmod +x attack_script.sh
```
2. Run the script as **root**:
```bash
sudo ./attack_script.sh
```
3. Select an **attack method** from the menu.
4. Enter the **target IP** and execute the attack.

## Script Workflow
1. Checks for **root access**.
2. Prompts the user for a **network range**.
3. Scans for **available IP addresses** using **Nmap**.
4. Displays an **attack selection menu**:
   - **Ping Flood Attack** (`hping3`)
   - **Metasploit Attack** (Scanning for vulnerabilities)
   - **ARP Spoofing Attack** (`arpspoof` + MITM setup)
5. Executes the selected attack on the target IP.
6. Logs attack details to `/var/log/attack_log.txt`.

## Output Files
- **/var/log/attack_log.txt** → Log file storing attack details.
- **range_ip.txt** → List of discovered hosts during network scanning.

## Example Output
```
You are root.. continuing..
Please provide the network range in CIDR format (e.g., 192.168.1.0/24):
192.168.1.0/24
Scanning the network...
Available IPs:
192.168.1.10
192.168.1.20

Attack Selection Menu:
1) Ping Flood Attack
2) Metasploit Attack
3) ARP Spoofing Attack
4) Exit

Enter your choice: 1
Enter target IP address: 192.168.1.10
Starting Ping Flood Attack on 192.168.1.10...
[ ✓ ] Attack logged in /var/log/attack_log.txt
```

## Legal Disclaimer
**This script is for educational and authorized penetration testing purposes only.** Unauthorized use against systems you do not own or have explicit permission to test is illegal and unethical.

## Credits
- Created by **May Hazon**
- Lecturer: **Erel**
- Class Code: **S5**
- Unit: **TMagen773632**

## License
This project is licensed under the MIT License. See the `LICENSE` file for details.

