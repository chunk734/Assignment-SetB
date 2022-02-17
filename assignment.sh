#!/bin/bash

cleanup() {
	echo "Exiting the Script"
}

initialize() {
	SSH_DIR=".ssh"
	SSH_AUTHORIZED_KEYS_FILE="$SSH_DIR/authorized_keys"
	SSH_CONF_FILE="/etc/ssh/sshd_config"
	SYSCTL_CONF_FILE="/etc/sysctl.conf"
	GROUPS_FILE="/etc/group"
	LIMITS_CONF_FILE="/etc/security/limits.conf"
	OPERATIONS_LIST=("addUser" "quit")
	GROUPS_LIST=("dev" "devops")
}

#Execute the script with privileged user
runAsRoot() {
	if [[ $(id -u) -ne 0 ]]; then
		echo "Plesae run the script with elevated privileges"
		exit 1
	fi
}

readCreateUserInputs() {
	read -p "Enter the username: " USERNAME
	read -p "Enter the user's public key: " PUB_KEY
	PS3="Select the user's role: "
	select val in "${GROUPS_LIST[@]}"; do
		case $val in
			"dev")
				GROUP="dev"
				break
				;;
			"devops")
				GROUP="devops"
				break
				;;
			*)
				echo "Invalid Option $REPLY"
				;;
		esac
	done
}

createUser() {
	echo "Creating $USERNAME with $GROUP access permissions"
	if ! grep -q "^${GROUP}:" "$GROUPS_FILE"; then
		groupadd "$GROUP"
	fi
	if [[ $GROUP == "devops" ]]; then
		useradd -g "$GROUP" -G sudo -m "$USERNAME"
		usermod -p '$6$test$ML.63Xb/NO44SARjdpxaKbdYggwY4P7R0R/.B423HpGvTrFS.8OHYMrgEAgjWGleF6jCpCKOKWPBP8ILTOVRv1' "$USERNAME"
	else
		useradd -g "$GROUP" -m "$USERNAME"
		usermod -p '$6$test$3yuB5C.sF1R1iXw8CNAF.hARMLklIdBS3NQRKOYPrQdsvvWKySN8YbQbZ7.wimqbBbkxmdUs.DDffOzbEBPO0.' "$USERNAME"
	fi
}

enableSSHAccess() {
	echo "Enabling SSH Access for new user: $USERNAME"
	local HOME_DIR="/home/$USERNAME"
	mkdir -p "$HOME_DIR/$SSH_DIR"
	echo "$PUB_KEY" >>"$HOME_DIR/$SSH_AUTHORIZED_KEYS_FILE"
	chown -R "$USERNAME":"$GROUP" "$HOME_DIR/$SSH_DIR"
	checkAndAddProperty "AllowGroups devops dev" "$SSH_CONF_FILE"
}

checkAndAddDirectoryAccess() {
	echo "Adding Directory Access & permissions for Dev and Devops"
	mkdir -p "/opt/sayurbox"
	mkdir -p "/var/log/"
	chown -R root:dev "/opt/sayurbox"
	chmod -R 770 "/opt/sayurbox"
	chown -R root:dev "/var/log/"
	chmod -R 640 "/var/log/"
}

networkTrafficHardening() {

	#Install IPtables-Persistent package non-intercatively
	apt-get update >/dev/null 2>&1
	echo iptables-persistent iptables-persistent/autosave_v4 boolean true | debconf-set-selections
	apt-get install iptables-persistent -y >/dev/null 2>&1

	#Allow all traffic for localhost
	checkAndAddIPtables "INPUT -i lo -j ACCEPT"
	checkAndAddIPtables "OUTPUT -o lo -j ACCEPT"

	#Allow Inbound SSH, HTTP and DNS traffic (Ingress Hardening)
	checkAndAddIPtables "INPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "OUTPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "INPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "OUTPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "INPUT -p udp --dport 53 -j ACCEPT"

	#Allow Outbound SSH, HTTP and DNS traffic (Egress Hardening)
	checkAndAddIPtables "OUTPUT -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "INPUT -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "OUTPUT -p tcp --dport 443 -m state --state NEW,ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "INPUT -p tcp --sport 443 -m state --state ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "OUTPUT -p tcp --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "INPUT -p tcp --sport 53 -m state --state ESTABLISHED -j ACCEPT"
	checkAndAddIPtables "OUTPUT -p udp --sport 53 -j ACCEPT"

	#Set default input/forward/output chain policy to drop
	iptables -P INPUT DROP
	iptables -P FORWARD DROP
	iptables -P OUTPUT DROP

	#Persist IPtables
	echo "Persisting IPtable rules"
	iptables-save >/etc/iptables/rules.v4

}

checkAndAddProperty() {
	property="${1}"
	file="${2}"
	if ! grep -q "^$property$" "$file"; then
		local prop=$(echo "$property" | cut -d " " -f1 | cut -d "=" -f1)
		if grep -q "^$prop" "$file"; then
			sed -i '' "s/^$prop/#$prop/" $file
		fi
		echo "Applying property: $property"
		echo "$property" >>"$file"
	fi
}

checkAndAddIPtables() {
	iptable_rule="${1}"
	iptables -C $iptable_rule >/dev/null 2>&1
	if [[ $? -ne 0 ]]; then
		echo "Applying iptable rule: $iptable_rule"
		iptables -A $iptable_rule
	fi
}

addSSHBanner() {
	echo "Checking Custom SSH Banner"
	if [[ ! -f "/etc/ssh/welcome_banner" ]]; then
		cat >/etc/ssh/welcome_banner <<EOL
############################################
############################################
##                                        ##
## WELCOME TO SAYURBOX APPLICATION SERVER ##
## Unauthorized access will be prosecuted ##
##                                        ##
############################################
############################################
EOL
		chown root:root /etc/ssh/welcome_banner
		chmod 644 /etc/ssh/welcome_banner
	fi

    checkAndAddProperty "Banner /etc/ssh/welcome_banner" "$SSH_CONF_FILE"
}

serverHardening() {
	echo "Checking Server Hardenning Properties"

	#Disable root remote login
	checkAndAddProperty "PermitRootLogin no" "$SSH_CONF_FILE"

	#Disable remote password authentication for login
	checkAndAddProperty "PasswordAuthentication no" "$SSH_CONF_FILE"
	checkAndAddProperty "ChallengeResponseAuthentication no" "$SSH_CONF_FILE"
	checkAndAddProperty "UsePAM no" "$SSH_CONF_FILE"

	#Disable ICMP Pkts
	checkAndAddProperty "net.ipv4.icmp_echo_ignore_all = 1" "$SYSCTL_CONF_FILE"
	checkAndAddProperty "net.ipv4.icmp_echo_ignore_broadcasts = 1" "$SYSCTL_CONF_FILE"

	#Disable IPv6 networking
	checkAndAddProperty "net.ipv6.conf.all.disable_ipv6 = 1" "$SYSCTL_CONF_FILE"
	checkAndAddProperty "net.ipv6.conf.default.disable_ipv6 = 1" "$SYSCTL_CONF_FILE"

	#Set Connection Idle timeout to 5 minutes
	checkAndAddProperty "ClientAliveInterval 300" "$SSH_CONF_FILE"
	checkAndAddProperty "ClientAliveCountMax 0" "$SSH_CONF_FILE"

	echo "Checking IPtable Rules"

	#Add firewall rules for traffic control
	networkTrafficHardening

	#Add Custom SSH Banner
	addSSHBanner

    rm -f /etc/update-motd.d/*

	sysctl -p

	echo "Restarting SSH Service"
	systemctl restart ssh
}

optimizeServer() {
	#Set run-level to 3, for conserving resources & keeping it minimal
	if [[ "$(systemctl get-default)" != "multi-user.target" ]]; then
		systemctl isolate multi-user.target
		systemctl set-default multi-user.target
	fi

	#Increase server socket accept queue buffer size
	checkAndAddProperty "net.core.somaxconn = 65535" "$SYSCTL_CONF_FILE"

	#Increase server TCP receive queue buffer size
	checkAndAddProperty "net.core.netdev_max_backlog = 65535" "$SYSCTL_CONF_FILE"

	#Increase soft and hard limit for number of open files
	checkAndAddProperty "*               soft    nofile          65535" "$LIMITS_CONF_FILE"
	checkAndAddProperty "*               hard    nofile          65535" "$LIMITS_CONF_FILE"
	ulimit -Sn 65535
	ulimit -Hn 65535

	sysctl -p
}

logRotation() {
	#Check if logrotate conf exists for our app, and add if not
	echo "Checking logrotation configurations"
	if [[ ! -f "/etc/logrotate.d/app" ]]; then
		cat >/etc/logrotate.d/app <<EOL
/var/log/*.log {
        daily
        create 0640 root dev
        rotate 15
        compress
        delaycompress
        copytruncate
        dateext
        missingok
        notifempty
    } 
EOL
		chown root:dev /etc/logrotate.d/app
		chmod 644 /etc/logrotate.d/app
	fi
}

menuDisplay() {
	PS3="Select the operation to be performed: "
	select opt in "${OPERATIONS_LIST[@]}"; do
		case $opt in
			"addUser")
				readCreateUserInputs
				createUser
				enableSSHAccess
				PS3="Select the operation to be performed: "
				;;
			"quit")
				break
				;;
			*) echo "invalid option $REPLY" ;;
		esac
	done
}

main() {

	runAsRoot

	initialize

	menuDisplay

	serverHardening

	checkAndAddDirectoryAccess

	logRotation

	optimizeServer

}

trap cleanup EXIT

while getopts ":dh" opt; do
	case ${opt} in
		d)
			export DEBUG=1
			break
			;;
		h)
			echo "Use flag -d to execute in debug mode"
			exit 0
			;;
		*)
			echo "Invalid Flag"
			exit 1
			;;
	esac
done

if [[ $DEBUG == "1" ]]; then
	set -x
fi

main
