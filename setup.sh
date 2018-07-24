#!/bin/sh
ROOT_DIR=$(dirname "$(readlink -f "$0")")
NO=0
YES=1

# Values can be changed from settings.conf file
TAG=""
SSH_BANNER=""
SERVICES=""
DISABLE_IPV6=${NO}
DISABLE_PING=${NO}

SSH_PORT=22
REMOVE_KEYS=${NO}
DISABLE_ROOT=${NO}
PASSWORD_AUTH=${NO}

USERS=()
USER_GROUPS=()

ALIAS_COMMANDS=()
ALIAS_ACTIONS=()


if [[ ${EUID} -ne 0 ]]
then
	echo
	echo "This script must be by the root user." 
	echo
	exit 1
fi

function parseConfig {
	category=""
	
	while IFS= read -r line;
	do
		comment=$(echo "$line" | grep -e "^#")
		
		if [[ ! -z ${line} ]] && [[ -z ${comment} ]]
		then
			#Uncomment Hashes
			line=$(echo "${line}" | sed -e "s/\/#/#/g")
		
			# Parse category
			if [[ ${line} =~ "[ TAG ]" ]]
			then
				category="TAG"
			elif [[ ${line} =~ "[ SSH_BANNER ]" ]]
			then
				category="SSH_BANNER"
			elif [[ ${line} =~ "[ GENERAL ]" ]]
			then
				category="GENERAL"
			elif [[ ${line} =~ "[ SSH_CONFIG ]" ]]
			then
				category="SSH_CONFIG"
			elif [[ ${line} =~ "[ USERS ]" ]]
			then
				category="USERS"
			elif [[ ${line} =~ "[ ALIASES ]" ]]
			then
				category="ALIASES"
			fi
		
			# Parse category options
			if [[ ${category} == "TAG" ]] && [[ ! ${line} =~ "[ TAG ]" ]]
			then
				TAG+="${line}\n"
			elif [[ ${category} == "SSH_BANNER" ]] && [[ ! ${line} =~ "[ SSH_BANNER ]" ]]
			then
				SSH_BANNER+="${line}\n"	
			elif [[ ${category} == "GENERAL" ]]
			then
				if [[ ${line} =~ "SERVICES" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | sed -e 's/^ *//g' | tr -d '"')
					
					SERVICES=${parse_str}
				elif [[ ${line} =~ "DISABLE_IPV6" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r"  | tr '[:upper:]' '[:lower:]')
					
					if [[ ${parse_str} == "yes" ]]
					then
						DISABLE_IPV6=${YES}
					else
						DISABLE_IPV6=${NO}
					fi
					
				elif [[ ${line} =~ "DISABLE_PING" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r"  | tr '[:upper:]' '[:lower:]')
					
					if [[ ${parse_str} == "yes" ]]
					then
						DISABLE_PING=${YES}
					else
						DISABLE_PING=${NO}
					fi
				fi
			elif [[ ${category} == "SSH_CONFIG" ]]
			then
				if [[ ${line} =~ "PORT" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r"  | tr '[:upper:]' '[:lower:]')
					
					SSH_PORT=${parse_str}
				elif [[ ${line} =~ "REMOVE_KEYS" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r"  | tr '[:upper:]' '[:lower:]')
					
					if [[ ${parse_str} == "yes" ]]
					then
						REMOVE_KEYS=${YES}
					else
						REMOVE_KEYS=${NO}
					fi
				elif [[ ${line} =~ "DISABLE_ROOT" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r"  | tr '[:upper:]' '[:lower:]')
					
					if [[ ${parse_str} == "yes" ]]
					then
						DISABLE_ROOT=${YES}
					else
						DISABLE_ROOT=${NO}
					fi
				elif [[ ${line} =~ "PASSWORD_AUTH" ]]
				then
					parse_str=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r"  | tr '[:upper:]' '[:lower:]')
					
					if [[ ${parse_str} == "yes" ]]
					then
						PASSWORD_AUTH=${YES}
					else
						PASSWORD_AUTH=${NO}
					fi
				fi
			elif [[ ${category} == "USERS" ]] && [[ ${line} =~ "=" ]]
			then
				username=$(echo "${line}" | cut -d '=' -f1 | tr -d " \t\n\r")
				group=$(echo "${line}" | cut -d '=' -f2 | tr -d " \t\n\r")
				
				USERS+=("${username}")
				USER_GROUPS+=("${group}")
			elif [[ ${category} == "ALIASES" ]] && [[ ${line} =~ "=" ]]
			then
				command=$(echo "${line}" | cut -d '=' -f1 | tr -d " \t\n\r")
				action=$(echo "${line}" | cut -d '=' -f2 | sed 's/^ *//g' | tr -d "\t\n\r" | tr -d '"')
				action=$(echo "$action" | sed "s/\[SSH_PORT\]/${SSH_PORT}/g")
				ALIAS_COMMANDS+=("${command}")
				ALIAS_ACTIONS+=("${action}")
			fi
		fi
	done < ${ROOT_DIR}/settings.conf
	
	echo
}

function debugConfig {
	echo -e "TAG:\n ${TAG}"
	echo -e "SSH_BANNER:\n ${SSH_BANNER}"
	echo "SERVICES: ${SERVICES}"
	echo "DISABLE_IPV6: ${DISABLE_IPV6}"
	echo "DISABLE_PING: ${DISABLE_PING}"
	
	echo "SSH_PORT: ${SSH_PORT}"
	echo "REMOVE_KEYS: ${REMOVE_KEYS}"
	echo "DISABLE_ROOT: ${DISABLE_ROOT}"
	echo "PASSWORD_AUTH: ${PASSWORD_AUTH}"
	
	echo "USERS: ${USERS[0]}"
	echo "USER_GROUPS: ${USER_GROUPS[0]}"
	echo "ALIAS_COMMANDS: ${ALIAS_COMMANDS[0]}"
	echo "ALIAS_ACTIONS: ${ALIAS_ACTIONS[0]}"
}

function remove_ssh_keys {
	echo "Removing SSH keys."
	if [[ ${REMOVE_KEYS} == ${YES} ]]
	then
		echo "Removing SSH known hosts."
		
		if [[ ${REMOVE_SSH_KEYS} == ${YES} ]]
		then
			for d in $(find /home/ -maxdepth 1 -type d)
			do
				if [ ${d} != "/home/" ]
				then
					if [[ -d "${d}/.ssh/" ]]
					then
						rm -r "${d}/.ssh/"
					fi
				fi
			done
			
			# Remove root known hosts
			if [[ -d "/root/.ssh/" ]]
			then
				rm -rf /root/.ssh
			fi
		fi
	fi
}

function configure_ssh {
	echo "Configuring SSH."
	file="/etc/ssh/sshd_config"
	
	replaceLine -s "^Port" -r "Port ${SSH_PORT}" -f "${file}"
	replaceLine -s "^PubkeyAuthentication" -r "PubkeyAuthentication yes" -f "${file}"
	
	if [[ ${PASSWORD_AUTH} == ${YES} ]]
	then
		replaceLine -s "^PasswordAuthentication" -r "PasswordAuthentication yes" -f "${file}"
	else
		replaceLine -s "^PasswordAuthentication" -r "PasswordAuthentication no" -f "${file}"
	fi
	
	if [[ ${DISABLE_ROOT} == ${YES} ]]
	then
		replaceLine -s "^PermitRootLogin" -r "PermitRootLogin no" -f "${file}"
		replaceLine -s "^AllowUsers" -r "AllowUsers ${USERS[@]}" -f "${file}"
	else
		replaceLine -s "^PermitRootLogin" -r "PermitRootLogin yes" -f "${file}"
		replaceLine -s "^AllowUsers" -r "AllowUsers ${USERS[@]} root" -f "${file}"
	fi
	
	# Configure MOTD
	echo -e "${SSH_BANNER}" > /etc/issue.net
}

function configure_general {
	echo "Configuring networking."
	file="/etc/sysctl.conf"

	if [[ ${DISABLE_IPV6} == ${YES} ]]
	then
		replaceLine -s "^net.ipv6.conf.all.disable_ipv6" -r "net.ipv6.conf.all.disable_ipv6 = 1" -f "${file}"
		replaceLine -s "^net.ipv6.conf.default.disable_ipv6" -r "net.ipv6.conf.default.disable_ipv6 = 1" -f "${file}"
		replaceLine -s "^net.ipv6.conf.lo.disable_ipv6" -r "net.ipv6.conf.lo.disable_ipv6 = 1" -f "${file}"
		replaceLine -s "^net.ipv6.conf.eth0.disable_ipv6" -r "net.ipv6.conf.eth0.disable_ipv6 = 1" -f "${file}"
	else
		replaceLine -s "^net.ipv6.conf.all.disable_ipv6" -r "net.ipv6.conf.all.disable_ipv6 = 0" -f "${file}"
		replaceLine -s "^net.ipv6.conf.default.disable_ipv6" -r "net.ipv6.conf.default.disable_ipv6 = 0" -f "${file}"
		replaceLine -s "^net.ipv6.conf.lo.disable_ipv6" -r "net.ipv6.conf.lo.disable_ipv6 = 0" -f "${file}"
		replaceLine -s "^net.ipv6.conf.eth0.disable_ipv6" -r "net.ipv6.conf.eth0.disable_ipv6 = 0" -f "${file}"
	fi
	
	if [[ ${DISABLE_PING} == ${YES} ]]
	then
		replaceLine -s "^net.ipv4.icmp_echo_ignore_all" -r "net.ipv4.icmp_echo_ignore_all = 1" -f "${file}"
	else
		replaceLine -s "^net.ipv4.icmp_echo_ignore_all" -r "net.ipv4.icmp_echo_ignore_all = 0" -f "${file}"
	fi
	
	sysctl -p >/dev/null 2>/dev/null
}

function configure_motd {
	echo "Configuring motd."
	
	echo "" > /etc/motd
	
	rm -f /etc/update-motd.d/00-header
	rm -f /etc/update-motd.d/10-sysinfo
	
	cp -f ${ROOT_DIR}/motd/00-header  /etc/update-motd.d/00-header
	cp -f ${ROOT_DIR}/motd/10-sysinfo /etc/update-motd.d/10-sysinfo
	
	echo -e "\nSERVICES=\"${SERVICES}\"" >> /etc/update-motd.d/00-header
	echo -e "\nTAG=\"\n${TAG}\"" >> /etc/update-motd.d/00-header
	echo >> /etc/update-motd.d/00-header
	echo "MOTD_HEADER=\"\${TAG}\nSERVER: \${HOST}\nSERVICES:\${SERVICES}\n\n*** UNAUTHORIZED USE IS STRICTLY PROHIBITED ***\"" >> /etc/update-motd.d/00-header
	echo -e "\necho \"\${MOTD_HEADER}\"" >> /etc/update-motd.d/00-header
	
	chmod +x /etc/update-motd.d/00-header
	chmod +x /etc/update-motd.d/10-sysinfo
}

function configure_firewall {
	echo "Configuring firewall."
	bash ${ROOT_DIR}/firewall.sh
}

function configure_users {
	echo "Configuring users."
	for (( i=0; i< ${#USERS[@]}; i++ )) do
		create_user -u "${USERS[i]}" -g "${USER_GROUPS[i]}"
	done
}

function configure_aliases {
	echo "Configuring aliases."

	# Create aliases file
	contents="\n"
	contents+="alias sudo='sudo '\n"
	
	for (( i=0; i< ${#ALIAS_COMMANDS[@]}; i++ )) do
		command="${ALIAS_COMMANDS[$i]}"
		action="${ALIAS_ACTIONS[$i]}"
		contents+="alias ${command}='${action}'\n"
	done
	
	echo -e "${contents}" > /etc/profile.d/00-aliases.sh
	chmod 644 /etc/profile.d/00-aliases.sh
}

function create_user {
	user=""
	group=""
	
	while getopts 'u:g:' flag; do
		case "${flag}" in
			u) 
				user="${OPTARG}"
			;;
			g)
				group="${OPTARG}"
			;;
		 esac
	done

	# Create users
	user_check=$(getent passwd "${user}")
	if [[ -z ${user_check}  ]]
	then
		adduser "${user}"
	fi
	
	# Add user to group
	usermod -aG "${group}" "${user}"
}

function replaceLine {
	SEARCH=""
	REPLACE=""
	FILE=""

	while test $# -gt 0; do
		case "$1" in
			-f|--file)
				shift
				FILE="$1"
				shift
			;;
			-s|--search)
				shift
				SEARCH="$1"
				shift
			;;
			-r|--replace)
				shift
				REPLACE="$1"
				shift
			;;
			*)
				break
			;;
		esac
	done
	
	if [[ -e ${FILE} ]]
	then
		if grep -q "${SEARCH}" "${FILE}"
		then
			# Replace line
			num=$(grep -n "${SEARCH}" "${FILE}" | cut -d ":" -f1)
			sed -i "${num}d" "${FILE}"
		fi
		# Append to file
		echo -e "${REPLACE}" >> "${FILE}"
	fi
}

parseConfig
#debugConfig

configure_general
configure_ssh
remove_ssh_keys
configure_users
configure_aliases
configure_motd
configure_firewall

echo
echo "Successfully completed setup!"
echo
