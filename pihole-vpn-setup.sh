#!/bin/bash
# Enforce root
if [[ $EUID -ne 0 ]]; then
  echo "This script must be run with  (as root)."
  echo "Try: sudo $0"
  exit 1
fi
set -euo pipefail

echo
echo -e "========================================="
echo -e "     Welcome to the pihole-vpn-setup  "
echo -e "========================================="
echo -e " This interactive script will help you:"
echo -e " • Install and configure Pi-hole"
echo -e " • Set up a private VPN using PiVPN (WireGuard or OpenVPN)"
echo -e " • Harden your Raspberry Pi firewall with UFW"
echo -e " • Block ads network-wide, even when you're away from home"
echo -e " • Disable unneeded services to reduce system load"
echo -e " • Schedule automatic updates and reboots"
echo -e "\n Recommended for Raspberry Pi Zero 2 W and similar setups"
echo -e " Requires: Raspberry Pi OS Lite (64-bit) + Ethernet connection"
echo -e "========================================="

#-------------SYSTEM UPDATE----------------------
echo
read -rp "Do you want to update and upgrade the system? [Y/n]: " update_choice
update_choice="${update_choice:-Y}"

if [[ "$update_choice" =~ ^[Yy]$ ]]; then
  echo -e "\nUpdating and upgrading system..."
  apt-get update &&  apt-get upgrade -y
  echo -e "\nSystem update completed."
else
  echo "Skipping system update."
fi

#-------------PI-HOLE INSTALLATION----------------
echo
if command -v pihole >/dev/null 2>&1; then
  echo "Pi-hole is already installed."
else
  read -rp "Pi-hole is not installed. Do you want to install it now? [Y/n]: " install_pihole
  install_pihole="${install_pihole:-Y}"

  if [[ "$install_pihole" =~ ^[Yy]$ ]]; then
    echo -e "\nInstalling Pi-hole..."
    curl -sSL https://install.pi-hole.net | bash
    echo -e "\nPi-hole installation completed."
    # Change Pi-hole admin password
    read -rp "Do you want to set a new Pi-hole web interface password? [Y/n]: " change_password
    change_password="${change_password:-Y}"

    if [[ "$change_password" =~ ^[Yy]$ ]]; then
       pihole setpassword
    else
      echo -e "\nSkipping password change."
    fi
    # Add user to pihole group
    read -rp "Add your user '$USER' to the 'pihole' group (so you won't be asked for  password)? [Y/n]: " add_group
	add_group="${add_group:-Y}"
	
    if [[ "$add_group" =~ ^[Yy]$ ]]; then
       usermod -aG pihole "$USER"
      echo -e "\nUser '$USER' added to the 'pihole' group. You may need to log out and back in for this to take effect."
    else
      echo -e "\nSkipping group membership change."
    fi
  else
    echo "Skipping Pi-hole installation."
  fi
fi

#-------------PIVPN INSTALLATION-------------------
echo
if [ -d /etc/pivpn ]; then
  echo "PiVPN is already installed."
else
  read -rp "PiVPN is not installed. Do you want to install it now? [Y/n]: " install_pivpn
  install_pivpn="${install_pivpn:-Y}"

  if [[ "$install_pivpn" =~ ^[Yy]$ ]]; then
    echo -e "\nInstalling PiVPN..."
    curl -L https://install.pivpn.io | bash
    echo -e "\nPiVPN installation completed."
    # Determine protocol
    if [ -f /etc/pivpn/wireguard/setupVars.conf ]; then
      vpn_type="wireguard"
    elif [ -f /etc/pivpn/openvpn/setupVars.conf ]; then
      vpn_type="openvpn"
    else
      echo -e "\nCould not determine VPN type."
      vpn_type="unknown"
    fi

    # Add VPN client
    if [[ "$vpn_type" == "wireguard" || "$vpn_type" == "openvpn" ]]; then
      read -rp "Do you want to add your first VPN client now? [Y/n]: " add_client
      add_client="${add_client:-Y}"

      if [[ "$add_client" =~ ^[Yy]$ ]]; then
        read -rp "Enter a name for the new VPN client: " client_name
         pivpn add -n "$client_name"

        # Show QR code (WireGuard only)
        if [[ "$vpn_type" == "wireguard" ]]; then
          read -rp "Do you want to display a QR code for easy mobile setup? [Y/n]: " show_qr
          show_qr="${show_qr:-Y}"

          if [[ "$show_qr" =~ ^[Yy]$ ]]; then
             pivpn -qr "$client_name"
            echo "Scan the QR code above with your mobile WireGuard app."
			read -rp "Press any key to continue..." -n1 -s
          else
            echo "Skipping QR code display."
          fi
        fi
      else
        echo "Skipping VPN client creation."
      fi

      echo -e "\nTo add more clients in the future, run:"
      echo "    pivpn add"
      [ "$vpn_type" == "wireguard" ] && echo "    pivpn -qr <client_name>  # To show QR for WireGuard"
    fi
  else
    echo "Skipping PiVPN installation."
  fi
fi

#-------------UFW INSTALLATION-----------------------
echo
if command -v ufw >/dev/null 2>&1; then
  echo "UFW is already installed."
else
  read -rp "UFW is not installed. Do you want to install it now? [Y/n]: " install_ufw
  install_ufw="${install_ufw:-Y}"

  if [[ "$install_ufw" =~ ^[Yy]$ ]]; then
    echo -e "\nInstalling UFW (Uncomplicated Firewall)..."
    apt install -y ufw
    echo -e "\nUFW installation completed."
  else
    echo "Skipping UFW installation."
  fi
fi

#-------------UFW CONFIGURATION------------------------
echo

# Detect defaults
vpn_interface=$(ip link show | grep -Eo 'wg[0-9]+|tun[0-9]+' | head -n1 || true)
vpn_subnet=""
vpn_port=""
lan_interface=$(ip route | grep default | awk '{print $5}')
lan_subnet=$(ip -o -f inet addr show eth0 | awk '{print $4}' | sed 's/[0-9]*\/[0-9]*$/0\/24/')

# Detect WireGuard settings if present
if [[ -f /etc/wireguard/$vpn_interface.conf ]]; then
vpn_port=$( grep -E '^ListenPort\s*=' /etc/wireguard/$vpn_interface.conf | awk -F '=' '{print $2}' | xargs)
vpn_proto="udp"
vpn_subnet=$(grep Address /etc/wireguard/$vpn_interface.conf | awk '{print $3}' | sed 's/[0-9]*\/[0-9]*$/0\/24/')
fi

# Detect OpenVPN settings if WireGuard not found
if [[ -z "$vpn_port" && -f /etc/openvpn/server.conf ]]; then
vpn_port=$( grep '^port ' /etc/openvpn/server.conf | awk '{print $2}' | xargs)
vpn_proto=$( grep '^proto ' /etc/openvpn/server.conf | awk '{print $2}' | xargs)
vpn_subnet=$( grep '^server ' /etc/openvpn/server.conf | awk '{print $2}' | sed -E 's/([0-9]+\.[0-9]+\.[0-9]+)\.[0-9]+/\1.0\/24/' | xargs)
fi

if ! command -v ufw >/dev/null 2>&1; then
  echo "UFW not installed. Skipping firewall setup."
else
  # Check if any rules exist
  existing_rules=$( {  grep -c '^### tuple' /etc/ufw/user.rules; } || { echo 0; } )
  existing_rules=$(echo "$existing_rules" | tr -dc '0-9')
  default_skip="Y"
  if [[ "$existing_rules" -eq 0 ]]; then
    default_skip="N"
    read -rp "No rules detected. Do you want to skip firewall configuration? [y/N]: " skip_ufw
  else
    read -rp "Rules detected. Do you want to skip firewall configuration? [Y/n]: " skip_ufw
  fi

  skip_ufw="${skip_ufw:-$default_skip}"

  if [[ "$skip_ufw" =~ ^[Yy]$ ]]; then
    echo "Skipping UFW configuration."
  else
  
	echo -e "\nResetting UFW rules..."
	ufw --force reset
	echo "Adding new UFW rules..."
	
	# LOOPBACK
	ufw allow in on lo comment "Loopback traffic"
	
    # SSH from LAN
    ufw allow in from "$lan_subnet" to any port 22 proto tcp comment "SSH from LAN"

    # DNS from LAN
    ufw allow in from "$lan_subnet" to any port 53 comment "DNS from LAN"

    # HTTP from LAN
    ufw allow in from "$lan_subnet" to any port 80 proto tcp comment "HTTP from LAN"
	
	# HTTPS from LAN
    ufw allow in from "$lan_subnet" to any port 443 proto tcp comment "HTTPS from LAN"
	
	# DHCP
    ufw allow in from "$lan_subnet" to any port 67, 68 proto udp comment "DHCP from LAN"
	
	# NTP
	ufw allow in ntp comment "NTP Server"
	
	# Allow DHCP client requests (broadcasts to server)
	ufw allow in from 0.0.0.0 port 68 proto udp to 255.255.255.255 port 67 comment "DHCP client requests"
	
	# SSH brute-force protection
    ufw limit ssh comment "Limit SSH connection rate"

	if [[ -z "$vpn_interface" ]]; then
	  echo -e "\nNo VPN interface detected. Skipping VPN firewall rules."
	else
	  echo -e "\nDetected VPN interface: $vpn_interface"
	  
	  # VPN port
	  ufw allow in "$vpn_port"/"$vpn_proto" comment "VPN port"
	  
	  # SSH from VPN
      ufw allow in from "$vpn_subnet" to any port 22 proto tcp comment "SSH from VPN"
	  
	  # DNS from VPN
      ufw allow in from "$vpn_subnet" to any port 53 comment "DNS from VPN"
	  
	  # HTTP from VPN
      ufw allow in from "$vpn_subnet" to any port 80 proto tcp comment "HTTP from VPN"
	  
	  # HTTPS from VPN
      ufw allow in from "$vpn_subnet" to any port 443 proto tcp comment "HTTPS from VPN"

	  # Allow routed traffic from VPN to LAN subnet
	  ufw route allow in on "$vpn_interface" out on "$lan_interface" to "$lan_subnet" comment "Allow VPN clients to access LAN"
	fi
	
	# Add MASQUERADE NAT rule (only if missing)
	masq_rule="-A POSTROUTING -s $vpn_subnet -o $lan_interface -j MASQUERADE"
	if ! grep -qF -- "$masq_rule" /etc/ufw/before.rules; then
	  echo "Adding MASQUERADE rule to /etc/ufw/before.rules..."
	  sed -i "/^*filter/i *nat\n:POSTROUTING ACCEPT [0:0]\n$masq_rule\nCOMMIT\n" /etc/ufw/before.rules
	  echo "NAT MASQUERADE rule added for VPN subnet $vpn_subnet on $lan_interface"
	else
	  echo "MASQUERADE rule already present. Skipping."
	fi
	
	# Enable IP forwarding in sysctl.conf
	sed -i 's|^#*net.ipv4.ip_forward=.*|net.ipv4.ip_forward=1|' /etc/sysctl.conf
	sysctl -w -q net.ipv4.ip_forward=1
	
	# Set UFW default forward policy to ACCEPT
	sed -i 's|^DEFAULT_FORWARD_POLICY=.*|DEFAULT_FORWARD_POLICY="ACCEPT"|' /etc/default/ufw
	
	# Optional: restrict outgoing traffic
	read -rp $'\nDo you want to restrict outgoing traffic and allow only essential ports? [y/N]: ' restrict_outgoing
	restrict_outgoing="${restrict_outgoing:-N}"

	if [[ "$restrict_outgoing" =~ ^[Yy]$ ]]; then
	  echo "Applying restrictive outgoing firewall settings..."
	  ufw default deny outgoing
	  echo "Allowing essential outgoing ports..."
	  ufw allow out on lo comment "Loopback traffic"
	  ufw allow out 22/tcp comment "Allow SSH"
	  ufw allow out 53 comment "Allow DNS"
	  ufw allow out 80,443/tcp comment "Allow HTTP"
	  ufw allow out 67,68/udp comment "Allow DHCP"
	  ufw allow out ntp comment "Allow NTP Server"
	  ufw allow out "$vpn_port"/"$vpn_proto" comment "Allow VPN port"
	  ufw allow out on "$lan_interface" from "$vpn_subnet" comment "Allow VPN clients to access Internet"
	  ufw allow out from "$lan_subnet" port 67 proto udp to 255.255.255.255 port 68 comment "Allow DHCP server responses"
	fi
	
	# Enable UFW
    echo -e "\nEnabling UFW..."
    ufw --force enable
	echo -e "\nUFW Status:"
	ufw status verbose
  fi
  
  ufw_reload_required=false
  
  echo
  
  # Block pings (ICMP)  
  if grep -qF -- "-A ufw-before-input -p icmp --icmp-type echo-request -j DROP" /etc/ufw/before.rules; then
	read -rp "ICMP ping blocking is currently active. Do you want to enable ICMP ping? [y/N]: " unblock_icmp
	unblock_icmp="${unblock_icmp:-N}"
  
	if [[ "$unblock_icmp" =~ ^[Yy]$ ]]; then
	  echo "Enabling ICMP echo-request..."
	  
	  # Uncomment the echo-request rule
	  sed -i '/^#.*--icmp-type echo-request/s/^# //' /etc/ufw/before.rules

      # Remove generic ICMP DROP rule
      sed -i '/icmp.*DROP/d' /etc/ufw/before.rules
	  sed -i '/-s.*echo-request/d' /etc/ufw/before.rules
	  
	  ufw_reload_required=true

      echo "ICMP ping enabled."
	else
	  echo "Skipping enabling ICMP — ping remains blocked."
	fi
  else
	read -rp $'ICMP ping blocking is currently not active. Do you want to block ICMP ping? [Y/n]: ' block_icmp
	block_icmp="${block_icmp:-Y}"

	if [[ "$block_icmp" =~ ^[Yy]$ ]]; then
	  echo "Blocking ICMP echo-request in UFW..."
		
	  # Insert DROP rule before COMMIT only if not already present
	  if ! grep -q 'icmp.*DROP' /etc/ufw/before.rules; then
		
		# Comment out echo-request allowance
		sed -i '/--icmp-type echo-request/s/^/# /' /etc/ufw/before.rules
		  
		sed -i "/^# -A ufw-before-input -p icmp --icmp-type echo-request/a -A ufw-before-input -p icmp --icmp-type echo-request -j DROP" /etc/ufw/before.rules
		sed -i "/^# -A ufw-before-input -p icmp --icmp-type echo-request/a -A ufw-before-input -s $lan_subnet -p icmp --icmp-type echo-request -j ACCEPT" /etc/ufw/before.rules
		  
		sed -i "/^# -A ufw-before-forward -p icmp --icmp-type echo-request/a -A ufw-before-forward -p icmp --icmp-type echo-request -j DROP" /etc/ufw/before.rules
		sed -i "/^# -A ufw-before-forward -p icmp --icmp-type echo-request/a -A ufw-before-forward -s $lan_subnet -p icmp --icmp-type echo-request -j ACCEPT" /etc/ufw/before.rules
		  
		if [ "$vpn_subnet" ]; then
		  sed -i "/^# -A ufw-before-input -p icmp --icmp-type echo-request/a -A ufw-before-input -s $vpn_subnet -p icmp --icmp-type echo-request -j ACCEPT" /etc/ufw/before.rules
			
		  sed -i "/^# -A ufw-before-forward -p icmp --icmp-type echo-request/a -A ufw-before-forward -s $vpn_subnet -p icmp --icmp-type echo-request -j ACCEPT" /etc/ufw/before.rules
		fi
	  fi
	  
	  ufw_reload_required=true
	  
	  echo "ICMP ping allowed from LAN/VPN, blocked from Internet."
	else
	  echo "Skipping ICMP blocking — ping remains unblocked."
	fi
  fi
  
  echo
  
  # IPv6 detection
  ipv6_disabled_in_ufw=$(grep -q '^IPV6=no' "/etc/default/ufw" && echo "yes" || echo "no")
  ipv6_disabled_in_sysctl=$(grep -q 'net.ipv6.conf.all.disable_ipv6 = 1' "/etc/sysctl.conf" && echo "yes" || echo "no")
  
  if [[ "$ipv6_disabled_in_ufw" == "yes" && "$ipv6_disabled_in_sysctl" == "yes" ]]; then
	read -rp "IPv6 is currently disabled. Do you want to enable IPv6? [y/N]: " reenable_ipv6
	reenable_ipv6="${reenable_ipv6:-N}"

	if [[ "$reenable_ipv6" =~ ^[Yy]$ ]]; then
	  echo "Enabling IPv6..."
	  
	  # Remove sysctl disables
      sed -i '/^net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
      sed -i '/^net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf

      # Re-enable immediately (in current session)
      sysctl -w -q net.ipv6.conf.all.disable_ipv6=0
      sysctl -w -q net.ipv6.conf.default.disable_ipv6=0

      # Enable IPv6 in UFW config
      sed -i 's/^IPV6=.*/IPV6=yes/' /etc/default/ufw
	  
	  ufw_reload_required=true

      echo "IPv6 has been enabled system-wide and in UFW."
	else
	  echo "Skipping enabling IPv6 — remains disabled."
	fi
  else
	read -rp $'IPv6 is currently enabled. Do you want to disable IPv6? [Y/n]: ' disable_ipv6
	disable_ipv6="${disable_ipv6:-Y}"
	
	if [[ "$disable_ipv6" =~ ^[Yy]$ ]]; then
	  echo "Disabling IPv6..."
	  
	  # Remove previous sysctl settings if any
	  sed -i '/^net.ipv6.conf.all.disable_ipv6/d' /etc/sysctl.conf
      sed -i '/^net.ipv6.conf.default.disable_ipv6/d' /etc/sysctl.conf

      # Append disable lines
      echo 'net.ipv6.conf.all.disable_ipv6 = 1' | tee -a /etc/sysctl.conf >/dev/null
      echo 'net.ipv6.conf.default.disable_ipv6 = 1' | tee -a /etc/sysctl.conf >/dev/null
	
	  # Apply settings
      sysctl -p -q
	
	  # Disable IPv6 in UFW config
      sed -i 's/^IPV6=.*/IPV6=no/' /etc/default/ufw
	  
	  ufw_reload_required=true
	  
	  echo "IPv6 has been disabled system-wide and in UFW."
	else
	  echo "Skipping disabling IPv6 — remains enabled."
	fi
  fi
  
  # Reload UFW to apply changes
  if [[ "$ufw_reload_required" == true ]]; then
	echo -e "\nReloading UFW to apply changes...\n"
	ufw reload
  fi
fi

#-------------PiOS CONFIGURATION------------------------
echo

# List of services to optionally disable or mask
declare -A disable_targets=(
  [bluetooth.service]="Disable Bluetooth (not used)"
  [triggerhappy.service]="Disable triggerhappy hotkey daemon (not used)"
  [ModemManager.service]="Disable 3G/4G modem support (not used)"
  [wpa_supplicant.service]="Disable Wi-Fi support (Ethernet-only setup)"
)

# Check if all of them are already disabled or masked
all_disabled=true
any_already_disabled=false
already_disabled_services=()

for service in "${!disable_targets[@]}"; do
  if systemctl is-enabled --quiet "$service" || systemctl is-active --quiet "$service"; then
    all_disabled=false
    break
  fi
done

if [[ "$all_disabled" == true ]]; then
  echo "All recommended services are already disabled or masked. Skipping this step."
  echo "If you want to re-enable any of them later, use the following commands:"

  for service in "${!disable_targets[@]}"; do
    is_masked=$(systemctl show -p LoadState --value "$service")
    if [[ "$is_masked" == "masked" ]]; then
	  echo "  sudo systemctl unmask $service && sudo systemctl enable --now $service"
    else
	  echo "  sudo systemctl enable --now $service"
    fi
  done
else
  read -rp $'Do you want to disable unnecessary services to reduce CPU and RAM usage [Y/n]: ' disable_services
  disable_services="${disable_services:-Y}"
  
  if [[ "$disable_services" =~ ^[Yy]$ ]]; then
	for service in "${!disable_targets[@]}"; do
	  description="${disable_targets[$service]}"
	  is_enabled=$(systemctl is-enabled "$service" 2>/dev/null || echo "disabled")
	  is_active=$(systemctl is-active "$service" 2>/dev/null || echo "inactive")
	  
	  if [[ "$is_enabled" == "enabled" || "$is_active" == "active" ]]; then
	    echo -e "\n[$service] $description"
		echo "Current status: enabled = $is_enabled, active = $is_active"
		read -rp "Disable this service? [Y/n]: " disable_choice
		disable_choice="${disable_choice:-Y}"
		
		if [[ "$disable_choice" =~ ^[Yy]$ ]]; then
		  echo "Disabling $service..."
		  systemctl -q disable --now "$service" 2>/dev/null || true
		  if [[ "$service" =~ ^(bluetooth|wpa_supplicant)\.service$ ]]; then
			systemctl -q mask "$service"
			echo "$service has been disabled and masked."
			echo "To re-enable: sudo systemctl unmask $service && sudo systemctl enable --now $service"
		  else
			echo "$service has been disabled."
			echo "To re-enable: sudo systemctl enable --now $service"
		  fi
		else
		  echo "Skipped $service."
		fi
	  else
		echo -e "\n$service is already disabled or masked."
		any_already_disabled=true
		already_disabled_services+=("$service")
	  fi
	done
	echo -e "\nDisabling unnecessary services is done"
	if [[ "$any_already_disabled" == true ]]; then
      echo -e "\nTo re-enable services were already disabled or masked:"
      for service in "${already_disabled_services[@]}"; do
	    is_masked=$(systemctl show -p LoadState --value "$service")
		if [[ "$is_masked" == "masked" ]]; then
		  echo "  sudo systemctl unmask $service && sudo systemctl enable --now $service"
		else
          echo "  sudo systemctl enable --now $service"
		fi
      done
	fi
  else
	echo "Skipping disable unnecessary services."
  fi
fi
  
echo

# Harden shared memory
shm_entry_hardened='tmpfs /dev/shm tmpfs defaults,noexec,nosuid,nodev 0 0'
shm_entry_normal='tmpfs /dev/shm tmpfs defaults 0 0'

if grep -qF "$shm_entry_hardened" "/etc/fstab"; then
  read -rp "Shared memory is currently hardened (noexec,nosuid,nodev). Do you want to restore default settings? [y/N]: " undo_shm
  undo_shm="${undo_shm:-N}"
  
  if [[ "$undo_shm" =~ ^[Yy]$ ]]; then
	echo "Restoring default settings..."
	
    sed -i '\|/dev/shm tmpfs|d' "/etc/fstab"
    echo "$shm_entry_normal" | tee -a "/etc/fstab" >/dev/null
    mount -o remount /dev/shm 2>/dev/null
	
    echo "Shared memory restored to default."
  else
    echo "Skipping restoring default settings — remains hardened."
  fi
else
  read -rp "Shared memory is currently not hardened. Do you want to harden shared memory? [Y/n]: " do_shm
  do_shm="${do_shm:-Y}"
  
  if [[ "$do_shm" =~ ^[Yy]$ ]]; then
	echo "Hardening shared memory..."
	
    sed -i '\|/dev/shm tmpfs|d' "/etc/fstab"
    echo "$shm_entry_hardened" | tee -a "/etc/fstab" >/dev/null
    mount -o remount /dev/shm 2>/dev/null
	
    echo "Shared memory hardened."
  else
    echo "Skipping shared memory hardening."
  fi
fi

echo

# Harden /tmp
tmp_entry_hardened='tmpfs /tmp tmpfs defaults,noexec,nosuid,nodev 0 0'
tmp_entry_normal='tmpfs /tmp tmpfs defaults 0 0'
is_tmp_mounted_tmpfs=$(mount | grep -qE '^tmpfs on /tmp ' && echo "yes" || echo "no")

if grep -qF "$tmp_entry_hardened" "/etc/fstab"; then
  read -rp "/tmp is already hardened (noexec,nosuid,nodev). Do you want to restore default /tmp settings? [y/N]: " undo_tmp
  undo_tmp="${undo_tmp:-N}"
  
  if [[ "$undo_tmp" =~ ^[Yy]$ ]]; then
	echo "Restoring default settings..."
	
    sed -i '\|/tmp tmpfs|d' "/etc/fstab"
    echo "$tmp_entry_normal" | tee -a "/etc/fstab" >/dev/null
	
	if [[ "$is_tmp_mounted_tmpfs" == "yes" ]]; then
      mount -o remount /tmp 2>/dev/null
	else
	  echo "/tmp is not mounted separately; changes will apply after reboot."
	fi
    
	echo "/tmp restored to default."
  else
    echo "Skipping restoring default settings — remains hardened."
  fi
else
  read -rp "/tmp is not hardened. Do you want to harden /tmp with noexec,nosuid,nodev? [Y/n]: " do_tmp
  do_tmp="${do_tmp:-Y}"
  
  if [[ "$do_tmp" =~ ^[Yy]$ ]]; then
	echo "Hardening /temp..."
	
    sed -i '\|/tmp tmpfs|d' "/etc/fstab"
    echo "$tmp_entry_hardened" | tee -a "/etc/fstab" >/dev/null
	
	if [[ "$is_tmp_mounted_tmpfs" == "yes" ]]; then
      mount -o remount /tmp 2>/dev/null
	  
	  echo "/tmp hardened."
    else
	  echo "/tmp is not mounted separately; tmpfs hardening will take effect after reboot."
	fi
  else
    echo "Skipping /tmp hardening."
  fi
fi

echo

# Prompt for other kernel tweaks
read -rp $'Do you want to apply additional kernel/system hardening tweaks (restrict dmesg, kernel pointers, core dumps)? [y/N]: ' apply_kernel_hardening
apply_kernel_hardening="${apply_kernel_hardening:-N}"
sysctl_reload_needed=false

if [[ "$apply_kernel_hardening" =~ ^[Yy]$ ]]; then
	echo
	
  # Restrict kernel log access (dmesg)
  if grep -q '^kernel.dmesg_restrict=1' "/etc/sysctl.conf"; then
	read -rp "Kernel log access is currently restricted. Do you want to allow access? [y/N]: " undo_dmesg
	undo_dmesg="${undo_dmesg:-N}"
	
	if [[ "$undo_dmesg" =~ ^[Yy]$ ]]; then
	  echo "Restoring kernel log access..."
	  
	  sed -i '/^kernel.dmesg_restrict=1/d' "/etc/sysctl.conf"
	  echo 'kernel.dmesg_restrict=0' | tee -a /etc/sysctl.conf >/dev/null
	  
	  echo "Kernel log access restored."
	  
	  sysctl_reload_needed=true
	else
	  echo "Skipping restoring kernel log access."
	fi
  else
	read -rp "Kernel log access is currently unrestricted. Do you want to restrict access to root only? [Y/n]: " do_dmesg
	do_dmesg="${do_dmesg:-Y}"
	
	if [[ "$do_dmesg" =~ ^[Yy]$ ]]; then
	  echo "Restricting kernel log access..."
	  
	  sed -i '/^kernel.dmesg_restrict=0/d' "/etc/sysctl.conf"
	  echo 'kernel.dmesg_restrict=1' | tee -a "/etc/sysctl.conf" >/dev/null
	  
	  echo "Kernel log access restricted to root."
	  
	  sysctl_reload_needed=true
	else
	  echo "Skipping kernel log access restriction."
	fi
  fi
  
  echo

  # Restrict kernel pointer exposure
  if grep -q '^kernel.kptr_restrict=2' "/etc/sysctl.conf"; then
	read -rp "Kernel pointer exposure is currently restricted. Do you want to restore default access? [y/N]: " undo_kptr
	undo_kptr="${undo_kptr:-N}"
	
	if [[ "$undo_kptr" =~ ^[Yy]$ ]]; then
	  echo "Restoring kernel pointer exposure..."
	  
      sed -i '/^kernel.kptr_restrict=2/d' "/etc/sysctl.conf"
	  echo 'kernel.kptr_restrict=0' | tee -a "/etc/sysctl.conf" >/dev/null
	  
      echo "Kernel pointer exposure restored."
	  
	  sysctl_reload_needed=true
	else
      echo "Skipping restoring kernel pointer exposure."
	fi
  else
	read -rp "Kernel pointer exposure is not restricted. Do you want to restrict kernel pointer exposure? [Y/n]: " do_kptr
	do_kptr="${do_kptr:-Y}"
	
	if [[ "$do_kptr" =~ ^[Yy]$ ]]; then
	  echo "Restricting kernel pointer exposure..."
	  
	  sed -i '/^kernel.kptr_restrict=0/d' "/etc/sysctl.conf"
      echo 'kernel.kptr_restrict=2' | tee -a "/etc/sysctl.conf" >/dev/null
	  
      echo "Kernel pointer exposure restricted."
	  
	  sysctl_reload_needed=true
	else
      echo "Skipping kernel pointer restriction."
    fi
  fi
  
  echo

  #Disable core dumps
  if grep -q '^\* hard core 0' "/etc/security/limits.conf" && grep -q '^fs.suid_dumpable=0' "/etc/sysctl.conf"; then
	read -rp "Core dumps are currently disabled. Do you want to enable core dumps? [y/N]: " undo_core
	undo_core="${undo_core:-N}"
	
	if [[ "$undo_core" =~ ^[Yy]$ ]]; then
	  echo "Enabling core dumps..."
	  
      sed -i '/^\* hard core 0/d' "/etc/security/limits.conf"
      sed -i '/^fs.suid_dumpable=0/d' "/etc/sysctl.conf"
	  echo 'fs.suid_dumpable=1' | tee -a "/etc/sysctl.conf" >/dev/null
      
	  echo "Core dumps enabled."
	  
	  sysctl_reload_needed=true
	else
      echo "Skipping enabling core dumps."
	fi
  else
	read -rp "Core dumps are currently allowed. Do you want to disable core dumps? [Y/n]: " do_core
	do_core="${do_core:-Y}"
	
	if [[ "$do_core" =~ ^[Yy]$ ]]; then
	  echo "Disabling core dumps..."
	
      sed -i '/^\* hard core/d' /etc/security/limits.conf
	  echo '* hard core 0' | tee -a "/etc/security/limits.conf" >/dev/null
	  sed -i '/^fs.suid_dumpable=1/d' /etc/sysctl.conf
      echo 'fs.suid_dumpable=0' | tee -a "/etc/sysctl.conf" >/dev/null
	  
      echo "Core dumps disabled."
	  
	  sysctl_reload_needed=true
	else
      echo "Skipping disabling core dump."
	fi
  fi
  
  echo
  
  # Reload sysctl only if needed
  if [[ "$sysctl_reload_needed" == true ]]; then
	echo "Reloading kernel sysctl parameters..."
	sysctl -p -q
	echo "sysctl settings reloaded."
  else
	echo "No kernel settings needed to be reloaded."
  fi
else
  echo "Skipping kernel/system hardening tweaks."
fi

#-------------SCHEDULE CONFIGURATION--------------------
echo

# Check for existing reboot cron job
existing_reboot_job=$( (crontab -l 2>/dev/null || true) | grep -F "/sbin/reboot" | grep -F "# Auto reboot" || true )
skip_reboot_scheduling=false
cron_line=""

echo "It is recommended to schedule periodic reboots after system updates."

if [[ -n "$existing_reboot_job" ]]; then
  echo "An automatic reboot is already scheduled:"
  echo "   $existing_reboot_job"
  echo
  read -rp "Do you want to update the existing schedule? [y/N]: " update_choice
  update_choice="${update_choice:-N}"
  
  if [[ "$update_choice" =~ ^[Nn]$ ]]; then
	echo "Leaving existing schedule unchanged."
	skip_reboot_scheduling=true
  else
	# Safely capture current crontab to a temp file (if it exists)
	tmp_cron="/tmp/current_cron.$$"
	crontab -l 2>/dev/null > "$tmp_cron" || true

	# Remove reboot jobs safely
	grep -vF "/sbin/reboot" "$tmp_cron" > "$tmp_cron.cleaned" || true

	# Compare and apply only if modified
	if ! cmp -s "$tmp_cron" "$tmp_cron.cleaned"; then
	  crontab "$tmp_cron.cleaned"
	  echo "Existing schedule removed from crontab."
	else
	  echo "No reboot job found in crontab — nothing to remove."
	fi
	
	# Clean up temp files
    rm -f "$tmp_cron" "$tmp_cron.cleaned"
  fi
fi

# Prompt for new schedule
if [[ "$skip_reboot_scheduling" == false ]]; then
  echo "Let's set up a new reboot schedule. You can choose to reboot daily, weekly, or monthly at a specific time."
  
  for attempt in {1..3}; do
	echo "Select reboot frequency:"
	echo "1) Daily"
	echo "2) Weekly"
	echo "3) Monthly"
	echo "4) Cancel / Skip"
	
	read -rp "Enter choice [1-4]: " freq_choice

	case "$freq_choice" in
	  1)
		# Daily reboot
		for i in {1..3}; do
		  read -rp "Enter time of day for daily reboot (24h format HH:MM): " reboot_time
		  if [[ "$reboot_time" =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; then
			hour="${reboot_time%:*}"
			minute="${reboot_time#*:}"
			cron_line="$minute $hour * * * /sbin/reboot # Auto reboot (daily)"
			break
		  else
			echo "Invalid time format (try $i of 3)."
		
			[[ "$i" -eq 3 ]] && echo "Skipping scheduled reboot." && skip_reboot_scheduling=true && break
		  fi
		done
		;;
	  
	  2)
		# Weekly reboot
		for i in {1..3}; do
		  read -rp "Enter day of week (e.g. mon): " reboot_day
		  read -rp "Enter time (HH:MM): " reboot_time
	  
		  # Convert day name to cron number (0=Sun to 6=Sat)
		  days_map=(sun mon tue wed thu fri sat)
		  day_num=-1
		  for j in "${!days_map[@]}"; do
			[[ "${reboot_day,,}" == "${days_map[$j],,}"* ]] && day_num=$j && break
		  done

		  if [[ "$day_num" -ge 0 && "$day_num" -le 6 ]]; then
			if [[ "$reboot_time" =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; then
			  hour="${reboot_time%:*}"
			  minute="${reboot_time#*:}"
			  cron_line="$minute $hour * * $day_num /sbin/reboot # Auto reboot (weekly)"
			  break
			else
			  echo "Invalid time format (try $i of 3)."
			fi
		  else
			echo "Invalid weekday name (try $i of 3)."
		  fi

		  [[ "$i" -eq 3 ]] && echo "Skipping scheduled reboot." && skip_reboot_scheduling=true && break
		done
		;;

	  3)
		# Monthly reboot
		for i in {1..3}; do
		  read -rp "Enter day of month (1–31): " reboot_dom
		  read -rp "Enter time (HH:MM): " reboot_time
		  
		  if [[ "$reboot_dom" =~ ^([1-9]|[12][0-9]|3[01])$ ]]; then
			if [[ "$reboot_time" =~ ^([01]?[0-9]|2[0-3]):[0-5][0-9]$ ]]; then
			  hour="${reboot_time%:*}"
			  minute="${reboot_time#*:}"
			  cron_line="$minute $hour $reboot_dom * * /sbin/reboot # Auto reboot (monthly)"
			  break
			else
			  echo "Invalid time format (try $i of 3)."
			fi
		  else
			echo "Invalid day of month (try $i of 3)."
		  fi

		  [[ "$i" -eq 3 ]] && echo "Skipping scheduled reboot." && skip_reboot_scheduling=true && break
		done
		;;

	  4)
		echo "Cancelled — no scheduled reboot set."
		skip_reboot_scheduling=true
		;;
	  
	  *)
		echo -e "Invalid choice (try $attempt of 3).\n"
		[[ "$attempt" -eq 3 ]] && echo "Skipping reboot scheduling." && skip_reboot_scheduling=true
		;;
    esac
	
	# If a valid option was selected and handled, exit the retry loop
	[[ "$skip_reboot_scheduling" == true || -n "$cron_line"  ]] && break
  done
fi

# Add to crontab
if [[ "$skip_reboot_scheduling" == false ]]; then
  (crontab -l 2>/dev/null; echo "$cron_line") | crontab -
  echo -e "\nScheduled reboot added:"
  echo "   $cron_line"
fi

echo

# Define update script path
update_script="/usr/local/sbin/rpi-weekly-maintenance.sh"

# Write the script from within this script
echo "Creating auto-update script at $update_script..."

tee "$update_script" >/dev/null << 'EOF'
#!/bin/bash
# Auto maintenance: system + Pi-hole + PiVPN updates

# Silent system upgrade
apt update && apt upgrade -y

# Pi-hole update
if command -v pihole &>/dev/null; then
  pihole -up
fi

# PiVPN update (assumes default answers)
if command -v pivpn &>/dev/null; then
  pivpn -up <<< $'y\ny\n' >/dev/null
fi
EOF

# Make it executable
chmod +x "$update_script"
echo "Maintenance script created and made executable."

# Add to root crontab (preserving other jobs)
cron_entry="45 3 * * 0 $update_script # Auto system+Pi-hole+PiVPN update"
if crontab -l 2>/dev/null | grep -qF "$update_script"; then
  echo "Maintenance job already exists in crontab. Skipping addition."
else
  (crontab -l 2>/dev/null; echo "$cron_entry") | crontab -
  echo "Weekly maintenance scheduled:"
  echo "   → Every Sunday at 03:45"
  echo "   → Command: $update_script"
fi

echo
echo -e "========================================="
echo -e "                 Summary                 "
echo -e "========================================="
echo
echo -e "Your Raspberry Pi has been configured with the following"
echo

# Pi-hole status
echo -n "Pi-hole: "
systemctl is-active --quiet pihole-FTL && echo "Running" || echo "Not running"

echo

# PiVPN
echo -n "PiVPN: "
[[ -d /etc/wireguard || -d /etc/openvpn ]] && echo "Installed" || echo "Not installed"

# UFW status and rules
echo -e "\nUFW Firewall Status:"

if ufw status | grep -q "Status: active"; then
  echo -n "UFW is active — "

  # Check if any rules exist in user.rules
  rule_count=$(grep -c '^### tuple' /etc/ufw/user.rules 2>/dev/null || echo 0)
  if [[ "$rule_count" -gt 0 ]]; then
    echo "$rule_count rules configured"
  else
    echo "No rules found"
  fi
else
  echo "UFW is inactive"
fi

# ICMP Block
echo -n "ICMP (ping) requests: "
if grep -qE '^-A ufw-before-input -p icmp --icmp-type echo-request -j DROP' /etc/ufw/before.rules; then
  echo "Blocked"
else
  echo "Allowed"
fi

# IPv6
echo -n "IPv6 support: "
sysctl net.ipv6.conf.all.disable_ipv6 2>/dev/null | grep -q "= 1" && echo "Disabled" || echo "Enabled"

# Service hardening summary
echo -e "\nUnneeded Services Status:"

recommended_services=(bluetooth wpa_supplicant ModemManager triggerhappy)

disabled_all=true
for svc in "${recommended_services[@]}"; do
  if systemctl is-enabled "$svc" 2>/dev/null | grep -q enabled; then
    echo "$svc is still enabled"
    disabled_all=false
  fi
done

if [[ "$disabled_all" == true ]]; then
  echo "All recommended services are disabled or masked"
fi

echo

# Shared memory
echo -n "/dev/shm hardened: "
if grep -q '/dev/shm' /etc/fstab && grep -q '/dev/shm.*noexec' /etc/fstab; then
  echo "Yes"
else
  echo "No"
fi

# /tmp hardening
echo -n "/tmp hardened: "
if grep -q '/tmp' /etc/fstab && grep -q '/tmp.*noexec' /etc/fstab; then
  echo "Yes"
else
  echo "No"
fi

echo -e "\nKernel Hardening Summary:"

# Check kptr
sysctl kernel.kptr_restrict 2>/dev/null | grep -q "= 2" && kptr=1 || kptr=0

# Check dmesg
sysctl kernel.dmesg_restrict 2>/dev/null | grep -q "= 1" && dmesg=1 || dmesg=0

# Check core dump
sysctl fs.suid_dumpable 2>/dev/null | grep -q "= 0" && dump=1 || dump=0

if [[ $kptr -eq 1 && $dmesg -eq 1 && $dump -eq 1 ]]; then
  echo "All optional kernel hardening tweaks applied"
else
  [[ $kptr -eq 0 ]] && echo "kernel.kptr_restrict not applied"
  [[ $dmesg -eq 0 ]] && echo "kernel.dmesg_restrict not applied"
  [[ $dump -eq 0 ]] && echo "core dump disabling not applied"
fi

echo

# Scheduled reboot
echo -n "Reboot schedule: "
(crontab -l 2>/dev/null || true) | grep -q "/sbin/reboot" && echo "Scheduled" || echo "None"

echo

read -rp "Rebooting is recommended to apply low-level changes. Reboot now? [Y/n]: " reboot_choice
reboot_choice="${reboot_choice:-Y}"

if [[ "$reboot_choice" =~ ^[Yy]$ ]]; then
  reboot
else
  echo -e "Reboot skipped. Run 'sudo reboot' when you're ready.\n"
fi

echo -e "========================================="
echo -e "All done!"
echo -e "You can now enjoy an ad-free experience from wherever you are."
echo -e "Thank you for using the pihole-vpn-setup script"
echo -e "=========================================\n"