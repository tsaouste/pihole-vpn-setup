# Pi-hole VPN Setup (`pihole-vpn-setup`)

🚀 **Ad-free browsing, everywhere you go**  
This project installs and configures **Pi-hole** and **PiVPN** (WireGuard/OpenVPN) on a Raspberry Pi, with **UFW firewall**, security hardening, and optional automation features.  

The script is fully interactive — guiding you step by step while letting you customize the configuration.  

---

## ✨ Features
- ✅ **Pi-hole installation & management**  
- ✅ **PiVPN setup** (WireGuard or OpenVPN)  
- ✅ **UFW firewall rules** with interactive prompts  
- ✅ **Security hardening** (ICMP, IPv6, `/tmp`, `/dev/shm`)  
- ✅ **Automatic updates & scheduled reboots**  
- ✅ **Friendly interactive prompts** for every choice  
- ✅ Can be safely **re-run anytime** to adjust settings  

---

## 📦 Installation
Download and install the latest release with just two commands:

```bash
wget https://raw.githubusercontent.com/tsaouste/pihole-vpn-setup/refs/heads/main/pihole-vpn-setup.sh
```
```bash
chmod +x pihole-vpn-setup.sh
```
---

## ▶️ Usage
After installation, simply run:

```bash
sudo ./pihole-vpn-setup.sh
```

The script will check what’s already installed and skip unnecessary steps.
You can re-run it anytime to adjust firewall rules, or reconfigure services.

---

## 🛠 Requirements
- Raspberry Pi (Zero 2 W or newer recommended)
- Raspberry Pi OS Lite (64-bit)
- Ethernet connection (preferred for stability)
- Sudo privileges

---

## 📚 Project Details
- 🔒 Security-first: designed to expose only VPN ports. Pi-hole services are available only via VPN or LAN.
- ⚡ Lightweight: unnecessary services (Bluetooth, Avahi, WPA, etc.) can be disabled interactively.
- 🌍 Mobile friendly: connect your phone via VPN → enjoy ad-free internet anywhere.

---

## 👨‍💻 Credits
This entire project was written with the help of ChatGPT (OpenAI),
fine-tuned through many iterations of testing and customization.

---

## 📝 License
MIT License – feel free to use, share, and modify with attribution.
