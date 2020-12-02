#!/bin/bash

#before beginning do this: make sure you're in a user's home directory, write down user's login, add admins in line 66-67, make the users.txt file for passwords
#also run this: 'dpkg -s apt-transport-https | grep -i status' and if it says 'Status: install ok installed' then run but if not run 'sudo apt-get install apt-transport-https'

#scanning system and noting stuff like mp3 locations, if there are any games, if there are any cronjobs, start up apps, last time someone tried to log on
cd ./Desktop/
sudo chpasswd < users.txt #this mass changes all users passwords. to do this the text file's contents are written like username:password
sudo find / -iname *.mp3 > mp3_files.txt
sudo updatedb
locate .mp3 >> mp3_files.txt
sudo find / -iname *.mp3 -exec rm -rf {} \;
echo 'games' > program_scan.txt
dpkg -l | grep game >> program_scan.txt
echo 'scanners' >> program_scan.txt
dpkg -l | grep scan >> program_scan.txt
echo 'password crackers' >> program_scan.txt
dpkg -l | grep crack >> program_scan.txt
echo 'ftp' >> program_scan.txt
dpkg -l | grep ftp >> program_scan.txt
echo 'samba' >> program_scan.txt
dpkg -l | grep samba >> program_scan.txt
echo 'xwindow system' >> program_scan.txt
dpkg -l xserver-xorg* >> program_scan.txt
sudo crontab -u root -l > root_crontab.txt
sudo crontab -r
sudo cat /root/.bash_history > bash_history.txt
echo 'start up init.d' > start_up.txt
ls -alrt /etc/init.d >> start_up.txt
echo 'rc.local' >> start_up.txt
ls -alrt /etc/rc.local >> start_up.txt
echo "users logged on" > last_logon.txt
sudo last >> last_logon.txt
echo "login fails" >> last_logon.txt
sudo lastb >> last_logon.txt
service --status-all > running_services.txt
sudo echo "ALL: ALL" >> /etc/hosts.deny
cat /etc/passwd | grep -E 1[0-9]{3} > users2.txt
sudo sed -i '/^APT::Periodic::Update-Package-Lists/ c\APT::Periodic::Update-Package-Lists "0";' /etc/a  pt/apt.conf.d/20auto-upgrades
#sudo sed -i '/^"${distro_id}:${distro_codename}-security";*$/ c\"${distro_id}:${distro_codename}-security";/' /etc/apt/apt.conf.d/50unattended-upgrades
#idk how to do this remotely do this but just comment out "${distro_id}:${distro_codename}-updates"; in /etc/apt/apt.conf.d/50unattended-upgrades


#checking for stuff that runs as root n stuff
sudo find / -perm -u=s -type f 2>/dev/null
sudo find / -perm 4000 -print > root_stuff.txt

#program stuff like enabling firewall, downloading good stuff, deleting bad stuff
sudo ufw enable
sudo ufw logging on
sudo ufw allow ssh
sudo apt-get remove --purge john -y
sudo apt-get remove --purge netcat-traditional -y
sudo apt-get remove --purge nginx -y
sudo apt-get remove --purge ophcrack -y
sudo apt-get remove --purge minetest -y
sudo apt-get remove --purge xinetd -y
sudo apt-get remove --purge telnetd -y
sudo apt-get remove --purge pure-ftpd -y
sudo apt-get remove --purge nmap -y
sudo apt-get remove --purge nis -y
sudo apt-get remove --purge rsh-client rsh-redone-client -y
sudo apt-get remove --purge talk -y
sudo apt-get remove --purge telnet -y
sudo apt-get remove --purge ldap-utils -y
sudo apt-get install aide -y
sudo apt-get install synaptic -y
sudo apt-get install gufw -y
sudo apt-get install ssh -y
sudo apt-get install clamav clamav-daemon -y
sudo apt-get install clamtk -y
#sudo apt-get install libpam-cracklib -y
sudo apt-get install bum -y
sudo apt-get install auditd -y
sudo apt-get install rkhunter -y
sudo synaptic
#aide -c /etc/aide.conf --init
sudo service ssh start
sudo apt-key adv --keyserver keyserver.ubuntu.com --recv-keys C80E383C3DE9F082E01391A0366C67DE91CA5D5F
sudo add-apt-repository "deb [arch=amd64] https://packages.cisofy.com/community/lynis/deb/ xenial main"
sudo apt-get install lynis -y
comm -23 <(apt-mark showmanual | sort -u) <(gzip -dc /var/log/installer/initial-status.gz | sed -n 's/^Package: //p' | sort -u) > man_downloaded.txt
#use  sudo cat /var/lib/dpkg/available | grep “Package:”  but put the packages found in man_downloaded.txt to delete package

#disable services
sudo systemctl disable cups
sudo systemctl disable postfix
sudo systemctl disable rsh
sudo systemctl disable isc-dhcp-server
sudo systemctl disable isc-dhcp-server6
sudo systemctl disable slapd
sudo systemctl disable nfs-kernel-server
sudo systemctl disable rpcbind
sudo systemctl disable bind9
sudo systemctl disable dovecot
sudo systemctl disable squid
sudo systemctl disable snmpd
sudo systemctl disable rsync
sudo systemctl disable nis
sudo systemctl enable auditd

#audit
#sudo chmod 777 /etc/audit/audit.rules
sudo sed -i '0,/^.*max_log_file_action.*$/s//max_log_file_action = keep_logs/' /etc/audit/auditd.conf
sudo echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
sudo echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
sudo echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
sudo echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
sudo echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
sudo echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
sudo echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
sudo echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
sudo echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
sudo echo "-w /etc/security/opasswd -p wa -k identity" >> /etc/audit/audit.rules
sudo echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules
sudo echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules
sudo echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules
sudo echo "-w /var/run/utmp -p wa -k session" >> /etc/audit/audit.rules
sudo echo "-w /var/log/wtmp -p wa -k session" >> /etc/audit/audit.rules
sudo echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules
sudo echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
sudo echo "-w /etc/sudoers.d -p wa -k scope" >> /etc/audit/audit.rules
sudo echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
sudo chmod 644 /etc/audit/audit.rules

#checking if certain services are disabled
echo 'chargen' > services.txt
grep -R "^chargen" /etc/inetd.* >> services.txt
echo 'daytime' >> services.txt
grep -R "^daytime" /etc/inetd.* >> services.txt
echo 'discard' >> services.txt
grep -R "^discard" /etc/inetd.* >> services.txt
echo 'echo' >> services.txt
grep -R "^echo" /etc/inetd.* >> services.txt
echo 'time' >> services.txt
grep -R "^time" /etc/inetd.* >> services.txt
echo 'rsh server' >> services.txt
grep -R "^shell" /etc/inetd.*
grep -R "^login" /etc/inetd.*
grep -R "^exec" /etc/inetd.*
echo 'talk' >> services.txt
grep -R "^talk" /etc/inetd.*
grep -R "^ntalk" /etc/inetd.*
echo 'telnet' >> services.txt
grep -R "^telnet" /etc/inetd.*
echo 'tftp' >> services.txt
grep -R "^tftp" /etc/inetd.*
echo 'xinetd' >> services.txt
sudo systemctl is-enabled xinetd

#configuring NON-package stuff like passwords, making people admin, disabling guest, ipv6
sudo chmod 777 /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
sudo chmod 777 /etc/pam.d/common-auth
sudo chmod 777 /etc/lightdm/lightdm.conf
sudo chmod 777 /etc/security/access.conf
sudo sed -i '/^PASS_MAX_DAYS/ c\PASS_MAX_DAYS   90'  /etc/login.defs
sudo sed -i '/^PASS_MIN_DAYS/ c\PASS_MIN_DAYS   15'  /etc/login.defs
sudo sed -i '/^PASS_WARN_AGE/ c\PASS_WARN_AGE   7' /etc/login.defs
#sudo sed -i 's/pam_cracklib.so/pam_cracklib.so retry=3 minlen=8 difolk=3 remember=5/g' /etc/pam.d/common-password
#sudo sed -i 's/pam_usix.so/pam_unix.so obscure use_authtok ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/g' /etc/pam.d/common-password
#echo 'auth required pam_telly2.so deny=5 onerr=fail unlock_time=1800' >> /etc/pam.d/common-auth
sudo passwd -l root
echo 'allow-guest=false' >> /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
echo 'allow-guest=false' >> /etc/lightdm/lightdm.conf
echo '-:root:ALL EXCEPT LOCAL' >> /etc/security/access.conf
echo 'exit 0' > /etc/rc.local
sudo sed -i '0,/^.*nameserver.*$/s//nameserver 8.8.8.8/' /etc/resolv.conf
sudo chmod 622 /etc/security/access.conf
sudo chmod 622 /usr/share/lightdm/lightdm.conf.d/50-ubuntu.conf
sudo chmod 622 /etc/pam.d/common-auth
sudo chmod 622 /etc/lightdm/lightdm.conf
sudo chmod 622 /etc/security/access.conf
sudo sed -i '0,/^.*adm:x:4:.*$/s//adm:x:4:[admin],[admin2]/' /etc/group
sudo sed -i '0,/^.*sudo:x:27:.*$/s//sudo:x:27:[admin1],[admin2]/' /etc/group

#make kernel more secure
sudo sysctl -w kernel.core_uses_pid=1
sudo sysctl -w kernel.ctrl-alt-del=0
sudo sysctl -w kernel.sysrq=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.secure_redirects=0
sudo sysctl -w net.ipv4.conf.default.secure_redirects=0
sudo sysctl -w net.ipv4.ip_forward=0
sudo sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sudo sysctl -w net.ipv4.conf.all.accept_source_route=0
sudo sysctl -w net.ipv6.conf.all.accept_source_route=0
sudo sysctl -w net.ipv4.conf.default.accept_source_route=0
sudo sysctl -w net.ipv6.conf.default.accept_source_route=0
sudo sysctl -w net.ipv4.conf.all.send_redirects=0
sudo sysctl -w net.ipv4.conf.default.send_redirects=0
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=2048
sudo sysctl -w net.ipv4.tcp_synack_retries=2
sudo sysctl -w net.ipv4.tcp_syn_retries=5
sudo sysctl -w net.ipv4.conf.all.log_martians=1
sudo sysctl -w net.ipv4.conf.default.log_martians=1
sudo sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
sudo sysctl -w net.ipv6.conf.all.accept_redirects=0
sudo sysctl -w net.ipv6.conf.default.accept_redirects=0
sudo sysctl -w net.ipv4.icmp_echo_ignore_all=1
sudo sysctl -w net.ipv4.tcp_syncookies=1
sudo sysctl -w net.ipv4.tcp_timestamps=0
sudo sysctl -w kernel.dmesg_restrict=1
sudo sysctl -w kernel.kptr_restrict=2
sudo sysctl -w net.ipv4.route.flush=1
sudo sysctl -w net.ipv6.conf.all.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.default.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.lo.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.eth0.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.eth1.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.eth2.disable_ipv6=1
sudo sysctl -w net.ipv6.conf.eth3.disable_ipv6=1
sudo sysctl -w kernel.randomize_va_space=2
sudo sysctl -w net.ipv4.conf.all.accept_redirects=0
sudo sysctl -w net.ipv4.conf.all.rp_filter=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sysctl -w net.ipv4.conf.all.rp_filte# r=1
sudo sysctl -w net.ipv4.conf.default.rp_filter=1
sudo sed -i '/^kernel.randomize_va_space/ c\kernel.randomize_va_space=2' /etc/sysctl.conf
sudo sed -i '/^net.ipv4.tcp_syncookies/ c\net.ipv4.tcp_syncookies=1' /etc/sysctl.conf
sysctl --system

#updates
sudo apt-get update -y
sudo apt-get dist-upgrade -y
sudo apt-get autoremove -y
sudo apt-get install apt-show versions -y

echo 'does this vm need ssh? [y/n]'
read sshYN
echo 'does this vm need vsftpd? [y/n]'
read vsftpdYN
echo 'does this vm need pureftpd? [y/n]'
read pureftpdYN
echo 'does this vm need mySQL? [y/n]'
read mySQLYN
echo 'does this vm need PHP? [y/n]'
read phpYN
echo 'does this vm need apache2? [y/n]'
read apacheYN
echo 'does this vm need samba? [y/n]'
read sambaYN

if	[ $sshYN == y ]
then
  #ssh configuration
  sudo sed -i '0,/^.*PermitRootLogin.*$/s//PermitRootLogin no/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*PermitEmptyPasswords.*$/s//PermitEmptyPasswords no/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*X11Forwarding.*$/s//X11Forwarding no/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*MaxAuthTries.*$/s//MaxAuthTries 3/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*LogLevel.*$/s//LogLevel VERBOSE/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*LoginGraceTime.*$/s//LoginGraceTime 20/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*AllowGroups.*$/s//AllowGroups $SSH_GRPS/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*Protocol.*$/s//Protocol 2/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*PassswordAuthentication.*$/s//PassswordAuthentication yes/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*PubkeyAuthentication.*$/s//PubkeyAuthentication yes/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*AllowTcpForwarding.*$/s//AllowTcpForwarding no/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*Port.*$/s//Port 2202/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*MaxAuthTries.*$/s//MaxAuthTries 2/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*UsePrivilegeSeparation.*$/s//UsePrivilegeSeparation SANDBOX/' /etc/ssh/sshd_config
  sudo sed -i '0,/^.*MaxStartups.*$/s//MaxStartups 10/' /etc/ssh/sshd_config
  sudo apt-get install openssh-client -y
  sudo apt-get install openssh-server -y
  sudo apt-get install ssh -y
  sudo systemctl start ssh
  sudo systemctl enable ssh

elif [ $sshYN == n ]
then
  sudo apt-get remove openssh-client -y
  sudo apt-get install openssh-server -y
  sudo apt-get remove ssh -y
  sudo systemctl disable ssh
else
	echo 'response not recognized'
fi

if	[ $vsftpdYN == y ]
then
  sudo sed -i '0,/^.*anonymous_enable.*$/s//anonymous_enable=NO/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*chroot_local_user.*$/s//chroot_local_user=YES/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*chroot_list_enable.*$/s//chroot_list_enable=YES/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*max_per_ip.*$/s//max_per_ip=2/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*local_enable.*$/s//local_enable=YES/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*write_enable.*$/s//write_enable=YES/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*anon_upload_enable.*$/s//anon_upload_enable=NO/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*hide_ids.*$/s//hide_ids=NO/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*anon_mkdir_write_enable.*$/s//anon_mkdir_write_enable=NO/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*anon_other_write_enable.*$/s//anon_other_write_enable=NO/' /etc/vsftpd.conf
  sudo sed -i '0,/^.*local_max_rate.*$/s//local_max_rate=1048576/' /etc/vsftpd.conf
  sudo apt-get install vsfptd -y
  sudo systemctl start vsftpd
  sudo systemctl enable vsftpd
elif [ $vsftpdYN == n ]
then
  sudo apt-get remove --purge vsftpd -y
  sudo systemctl disable vsftpd
  sudo apt-get remove --purge ftp -y
else
  echo 'response not recognized'
fi

if [ $pureftpdYN == y ]
then
  chmod 777 /etc/pure-ftpd/conf
  echo 'yes' > /etc/pure-ftpd/conf/NoAnonymous
  echo 2 > /etc/pure-ftpd/conf/TLS
  chmod 644 /etc/pure-ftpd/conf
elif [ $pureftpdYN == n ]
then
  sudo apt-get remove --purge pure-ftpd -y
  sudo apt-get remove --purge ftp -y
else
  echo 'response not recognized'
fi

if [ $mySQLYN == y ]
then
  sudo apt-get install mysql-server -y
  sudo sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf
  sudo apt-get install mysql-server -y
  #add local-infile=0
    sudo /usr/bin/mysql_secure_installation
	#press y for everything
  sudo systemctl enable mysql.service
elif [ $mySQLYN == n ]
then
  sudo apt-get remove --purge mysql-server -y
else
  echo 'response not recognized'
fi

if [ $phpYN == y ]
then

  sudo find /etc -file *php*.ini >> php_path.txt
	sudo sed -i '0,/^.*disable_functions.*$/s//disable_functions = pcntl_alarm,pcntl_fork,pcntl_waitpid,pcntl_wait,pcntl_wifexited,pcntl_wifstopped,pcntl_wifsignaled,pcntl_wexitstatus,pcntl_wtermsig,pcntl_wstopsig,pcntl_signal,pcntl_signal_dispatch,exec,system,shell_exec,passthru/' /etc/php5/apache2/php.ini
	sudo sed -i '0,/^.*expose_php.*$/s//expose_php = Off/' /etc/php5/apache2/php.ini
	sudo sed -i '0,/^.*display_errors.*$/s//display_errors = Off/' /etc/php5/apache2/php.ini
	sudo sed -i '0,/^.*track_errors.*$/s//track_errors = Off/' /etc/php5/apache2/php.ini
	sudo sed -i '0,/^.*html_errors.*$/s//html_errors = Off/' /etc/php5/apache2/php.ini
elif [ $phpYN == n ]
then
  'rip ok'
else
  echo 'response not recognized'
fi

if [ $apacheYN == y ]
then
  sudo apt-get install apache2 -y
  sudo systemctl start apache2.service
	sudo systemctl enable apache2.service
  sudo systemctl restart apache2.service
  sudo sed -i '/^ServerTokens/ c\ServerTokens Prod' /etc/apache2/conf-enabled/security.conf
	sudo sed -i '/^ServerSignature/ c\ServerSignature Off' /etc/apache2/conf-enabled/security.conf
	sudo sed -i '/^TraceEnable/ c\TraceEnable Off' /etc/apache2/conf-enabled/security.conf
elif [ $apacheYN == n ]
then
  sudo systemctl disable apache2.service apache2
  sudo apt-get remove apache2 -y
else
  echo 'response not recognized'
fi

if [ $sambaYN == y ]
then
  sudo apt-get install samba -y
  sudo systemctl smbd enable
elif [ $sambaYN == n ]
then
  sudo systemctl smbd disable
  sudo apt-get remove --purge samba -y
else
  echo 'response not recognized'
fi

#audit policy ???? ill ask the mentors next time i see them about lynis (edit: lynis is really good for doing a double check in stuff that needs to be secured)
sudo auditctl -e 1
sudo lynis -c
sudo lynis audit system

#remove autologin in /etc/lightdm/lightdm.conf
