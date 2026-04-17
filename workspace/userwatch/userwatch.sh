#!/usr/bin/env bash
set -uo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
RESET='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly ACTIVITY_DIR="${SCRIPT_DIR}/userActivity"
readonly USER_REPORT="${SCRIPT_DIR}/user_report.txt"
readonly SERVICES_FILE="${SCRIPT_DIR}/services.txt"
readonly SCORING_USERS_FILE="${SCRIPT_DIR}/SCORING-Users.txt"
readonly REDTEAM_USERS_FILE="${SCRIPT_DIR}/REDTEAM-Users.txt"
readonly LOG_FILE="${SCRIPT_DIR}/userwatch.log"
readonly PID_FILE="${SCRIPT_DIR}/userwatch.pid"
readonly POLL_INTERVAL=3
readonly BRUTE_FORCE_WINDOW=30   # seconds before the same rate-key can print again

SCRIPT_RUNNER="$(id -un)"
readonly SCRIPT_RUNNER

REDTEAM_PATTERNS=(
    # reverse / bind shells
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

    # download and execute
    '(curl|wget|aria2c|axel) .+\| *(ba)?sh'
    '(curl|wget|aria2c|axel) .+\| *(python[23]?|perl|ruby|php)'
    '(curl|wget|aria2c|axel) .*\.(sh|py|pl|rb|elf|bin)'
    '(curl|wget|aria2c|axel) .* -[Oo] /(tmp|dev/shm|var/tmp)/'
    'curl .*(--data|-d[^a-z]|--form|-F[^a-z])'   # -d[^a-z] matches -d and -d@ but not --digest
    'wget.*(--post-data|--post-file)'

    # exfiltration
    '(scp|rsync) .+ [a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+:'
    'tar .+\| *(nc|ncat|curl|wget|ssh)'

    # SSH tunneling
    'ssh .*-[a-zA-Z]*(R|L|D)'

    # credential file access
    '/etc/shadow|/etc/gshadow'
    '(cat|less|head|xxd|base64|strings|openssl) .+\.ssh/id_'
    'authorized_keys'

    # auth/user file modification
    '(>>|>) /etc/passwd|(>>|>) /etc/shadow'
    '\btee\b .*/etc/(passwd|shadow)'

    # hosts file modification
    '(>>|>) /etc/hosts|\btee\b .*/etc/hosts'

    # user and privilege manipulation
    '\buseradd\b|\badduser\b|\buserdel\b|\bdeluser\b'
    '\busermod\b|\bchpasswd\b'
    'passwd [^ ]'
    '\bvisudo\b|\bsudoedit\b'
    'echo .*(ALL|NOPASSWD).*(>>|>) .*/sudoers'
    '\bsudo\b -[a-zA-Z]*[si]\b'
    '/etc/sudoers\.d/'

    # SUID bit setting
    'chmod .*(u\+s|\+s|4[0-7][0-7][0-7])'

    # disabling security controls
    'setenforce 0|setenforce Permissive'
    'iptables -F|iptables --flush|ufw disable|firewall-cmd.*--panic'
    'nft flush|\baa-disable\b|apparmor_parser -R'

    # shared library / environment injection
    'LD_PRELOAD='
    '/etc/ld\.so\.preload'
    'BASH_ENV='

    # PAM modification
    '/etc/pam\.d/'

    # systemd service persistence
    '/etc/systemd/system/.*\.service'

    # log and history tampering
    '> /var/log/|shred .*/var/log/'
    'history -c|unset HISTFILE|HISTSIZE=0'

    # persistence paths
    '\bcrontab\b -e'
    '\btee\b -a.*(\.bashrc|\.profile|\.zshrc|\.bash_profile|authorized_keys)'
    'echo .+(>>|>) .*(\.bashrc|\.bash_profile|\.profile|\.zshrc|\.bash_logout)'
    '/etc/cron\.(d|daily|hourly|weekly|monthly)|/etc/rc\.local|/etc/profile\.d'
    'echo .+\| *\bat\b'

    # web shell creation
    '\btee\b .*/var/www/.*\.(php|sh|py|pl|jsp|aspx)'
    '(>>|>) .*/var/www/.*\.(php|sh|py|pl|jsp|aspx)'

    # interpreter-based network shells
    'python[23]? -c .*(socket|pty|subprocess|os\.system)'
    'perl -e .*(socket|fork|exec)'
    'ruby -e .*TCPSocket'
    'php -r .*(fsockopen|shell_exec|system|exec|passthru|popen)'

    # SUID binary enumeration
    'find .* -perm.*(4000|u\+s)'

    # process tracing
    '\bstrace\b|\bltrace\b|\bgdb\b'

    # file attribute manipulation
    '\bchattr\b'

    # container / namespace escape
    'docker run.*--privileged|\bnsenter\b|\blxc\b|\blxd\b'

    # SSH daemon config modification
    '(>>|>) /etc/ssh/|\btee\b .*/etc/ssh/'
    '\bsed\b.*-i.*/etc/ssh/'

    # DNS zone file modification
    '(>>|>) /etc/bind/|\btee\b .*/etc/bind/'
    '(>>|>) /var/lib/bind/|\btee\b .*/var/lib/bind/'
    '(>>|>) /etc/named/|\btee\b .*/etc/named/'
    '(>>|>) /var/named/|\btee\b .*/var/named/'
    '\bnsupdate\b'

    # IPv6 firewall flush
    '\bip6tables\b.*(-F\b|--flush)'

    # database user / credential manipulation
    'mysql.*(--execute|-e).*(DROP USER|ALTER USER|SET PASSWORD|RENAME USER)'
    'mysql.*(--execute|-e).*(GRANT|REVOKE).*(ALL|SUPER|PROXY)'
    '\bmysqladmin\b.*(password|set-password|flush-privileges)'
    'mariadb.*(--execute|-e).*(DROP USER|ALTER USER|SET PASSWORD|RENAME USER)'
    'mariadb.*(--execute|-e).*(GRANT|REVOKE).*(ALL|SUPER|PROXY)'
    '\bmariadb-admin\b.*(password|set-password|flush-privileges)'
    'psql.*(--command|-c).*(DROP USER|ALTER USER|SET PASSWORD|CREATE USER|REVOKE)'

    # Saprus C2
    '/etc/\.redteam'
    '\bbidir-comms\b|\bpass-watch\b'

    # ansible attack modules
    '\bansible\b .* -m *(shell|command|raw|script)\b'

    # shell upgrade / TTY stabilization
    '\bscript\b -q /dev/null|\bscript\b.*/dev/null'
    '\bstty\b raw'

    # additional interpreter shells
    'ruby -rsocket'
    'node -e.*(require.*net|net\.connect|net\.Socket)'
    '\btclsh\b|\bwish\b'

    # systemd transient execution
    '\bsystemd-run\b'

    # capability escalation
    '\bsetcap\b'

    # profile / RC file persistence
    '(>>|>) /etc/profile\b|\btee\b .*/etc/profile\b'
    '(>>|>) /root/\.bashrc|\btee\b .*/root/\.bashrc'

    # at job from file
    '\bat\b -f'

    # base64 single-line encoding
    'base64 -w 0|base64 --wrap=0'

    # symlink attacks on auth files
    'ln -s.*(shadow|sudoers)'
)

SCORING_PATTERNS=(
    # service disruption
    '\bsystemctl\b.*(stop|disable|mask)'
    '\bservice\b .+ (stop|disable)'

    # process termination
    '\bpkill\b|\bkillall\b'
    '\bkill\b -[1-9]'

    # system availability
    '\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b'

    # data destruction
    'rm -(rf|fr|Rf|fR|rF|Fr)'
    'dd if='
    'mkfs\.'
    '\bfdisk\b|\bparted\b|\bgdisk\b'

    # web content destruction
    '(>>|>) .*/var/www/html/index\.'
    'rm .*/var/www'
    '\b(curl|wget|aria2c|axel)\b.*-[Oo] .*/var/www/'

    # scheduled task destruction
    '\bcrontab\b -r'
)

OTHER_PATTERNS=(
    # identity recon
    '\bid\b|\bwhoami\b|\bgroups\b'
    '\buname\b|\bhostname\b'

    # process enumeration
    '\bps\b|\btop\b|\bhtop\b|\bpgrep\b'

    # network state
    '\bnetstat\b|\bss\b -'
    'ifconfig|\bip\b (addr|route|link|neigh)'
    '\barp\b -[an]'

    # network sniffing
    '\btcpdump\b|\btshark\b'

    # file and user enumeration
    '(cat|less|more|head|tail) /etc/passwd'
    '(cat|less|more|head|tail) /etc/(hosts|resolv\.conf|group|crontab)'
    'ls .*/root'
    '(cat|less|head) /etc/sudoers'
    'ls /etc/cron'
    'find / -name '
    '\blocate\b '

    # package enumeration
    'dpkg -l|rpm -qa'

    # login / session history
    '\blast\b|\blastlog\b|\bwho\b'

    # disk / filesystem enumeration
    '\bdf\b|\blsblk\b|\bblkid\b'

    # open files / capabilities
    '\blsof\b'
    '\bgetcap\b'

    # key management
    '\bssh-keygen\b'

    # base64 decode
    'base64 -d|base64 --decode'

    # SMB client
    '\bsmbclient\b'

    # writable file enumeration
    'find .* -writable'

    # service management (non-destructive)
    'systemctl (start|restart|reload|enable|status)'
    'service .+ (start|restart|status)'

    # sudo privilege listing
    'sudo -[lL]'

    # mount operations
    '\bmount\b|\bumount\b'

    # ansible
    '\bansible-playbook\b|\bansible\b'
)

printf -v REDTEAM_RE '%s|' "${REDTEAM_PATTERNS[@]}"; REDTEAM_RE="${REDTEAM_RE%|}"
printf -v SCORING_RE '%s|' "${SCORING_PATTERNS[@]}"; SCORING_RE="${SCORING_RE%|}"
printf -v OTHER_RE   '%s|' "${OTHER_PATTERNS[@]}";   OTHER_RE="${OTHER_RE%|}"

SERVICES_RE=""
if [[ -f "${SERVICES_FILE}" ]]; then
    _svc_pat=""
    while IFS= read -r _svc; do
        [[ -z "${_svc}" || "${_svc}" =~ ^# ]] && continue
        _svc_pat="${_svc_pat}${_svc_pat:+|}${_svc}"
    done < "${SERVICES_FILE}"
    [[ -n "${_svc_pat}" ]] && SERVICES_RE="(${_svc_pat})"
    unset _svc_pat _svc
fi
readonly SERVICES_RE

AUTH_LOG=""
AUTH_MONITOR_PID=""
declare -A KNOWN_SESSIONS=()
declare -A SEEN_PIDS=()
declare -A KNOWN_UIDS=()
declare -A SEEN_ARTIFACTS=()
declare -A LAST_ALERT_TS=()

log() {
    local ts; printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
    echo "${ts} $*" >> "${LOG_FILE}"
}

log_to_user_file() {
    local user="$1" message="$2"
    local user_file="${ACTIVITY_DIR}/${user}.txt"
    local ts; printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
    if [[ ! -f "${user_file}" ]]; then
        mkdir -p "${ACTIVITY_DIR}"
        echo "activity log: ${user} -- opened ${ts}" > "${user_file}"
    fi
    echo "${ts} ${message}" >> "${user_file}"
}

add_to_team() {
    local file="$1" user="$2"
    [[ -z "${user}" ]] && return 0
    grep -qxF "${user}" "${file}" 2>/dev/null && return 0
    echo "${user}" >> "${file}"
    log "added ${user} to $(basename "${file}")"
}

alert() {
    local severity="$1" user="$2" cmd="$3" rate_key="${4:-}"

    [[ "${user}" == "${SCRIPT_RUNNER}" ]] && return 0

    local ts; printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1

    log "ALERT [${severity^^}] user=${user} cmd=${cmd}"
    log_to_user_file "${user}" "ALERT [${severity^^}] ${cmd}"
    [[ "${severity}" == "redteam" ]] && add_to_team "${REDTEAM_USERS_FILE}" "${user}"

    if [[ -n "${rate_key}" ]]; then
        local now; printf -v now '%(%s)T' -1
        local last="${LAST_ALERT_TS["${rate_key}"]:-0}"
        if (( now - last < BRUTE_FORCE_WINDOW )); then
            return 0
        fi
        LAST_ALERT_TS["${rate_key}"]="${now}"
    fi

    local color
    case "${severity}" in
        redteam) color="${RED}"    ;;
        scoring) color="${YELLOW}" ;;
        *)       color="${CYAN}"   ;;
    esac
    echo -e "${color}${BOLD}${ts} <ALERT> [${severity^^}] user=\"${user}\" cmd: ${cmd}${RESET}"
}

notice() {
    local message="$1"
    local ts; printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
    echo -e "${GREEN}${BOLD}${ts} <LOGIN> ${message}${RESET}"
    log "NOTICE ${message}"
}

enumerate_users() {
    log "enumerating users..."
    local ts; printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
    {
        echo "user report -- ${ts}"
        echo ""
        printf "%-20s %-6s %-6s %-25s %s\n" USERNAME UID GID HOME SHELL
        printf "%-20s %-6s %-6s %-25s %s\n" -------- --- --- ---- -----
        while IFS=: read -r uname _pass uid gid _gecos home shell; do
            printf "%-20s %-6s %-6s %-25s %s\n" \
                "${uname}" "${uid}" "${gid}" "${home}" "${shell}"
        done < /etc/passwd

        echo ""
        echo "root accounts (UID 0):"
        awk -F: '($3==0){print "  "$1}' /etc/passwd

        echo ""
        echo "privileged group members:"
        local grp members
        for grp in sudo wheel admin; do
            if getent group "${grp}" &>/dev/null; then
                members="$(getent group "${grp}" | cut -d: -f4)"
                [[ -n "${members}" ]] && echo "  ${grp}: ${members}"
            fi
        done

        echo ""
        echo "sudoers entries (/etc/sudoers):"
        if [[ -r /etc/sudoers ]]; then
            grep -vE \
                '^[[:space:]]*(#|$|Defaults|Cmnd_Alias|Host_Alias|User_Alias|Runas_Alias)' \
                /etc/sudoers 2>/dev/null || true
        else
            echo "  (no read access)"
        fi

        echo ""
        echo "sudoers.d entries (/etc/sudoers.d/):"
        if [[ -d /etc/sudoers.d ]]; then
            local found_any=0
            for _f in /etc/sudoers.d/*; do
                [[ -f "${_f}" ]] || continue
                found_any=1
                echo "  -- ${_f} --"
                grep -vE '^[[:space:]]*(#|$)' "${_f}" 2>/dev/null || true
            done
            [[ "${found_any}" -eq 0 ]] && echo "  (empty)"
        else
            echo "  (no sudoers.d directory)"
        fi

        echo ""
        echo "active sessions:"
        who 2>/dev/null || echo "  (unavailable)"

        echo ""
        echo "recent logins:"
        last -n 20 2>/dev/null || echo "  (unavailable)"

    } > "${USER_REPORT}"

    echo "  user report -> ${USER_REPORT}"
    log "user report generated"
}

setup_activity_dir() {
    mkdir -p "${ACTIVITY_DIR}"
    local ts user_file; printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
    while IFS=: read -r uname _pass uid _rest; do
        user_file="${ACTIVITY_DIR}/${uname}.txt"
        if [[ ! -f "${user_file}" ]]; then
            echo "activity log: ${uname} (uid ${uid}) -- opened ${ts}" > "${user_file}"
        fi
    done < /etc/passwd
    log "activity directory ready: ${ACTIVITY_DIR}"
}

find_auth_log() {
    local candidate
    for candidate in /var/log/auth.log /var/log/secure; do
        if [[ -f "${candidate}" && -r "${candidate}" ]]; then
            AUTH_LOG="${candidate}"
            log "using auth log: ${AUTH_LOG}"
            return 0
        fi
    done
    if command -v journalctl &>/dev/null && journalctl -n 1 &>/dev/null; then
        AUTH_LOG="journalctl"
        log "using journalctl for auth monitoring"
        return 0
    fi
    log "WARNING: no readable auth log found -- auth event monitoring disabled"
    return 1
}

classify_command() {
    local cmd="$1"
    local severity="none"

    if   grep -qE "${REDTEAM_RE}" <<< "${cmd}"; then severity="redteam"
    elif grep -qE "${SCORING_RE}" <<< "${cmd}"; then severity="scoring"
    elif grep -qE "${OTHER_RE}"   <<< "${cmd}"; then severity="other"
    fi

    # escalate to SCORING if a named scored service is being killed or stopped
    if [[ "${severity}" != "redteam" && "${severity}" != "scoring" \
       && -n "${SERVICES_RE}" ]]; then
        if grep -qE "${SERVICES_RE}" <<< "${cmd}" \
        && grep -qE '(stop|disable|mask|kill)' <<< "${cmd}"; then
            severity="scoring"
        fi
    fi

    echo "${severity}"
}

monitor_logins() {
    local current_sessions
    current_sessions="$(who 2>/dev/null | awk '{print $1"@"$2}')" || return 0

    declare -A current_map=()
    local session user tty ts
    while IFS= read -r session; do
        [[ -n "${session}" ]] && current_map["${session}"]=1
    done <<< "${current_sessions}"

    for session in "${!current_map[@]}"; do
        if [[ -z "${KNOWN_SESSIONS["${session}"]+_}" ]]; then
            KNOWN_SESSIONS["${session}"]=1
            user="${session%%@*}"; tty="${session##*@}"
            log_to_user_file "${user}" "LOGIN on ${tty}"
            notice "login: ${user} on ${tty}"
        fi
    done

    for session in "${!KNOWN_SESSIONS[@]}"; do
        if [[ -z "${current_map["${session}"]+_}" ]]; then
            unset "KNOWN_SESSIONS[${session}]"
            user="${session%%@*}"; tty="${session##*@}"
            printf -v ts '%(%Y-%m-%d %H:%M:%S)T' -1
            log_to_user_file "${user}" "LOGOUT from ${tty}"
            log "LOGOUT: ${user} from ${tty}"
            echo -e "${CYAN}${BOLD}${ts} <LOGOUT> logout: ${user} from ${tty}${RESET}"
        fi
    done
}

monitor_auth_log() {
    [[ -z "${AUTH_LOG}" ]] && return 0

    local re_sudo_user='sudo:[[:space:]]+([^[:space:]:]+)'
    local re_sudo_cmd='COMMAND=(.+)$'
    local re_lognameuser='(logname|user)=([^[:space:];]+)'
    local re_su_target='for user ([^[:space:]]+)'
    local re_su_by=' by ([^ (]+)'
    local re_user_eq='user=([^[:space:];]+)'
    local re_ssh_from=' from ([0-9a-fA-F.:]+)'
    local re_ssh_method='Accepted (password|publickey)'
    local re_ssh_invalid='for invalid user ([^[:space:]]+)'
    local re_ssh_valid_user='for ([^[:space:]]+) from'

    if [[ "${AUTH_LOG}" == "journalctl" ]]; then
        journalctl -f -n 0 --output=short 2>/dev/null
    else
        tail -F "${AUTH_LOG}" 2>/dev/null
    fi | while IFS= read -r line; do

        # sudo command executed
        if [[ "${line}" == *"sudo:"*"COMMAND="* ]]; then
            [[ "${line}" =~ ${re_sudo_user} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ "${line}" =~ ${re_sudo_cmd}  ]] && cmd="${BASH_REMATCH[1]}"  || cmd=""
            [[ -z "${user}" || -z "${cmd}" ]] && continue

            severity="$(classify_command "${cmd}")"
            if [[ "${severity}" != "none" ]]; then
                alert "${severity}" "${user}" "${cmd}"
            else
                log_to_user_file "${user}" "sudo ${cmd}"
                log "INFO: ${user} sudo: ${cmd}"
            fi

        # sudo failure
        elif [[ "${line}" == *"sudo:"*"incorrect password"* ]] \
          || [[ "${line}" == *"pam_unix(sudo"*"): authentication failure"* ]]; then
            [[ "${line}" =~ ${re_lognameuser} ]] && user="${BASH_REMATCH[2]}" || user=""
            [[ -z "${user}" ]] && continue
            log "FAILED SUDO: ${user}"
            log_to_user_file "${user}" "FAILED sudo attempt"
            alert "redteam" "${user}" "failed sudo authentication" "sudo_fail:${user}"

        # su session opened
        elif [[ "${line}" == *"pam_unix(su"*"): session opened"* ]]; then
            [[ "${line}" =~ ${re_su_target} ]] && target="${BASH_REMATCH[1]}" || target=""
            [[ "${line}" =~ ${re_su_by}     ]] && by="${BASH_REMATCH[1]}"     || by=""
            [[ -z "${by}" ]] && continue
            log "SU: ${by} -> ${target:-root}"
            log_to_user_file "${by}" "SU to ${target:-root}"
            if [[ "${target:-root}" == "root" ]]; then
                alert "redteam" "${by}" "su to root"
            else
                alert "other" "${by}" "su to ${target}"
            fi

        # su failure
        elif [[ "${line}" == *"pam_unix(su"*"): authentication failure"* ]]; then
            [[ "${line}" =~ ${re_user_eq} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ -z "${user}" ]] && continue
            log "FAILED SU: ${user}"
            log_to_user_file "${user}" "FAILED su attempt"
            alert "redteam" "${user}" "failed su authentication" "su_fail:${user}"

        # SSH login success
        elif [[ "${line}" == *"sshd["*"]: Accepted password"* ]] \
          || [[ "${line}" == *"sshd["*"]: Accepted publickey"* ]]; then
            [[ "${line}" =~ ${re_ssh_valid_user} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ "${line}" =~ ${re_ssh_from}        ]] && src="${BASH_REMATCH[1]}"  || src=""
            [[ "${line}" =~ ${re_ssh_method}      ]] && method="${BASH_REMATCH[1]}" || method=""
            [[ -z "${user}" ]] && continue
            log_to_user_file "${user}" "SSH login from ${src:-unknown} [${method:-?}]"
            notice "SSH  accepted: user=\"${user}\" from=${src:-unknown} [${method:-?}]"

        # SSH failure
        elif [[ "${line}" == *"sshd["*"]: Failed password"* ]] \
          || [[ "${line}" == *"sshd["*"]: Failed publickey"* ]]; then
            if [[ "${line}" =~ ${re_ssh_invalid} ]]; then
                user="${BASH_REMATCH[1]}"
            elif [[ "${line}" =~ ${re_ssh_valid_user} ]]; then
                user="${BASH_REMATCH[1]}"
            else
                user=""
            fi
            [[ "${line}" =~ ${re_ssh_from} ]] && src="${BASH_REMATCH[1]}" || src=""
            [[ -z "${user}" ]] && continue
            log "FAILED SSH: ${user} from ${src:-unknown}"
            log_to_user_file "${user}" "FAILED SSH login from ${src:-unknown}"
            alert "redteam" "${user}" "failed SSH login from ${src:-unknown}" "ssh_fail:${user}"

        # FTP login success
        elif [[ "${line}" == *"pam_unix(vsftpd:session): session opened"* ]]; then
            [[ "${line}" =~ ${re_su_target} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ -z "${user}" ]] && continue
            log_to_user_file "${user}" "FTP login"
            notice "FTP  accepted: user=\"${user}\""

        # SMB login success
        elif [[ "${line}" == *"pam_unix(smbd:session): session opened"* ]]; then
            [[ "${line}" =~ ${re_su_target} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ -z "${user}" ]] && continue
            log_to_user_file "${user}" "SMB login"
            notice "SMB  accepted: user=\"${user}\""

        # FTP failure
        elif [[ "${line}" == *"pam_unix(vsftpd:auth): authentication failure"* ]]; then
            [[ "${line}" =~ ${re_user_eq} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ -z "${user}" ]] && continue
            log "FAILED FTP: ${user}"
            log_to_user_file "${user}" "FAILED FTP login"
            alert "redteam" "${user}" "failed FTP authentication" "ftp_fail:${user}"

        # SMB failure
        elif [[ "${line}" == *"pam_unix(smbd:auth): authentication failure"* ]]; then
            [[ "${line}" =~ ${re_user_eq} ]] && user="${BASH_REMATCH[1]}" || user=""
            [[ -z "${user}" ]] && continue
            log "FAILED SMB: ${user}"
            log_to_user_file "${user}" "FAILED SMB login"
            alert "redteam" "${user}" "failed SMB authentication" "smb_fail:${user}"
        fi

    done &

    AUTH_MONITOR_PID="$!"
    log "auth log monitor started (pid ${AUTH_MONITOR_PID})"
}

monitor_processes() {
    local snapshot
    snapshot="$(ps -eo pid,user,ruser,comm,args --no-headers 2>/dev/null)" || return 0

    local _skip=":ps:grep:awk:sed:tail:sshd:cron:at:dbus-daemon:polkit:systemd:su:sudo:passwd:newgrp:chsh:chfn:ping:ping6:ssh-agent:"
    local _bad_procs=":bidir-comms:pass-watch:simple-message:msfconsole:sliver:havoc:empire:covenant:"
    local pid user ruser comm args severity

    while IFS= read -r proc_line; do
        [[ -z "${proc_line}" ]] && continue
        read -r pid user ruser comm args <<< "${proc_line}"
        [[ -z "${pid}" || -z "${user}" || -z "${ruser}" ]] && continue

        [[ -n "${SEEN_PIDS["${pid}"]+_}" ]] && continue
        SEEN_PIDS["${pid}"]=1

        if [[ "${_bad_procs}" == *":${comm}:"* ]]; then
            log_to_user_file "${ruser}" "BAD_PROC [REDTEAM] ${args}"
            alert "redteam" "${ruser}" "${args} (known C2 process: ${comm})"
            continue
        fi

        [[ "${user}" == "${ruser}" ]] && continue
        [[ "${_skip}" == *":${comm}:"* ]] && continue

        severity="$(classify_command "${args}")"

        if [[ "${user}" == "root" ]]; then
            [[ "${severity}" == "none" ]] && severity="redteam"
            log_to_user_file "${ruser}" "PROC_AS_ROOT [${severity^^}] ${args}"
            alert "${severity}" "${ruser}" "${args} (running as root)"
        else
            [[ "${severity}" == "none" ]] && severity="other"
            alert "${severity}" "${ruser}" "${args} (running as ${user})"
        fi

    done <<< "${snapshot}"
}

setup_team_lists() {
    local uname uid shell

    : > "${SCORING_USERS_FILE}"
    while IFS=: read -r uname _pass uid _gid _gecos _home shell; do
        [[ "${uid}" =~ ^[0-9]+$ ]] || continue
        [[ "${uid}" -lt 1000 ]]    && continue
        case "${shell}" in
            */nologin|*/false|*/sync|*/halt|*/shutdown) continue ;;
        esac
        echo "${uname}" >> "${SCORING_USERS_FILE}"
    done < /etc/passwd

    : > "${REDTEAM_USERS_FILE}"

    local user_list
    user_list="$(paste -sd ',' "${SCORING_USERS_FILE}" | sed 's/,/, /g')"
    echo "  SCORING-Users: ${user_list:-none}"
    echo "  REDTEAM-Users: (none yet)"
    log "team lists initialized -- $(wc -l < "${SCORING_USERS_FILE}" | tr -d ' ') scoring user(s)"
}

seed_known_uids() {
    local uid
    while IFS=: read -r _uname _pass uid _rest; do
        KNOWN_UIDS["${uid}"]=1
    done < /etc/passwd
}

monitor_new_users() {
    local uname uid
    while IFS=: read -r uname _pass uid _rest; do
        [[ "${uid}" =~ ^[0-9]+$ ]]          || continue
        [[ -n "${KNOWN_UIDS["${uid}"]+_}" ]] && continue
        KNOWN_UIDS["${uid}"]=1
        log "NEW ACCOUNT: ${uname} (uid ${uid})"
        add_to_team "${REDTEAM_USERS_FILE}" "${uname}"
        alert "redteam" "${uname}" "account created mid-run (uid ${uid})"
    done < /etc/passwd
}

cleanup_pids() {
    local pid
    for pid in "${!SEEN_PIDS[@]}"; do
        [[ -d "/proc/${pid}" ]] || unset "SEEN_PIDS[${pid}]"
    done
}

check_redteam_artifacts() {
    if [[ -d /etc/.redteam && -z "${SEEN_ARTIFACTS["/etc/.redteam"]+_}" ]]; then
        SEEN_ARTIFACTS["/etc/.redteam"]=1
        alert "redteam" "root" "Saprus C2 artifact: /etc/.redteam/ directory exists"
        log "ARTIFACT: /etc/.redteam/ found"
    fi

    if [[ -f /etc/.redteam/passwd.log && -z "${SEEN_ARTIFACTS["/etc/.redteam/passwd.log"]+_}" ]]; then
        SEEN_ARTIFACTS["/etc/.redteam/passwd.log"]=1
        alert "redteam" "root" "Saprus credential harvest file: /etc/.redteam/passwd.log"
        log "ARTIFACT: /etc/.redteam/passwd.log found"
    fi

    local f
    for f in /dev/shm/*; do
        [[ -f "${f}" && -x "${f}" ]] || continue
        [[ -n "${SEEN_ARTIFACTS["${f}"]+_}" ]] && continue
        SEEN_ARTIFACTS["${f}"]=1
        alert "redteam" "root" "executable staged in /dev/shm: ${f}"
        log "ARTIFACT: executable in /dev/shm: ${f}"
    done

    # alert once per new file created after monitoring started
    for f in /etc/cron.d/*; do
        [[ -f "${f}" ]] || continue
        [[ -n "${SEEN_ARTIFACTS["cron:${f}"]+_}" ]] && continue
        if [[ "$(find "${f}" -newer "${LOG_FILE}" 2>/dev/null)" == "${f}" ]]; then
            SEEN_ARTIFACTS["cron:${f}"]=1
            alert "redteam" "root" "new cron.d file detected: ${f}"
            log "ARTIFACT: new /etc/cron.d file: ${f}"
        fi
    done
}

cleanup() {
    echo ""
    log "userwatch shutting down"
    if [[ -n "${AUTH_MONITOR_PID}" ]]; then
        kill "${AUTH_MONITOR_PID}" 2>/dev/null || true
    fi
    rm -f "${PID_FILE}"
    echo "stopped."
}

trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

main() {
    [[ "${EUID}" -ne 0 ]] && echo "WARNING: not root -- some monitoring features will be limited"

    if [[ -f "${PID_FILE}" ]]; then
        local existing_pid
        existing_pid="$(cat "${PID_FILE}" 2>/dev/null)"
        if [[ -n "${existing_pid}" ]] && [[ "${existing_pid}" =~ ^[0-9]+$ ]] \
           && kill -0 "${existing_pid}" 2>/dev/null; then
            echo "ERROR: userwatch is already running (pid ${existing_pid})."
            echo "       Stop it first:  kill ${existing_pid}"
            exit 1
        fi
    fi

    echo $$ > "${PID_FILE}"

    echo -e "${BOLD}============================================================${RESET}"
    echo -e "${BOLD}  USERWATCH -- UA -- YOU KNOW ${RESET}"
    local _start; printf -v _start '%(%Y-%m-%d %H:%M:%S)T' -1
    echo -e "${BOLD}  Started : ${_start}${RESET}"
    echo -e "${BOLD}  Runner  : ${SCRIPT_RUNNER} (never alerted)${RESET}"
    echo -e "${BOLD}  Poll    : ${POLL_INTERVAL}s${RESET}"
    echo -e "${BOLD}  Patterns: ${#REDTEAM_PATTERNS[@]} REDTEAM | ${#SCORING_PATTERNS[@]} SCORING | ${#OTHER_PATTERNS[@]} OTHER${RESET}"
    echo -e "${BOLD}  Alert tiers:${RESET}"
    echo -e "    ${RED}${BOLD}REDTEAM${RESET} -- active attack (shells, scans, credential access, persistence)"
    echo -e "    ${YELLOW}${BOLD}SCORING${RESET} -- breaks competition score (service stops, data destruction)"
    echo -e "    ${CYAN}${BOLD}OTHER  ${RESET} -- passive recon / enumeration (logged for visibility)"
    echo -e "    ${GREEN}${BOLD}LOGIN  ${RESET} -- SSH/FTP/SMB login accepted (always visible)"
    echo -e "${BOLD}============================================================${RESET}"
    echo ""

    enumerate_users
    setup_activity_dir
    setup_team_lists
    seed_known_uids
    find_auth_log || true

    echo ""
    echo -e "  Auth source : ${AUTH_LOG:-DISABLED}"
    echo ""

    local session
    while IFS= read -r session; do
        [[ -n "${session}" ]] && KNOWN_SESSIONS["${session}"]=1
    done < <(who 2>/dev/null | awk '{print $1"@"$2}')

    monitor_auth_log

    log "monitoring started (poll ${POLL_INTERVAL}s)"
    echo -e "${BOLD}Monitoring -- Ctrl+C to stop${RESET}"
    echo ""

    local iteration=0
    while true; do
        monitor_logins
        monitor_new_users
        monitor_processes
        check_redteam_artifacts
        (( ++iteration )) || true
        (( iteration % 20 == 0 )) && cleanup_pids
        sleep "${POLL_INTERVAL}"
    done
}

main "$@"
