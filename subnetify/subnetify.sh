#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────
#  subnetify — subnet inspector
#  Usage:
#    subnetify              → your own IPs + subnets
#    subnetify <target>     → subnet info for a domain or IP
# ─────────────────────────────────────────────────────────────

R=$'\033[0m'; B=$'\033[1m'; CY=$'\033[96m'; GN=$'\033[92m'
YL=$'\033[93m'; RD=$'\033[91m'; GY=$'\033[90m'; MG=$'\033[95m'

div() { echo -e "${GY}$(printf '─%.0s' {1..52})${R}"; }

# ── math helpers ──────────────────────────────────────────────

cidr_to_mask() {
    local bits=$1 mask=0
    (( bits > 0 )) && mask=$(( ( (1 << bits) - 1 ) << (32 - bits) ))
    printf "%d.%d.%d.%d" \
        "$(( (mask >> 24) & 255 ))" "$(( (mask >> 16) & 255 ))" \
        "$(( (mask >>  8) & 255 ))" "$(( mask & 255 ))"
}

ip_to_int() {
    local IFS='.' a b c d
    read -r a b c d <<< "$1"
    echo $(( (a<<24)|(b<<16)|(c<<8)|d ))
}

int_to_ip() {
    local n=$1
    printf "%d.%d.%d.%d" \
        "$(( (n>>24)&255 ))" "$(( (n>>16)&255 ))" \
        "$(( (n>>8)&255 ))"  "$(( n&255 ))"
}

# detect likely CIDR from a bare IP (no /prefix given)
guess_cidr() {
    local ip=$1
    local a; a=$(echo "$ip" | cut -d. -f1)
    # RFC1918 / common ranges → guess the typical mask used
    if   [[ "$ip" == 10.* ]];       then echo 8
    elif [[ "$ip" == 172.1[6-9].* || "$ip" == 172.2[0-9].* || "$ip" == 172.3[01].* ]]; then echo 16
    elif [[ "$ip" == 192.168.* ]];  then echo 24
    elif [[ "$ip" == 100.6[4-9].* || "$ip" == 100.[7-9][0-9].* || "$ip" == 100.1[01][0-9].* || "$ip" == 100.12[0-7].* ]]; then echo 10   # CGNAT/Tailscale
    else echo 24   # public IP — /24 is the common BGP prefix size
    fi
}

private_label() {
    local ip=$1
    local b2; b2=$(echo "$ip" | cut -d. -f2)
    if   [[ "$ip" == 10.* ]];      then echo "${GY}RFC1918 Class A${R}"
    elif [[ "$ip" == 172.* ]] && (( b2 >= 16 && b2 <= 31 )); then echo "${GY}RFC1918 Class B${R}"
    elif [[ "$ip" == 192.168.* ]]; then echo "${GY}RFC1918 Class C${R}"
    elif [[ "$ip" == 100.6[4-9].* || "$ip" == 100.[7-9]*.* || "$ip" == 100.1[01]*.* || "$ip" == 100.12[0-7].* ]]; then echo "${MG}CGNAT/Tailscale${R}"
    elif [[ "$ip" == 127.* ]];     then echo "${GY}Loopback${R}"
    elif [[ "$ip" == 169.254.* ]]; then echo "${YL}Link-local (no DHCP)${R}"
    else echo "${CY}Public${R}"
    fi
}

cidr_hint() {
    case $1 in
        8)  echo "entire Class A block (~16M hosts)" ;;
        16) echo "Class B block (~65k hosts)" ;;
        24) echo "standard LAN — 254 usable" ;;
        25) echo "half /24 — 126 usable" ;;
        26) echo "quarter /24 — 62 usable" ;;
        27) echo "30 usable hosts" ;;
        28) echo "14 usable hosts" ;;
        29) echo "6 usable hosts" ;;
        30) echo "point-to-point — 2 hosts" ;;
        31) echo "RFC 3021 P2P — no broadcast" ;;
        32) echo "host route — single IP" ;;
        *)  local u=$(( (1 << (32-$1)) - 2 )); echo "$u usable hosts" ;;
    esac
}

# ── the main block ────────────────────────────────────────────
show_subnet() {
    local ip=$1 cidr=$2 iface=$3

    local mask;      mask=$(cidr_to_mask "$cidr")
    local ip_int;    ip_int=$(ip_to_int "$ip")
    local mask_int;  mask_int=$(ip_to_int "$mask")
    local wc_int=$(( ~mask_int & 0xFFFFFFFF ))

    local net_int=$(( ip_int & mask_int ))
    local bc_int=$(( net_int | wc_int ))
    local network;   network=$(int_to_ip $net_int)
    local broadcast; broadcast=$(int_to_ip $bc_int)
    local first;     first=$(int_to_ip $(( net_int + 1 )) )
    local last;      last=$(int_to_ip $(( bc_int  - 1 )) )
    local total=$(( bc_int - net_int + 1 ))
    local usable=$(( total - 2 )); (( usable < 0 )) && usable=0

    local label; label=$(private_label "$ip")
    local hint;  hint=$(cidr_hint "$cidr")

    # header
    [[ -n "$iface" ]] && echo -e "\n  ${B}${iface}${R}"
    echo -e "  ${B}${CY}${ip}/${cidr}${R}  ${label}"
    div

    printf "  ${GY}%-17s${R}  %s\n"   "Subnet mask"  "${YL}${mask}${R}"
    printf "  ${GY}%-17s${R}  %s\n"   "Network"      "${GN}${network}/${cidr}${R}"
    printf "  ${GY}%-17s${R}  %s\n"   "Broadcast"    "${RD}${broadcast}${R}"
    printf "  ${GY}%-17s${R}  %s\n"   "First host"   "${GN}${first}${R}"
    printf "  ${GY}%-17s${R}  %s\n"   "Last host"    "${GN}${last}${R}"
    printf "  ${GY}%-17s${R}  ${B}%s${R}  ${GY}%s${R}\n" \
           "Usable hosts"  "$usable"  "($hint)"

    # CIDR range bar
    local bw=38 filled=0
    (( total > 0 )) && filled=$(( usable * bw / total ))
    local bar="${GN}"
    for (( i=0; i<filled;  i++ )); do bar+="█"; done
    bar+="${GY}"
    for (( i=filled; i<bw; i++ )); do bar+="░"; done
    bar+="${R}"
    printf "  ${GY}%-17s${R}  [%s]\n" "Range" "$bar"

    # nmap scan suggestion
    echo -e "\n  ${GY}nmap scan hint:${R}"
    echo -e "  ${GY}  nmap -sn ${network}/${cidr}${R}   ${GY}# ping sweep${R}"
    echo -e "  ${GY}  nmap -sV ${network}/${cidr}${R}   ${GY}# service scan${R}"
    echo
}

# ── resolve a target (domain or IP) to IP+cidr ───────────────
resolve_target() {
    local target=$1
    # strip protocol if pasted as URL
    target="${target#http://}"; target="${target#https://}"; target="${target%%/*}"

    local ip=""
    # check if already an IP (with optional /cidr)
    if [[ "$target" =~ ^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)(/([0-9]+))?$ ]]; then
        ip="${BASH_REMATCH[1]}"
        cidr="${BASH_REMATCH[3]}"
        [[ -z "$cidr" ]] && cidr=$(guess_cidr "$ip")
    else
        # DNS resolve
        echo -e "  ${GY}Resolving ${B}${target}${R}${GY}…${R}"
        # try dig, then host, then getent
        if command -v dig &>/dev/null; then
            mapfile -t ips < <(dig +short A "$target" 2>/dev/null | grep -E '^[0-9]+\.')
        elif command -v host &>/dev/null; then
            mapfile -t ips < <(host "$target" 2>/dev/null | awk '/has address/{print $NF}')
        else
            mapfile -t ips < <(getent hosts "$target" 2>/dev/null | awk '{print $1}')
        fi

        if [[ ${#ips[@]} -eq 0 ]]; then
            echo -e "  ${RD}Could not resolve '${target}'${R}"
            exit 1
        fi

        # show all resolved IPs, process each
        echo -e "  ${GY}Resolved to: ${GN}${ips[*]}${R}\n"
        for ip in "${ips[@]}"; do
            cidr=$(guess_cidr "$ip")
            show_subnet "$ip" "$cidr" "$target"
        done

        # also show CNAME chain if dig available
        if command -v dig &>/dev/null; then
            local chain
            chain=$(dig +short "$target" 2>/dev/null | grep -v '^[0-9]')
            if [[ -n "$chain" ]]; then
                echo -e "  ${GY}CNAME chain:${R}"
                echo "$chain" | while read -r c; do
                    echo -e "  ${GY}  → ${CY}${c}${R}"
                done
                echo
            fi
        fi
        return
    fi

    show_subnet "$ip" "$cidr" ""
}

# ── self mode: gather all local interfaces ────────────────────
show_self() {
    echo -e "\n  ${B}${CY}subnetify${R}  ${GY}— your interfaces${R}\n"
    div

    # public IP
    local pub=""
    for svc in "https://api.ipify.org" "https://ifconfig.me/ip" "https://ipecho.net/plain"; do
        pub=$(curl -sf --max-time 3 "$svc" 2>/dev/null | tr -d '[:space:]')
        [[ -n "$pub" ]] && break
    done
    if [[ -n "$pub" ]]; then
        local geo isp city country
        geo=$(curl -sf --max-time 3 "https://ipinfo.io/${pub}/json" 2>/dev/null)
        city=$(    echo "$geo" | grep '"city"'    | cut -d'"' -f4)
        country=$( echo "$geo" | grep '"country"' | cut -d'"' -f4)
        isp=$(     echo "$geo" | grep '"org"'     | cut -d'"' -f4)
        printf "\n  ${GY}%-17s${R}  ${B}%s${R}\n" "Public IP" "$pub"
        [[ -n "$city" ]] && printf "  ${GY}%-17s${R}  %s, %s\n" "Location" "$city" "$country"
        [[ -n "$isp"  ]] && printf "  ${GY}%-17s${R}  %s\n"     "ISP/Org"  "$isp"
    else
        echo -e "\n  ${YL}Public IP: offline or unreachable${R}"
    fi

    echo; div

    local found=0
    if command -v ip &>/dev/null; then
        local cur_iface=""
        while IFS= read -r line; do
            if [[ "$line" =~ ^[0-9]+:\ ([^:@]+) ]]; then
                cur_iface="${BASH_REMATCH[1]// /}"
            fi
            if [[ "$line" =~ inet\ ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+) ]]; then
                local lip="${BASH_REMATCH[1]}" lcidr="${BASH_REMATCH[2]}"
                [[ "$lip" == "127.0.0.1" ]] && continue
                show_subnet "$lip" "$lcidr" "$cur_iface"
                (( found++ ))
            fi
        done < <(ip addr show 2>/dev/null)

    elif command -v ifconfig &>/dev/null; then
        local cur_iface=""
        while IFS= read -r line; do
            # interface name line
            if [[ "$line" =~ ^([a-zA-Z][a-zA-Z0-9]*[0-9]):?  ]]; then
                cur_iface="${BASH_REMATCH[1]}"
            fi
            # Linux ifconfig: inet addr:x.x.x.x  Mask:x.x.x.x
            if [[ "$line" =~ inet\ addr:([0-9.]+).*Mask:([0-9.]+) ]]; then
                local lip="${BASH_REMATCH[1]}" smask="${BASH_REMATCH[2]}"
                [[ "$lip" == "127.0.0.1" ]] && continue
                local lcidr=0 IFS='.' m1 m2 m3 m4
                read -r m1 m2 m3 m4 <<< "$smask"
                for oct in $m1 $m2 $m3 $m4; do
                    for bit in 7 6 5 4 3 2 1 0; do
                        (( (oct >> bit) & 1 )) && (( lcidr++ ))
                    done
                done
                show_subnet "$lip" "$lcidr" "$cur_iface"
                (( found++ ))
            fi
            # macOS ifconfig: inet x.x.x.x netmask 0xffffff00
            if [[ "$line" =~ inet\ ([0-9.]+)\ netmask\ 0x([0-9a-fA-F]{8}) ]]; then
                local lip="${BASH_REMATCH[1]}" hm="${BASH_REMATCH[2]}"
                [[ "$lip" == "127.0.0.1" ]] && continue
                local mint=$(( 16#$hm )) lcidr=0
                for (( bit=31; bit>=0; bit-- )); do
                    (( (mint >> bit) & 1 )) && (( lcidr++ )) || break
                done
                show_subnet "$lip" "$lcidr" "$cur_iface"
                (( found++ ))
            fi
        done < <(ifconfig 2>/dev/null)
    else
        echo -e "  ${RD}No 'ip' or 'ifconfig' found${R}"
        exit 1
    fi

    (( found == 0 )) && echo -e "  ${YL}No non-loopback interfaces found${R}"

    # Tailscale bonus
    if command -v tailscale &>/dev/null; then
        local ts_ip; ts_ip=$(tailscale ip -4 2>/dev/null)
        if [[ -n "$ts_ip" ]]; then
            echo -e "  ${MG}Tailscale${R}"
            show_subnet "$ts_ip" "$(guess_cidr "$ts_ip")" "tailscale0"
        fi
    fi
}

# ── entry point ───────────────────────────────────────────────
if [[ $# -eq 0 ]]; then
    show_self
else
    echo -e "\n  ${B}${CY}subnetify${R}  ${GY}— target: ${B}$1${R}\n"
    div
    resolve_target "$1"
fi
