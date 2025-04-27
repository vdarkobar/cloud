#!/usr/bin/env bash
set -eEuo pipefail

# Colors and symbols
YW="\033[33m"
BL="\033[36m"
RD="\033[01;31m"
GN="\033[1;92m"
CL="\033[m"
TAB="  "
CM="${TAB}✔️${TAB}${CL}"

# --- Header Info Inline ---
clear
cat <<"EOF"
Delete LXC containers on a Proxmox VE server
EOF

echo "Loading..."
whiptail --backtitle "Proxmox VE" \
        --title "Proxmox VE LXC Deletion" \
        --yesno "This will delete LXC containers. Proceed?" 10 58

# List containers
NODE=$(hostname)
containers=$(pct list | tail -n +2 | awk '{print $0 " " $4}')
if [ -z "$containers" ]; then
    whiptail --title "LXC Container Delete" \
             --msgbox "No LXC containers available!" 10 60
    exit 1
fi

# Build checklist items
menu_items=()
FORMAT="%-10s %-15s"
while read -r line; do
    id=$(awk '{print $1}' <<<"$line")
    name=$(awk '{print $2}' <<<"$line")
    status=$(awk '{print $3}' <<<"$line")
    pretty=$(printf "$FORMAT" "$name" "$status")
    menu_items+=( "$id" "$pretty" "OFF" )
done <<<"$containers"

CHOICES=$(whiptail --title "LXC Container Delete" \
                   --checklist "Select LXC containers to delete:" \
                   25 60 13 \
                   "${menu_items[@]}" \
                   3>&2 2>&1 1>&3)

if [ -z "${CHOICES//\"/}" ]; then
    whiptail --title "LXC Container Delete" \
             --msgbox "No containers selected!" 10 60
    exit 1
fi

# Deletion mode
read -p "Delete containers manually or automatically? (Default: manual) m/a: " mode
mode=${mode:-m}

# Process each selected container
for cid in $(tr -d '"' <<<"$CHOICES" | tr ' ' '\n'); do
    st=$(pct status "$cid" | awk '{print $2}')
    if [ "$st" = "running" ]; then
        echo -e "${BL}[Info]${GN} Stopping container $cid...${CL}"
        pct stop "$cid" &
        wait $!
        echo -e "${BL}[Info]${GN} Container $cid stopped.${CL}"
    fi

    # Decide whether to delete
    if [ "$mode" = "a" ]; then
        confirm_delete=true
    else
        read -p "Delete container $cid? (y/N): " yn
        case "$yn" in [Yy]*) confirm_delete=true ;; *) confirm_delete=false ;; esac
    fi

    if [ "$confirm_delete" = true ]; then
        echo -e "${BL}[Info]${GN} Deleting container $cid...${CL}"
        pct destroy "$cid" -f &
        pid=$!

        # Inline spinner
        spin='|/-\'
        while ps -p $pid >/dev/null; do
            for c in ${spin}; do
                printf " [%c]  " "$c"
                sleep 0.1
                printf "\r"
            done
        done
        wait $pid && echo "Container $cid deleted." \
                      || whiptail --title "Error" \
                                   --msgbox "Failed to delete container $cid." 10 60
    else
        echo -e "${BL}[Info]${RD} Skipping container $cid...${CL}"
    fi
done

# Final header & completion message
clear
cat <<"EOF"
Delete LXC containers on a Proxmox VE server
EOF
echo -e "${GN}Deletion process completed.${CL}"
