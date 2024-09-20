#!/usr/bin/env bash

set -euo pipefail

# Fetch Office 365 endpoints
ENDPOINTS_URL="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
TEMP_FILE=$(mktemp)

curl -s "$ENDPOINTS_URL" > "$TEMP_FILE"

# Function to preprocess URLs
preprocess_url() {
    local url="$1"
    # Remove "*." prefix if present
    echo "${url#\*.}"
}

# Function to generate iptables rules
generate_iptables_rules() {
    echo "# Office 365 Firewall Rules"
    echo

    # Allow outbound traffic to Office 365 IP ranges
    jq -r '.[] | select(.category == "Optimize" or .category == "Allow" or .category == "Default") | .ips[]?' "$TEMP_FILE" | sort -u | while read -r ip; do
        if [[ $ip == *":"* ]]; then
            echo "ip6tables -A OUTPUT -d $ip -j ACCEPT"
        else
            echo "iptables -A OUTPUT -d $ip -j ACCEPT"
        fi
    done

    echo

    # Allow outbound traffic to required URLs
    jq -r '.[] | select(.category == "Optimize" or .category == "Allow" or .category == "Default") | .urls[]?' "$TEMP_FILE" | sort -u | while read -r url; do
        processed_url=$(preprocess_url "$url")
        echo "iptables -A OUTPUT -p tcp --dport 80 -m string --string \"$processed_url\" --algo bm -j ACCEPT"
        echo "iptables -A OUTPUT -p tcp --dport 443 -m string --string \"$processed_url\" --algo bm -j ACCEPT"
    done
}

# Function to generate PF (Packet Filter) rules for BSD systems
generate_pf_rules() {
    echo "# Office 365 Firewall Rules for PF"
    echo

    echo "table <office365_ips> {"
    jq -r '.[] | select(.category == "Optimize" or .category == "Allow") | .ips[]?' "$TEMP_FILE" | sort -u | sed 's/^/    /'
    echo "}"
    echo

    echo "pass out quick to <office365_ips>"
    echo

    echo "# URL-based rules are more complex in PF and may require application layer filtering"
    echo "# Consider using a proxy or next-gen firewall for URL filtering"
    echo "# Note: URLs have been preprocessed to remove '*.' prefixes for compatibility"
}

# Main function
main() {
    case "${1:-iptables}" in
        iptables)
            generate_iptables_rules
            ;;
        pf)
            generate_pf_rules
            ;;
        *)
            echo "Usage: $0 [iptables|pf]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"

# Clean up
rm "$TEMP_FILE"

