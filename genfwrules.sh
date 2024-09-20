#!/bin/bash

# Fetch Office 365 endpoints
ENDPOINTS_URL="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
TEMP_FILE="/tmp/o365_endpoints.json"

curl -s "$ENDPOINTS_URL" > "$TEMP_FILE"

# Function to generate iptables rules
generate_iptables_rules() {
    echo "# Office 365 Firewall Rules"
    echo

    # Allow outbound traffic to Office 365 IP ranges
    jq -r '.[] | select(.category == "Optimize" or .category == "Allow") | .ips[]?' "$TEMP_FILE" | sort -u | while read -r ip; do
        if [[ $ip == *":"* ]]; then
            echo "ip6tables -A OUTPUT -d $ip -j ACCEPT"
        else
            echo "iptables -A OUTPUT -d $ip -j ACCEPT"
        fi
    done

    echo

    # Allow outbound traffic to required URLs
    jq -r '.[] | select(.category == "Optimize" or .category == "Allow") | .urls[]?' "$TEMP_FILE" | sort -u | while read -r url; do
        echo "iptables -A OUTPUT -p tcp --dport 80 -m string --string \"$url\" --algo bm -j ACCEPT"
        echo "iptables -A OUTPUT -p tcp --dport 443 -m string --string \"$url\" --algo bm -j ACCEPT"
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
}

# Generate rules (uncomment the one you need)
generate_iptables_rules
# generate_pf_rules

# Clean up
rm "$TEMP_FILE"

