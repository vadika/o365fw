{ pkgs ? import <nixpkgs> {} }:

let
  generateO365FWScript = pkgs.writeTextFile {
    name = "generate-o365fw-script";
    text = ''
    #!/usr/bin/env bash

    set -euo pipefail

    # Fetch Office 365 endpoints
    ENDPOINTS_URL="https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7"
    TEMP_FILE=$(mktemp)

    curl -s "$ENDPOINTS_URL" > "$TEMP_FILE"

    # Function to preprocess URLs
    preprocess_url() {
        local url="$1"
        # Replace "*." prefix with "." if present
        echo "''${url/\*./\.}"
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

    # Main function
    main() {
        generate_iptables_rules
    }

    # Run main function
    main "$@"

    # Clean up
    rm "$TEMP_FILE"
    '';
  };

  o365fw = generateO365FWScript;
in
{
  inherit o365fw generateO365FWScript;
}
