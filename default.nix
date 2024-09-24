{ pkgs ? import <nixpkgs> {} }:

let
  endpointsFile = pkgs.fetchurl {
    url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7";
    sha256 = "1zly0g23vray4wg6fjxxdys6zzksbymlzggbg75jxqcf8g9j6xnw";
  };

  generateO365FWScript = pkgs.writeShellScript "generate-o365fw-script" ''
    #!/usr/bin/env bash

    set -euo pipefail

    ENDPOINTS_FILE="${endpointsFile}"

    preprocess_url() {
        local url="$1"
        # Return the URL as-is without any filtering
        echo "$url"
    }

    generate_iptables_rules() {
        echo "# Office 365 Firewall Rules"
        echo

        jq -r '.[] | select(.category == "Optimize" or .category == "Allow" or .category == "Default") | .ips[]?' "$ENDPOINTS_FILE" | sort -u | while read -r ip; do
            if [[ $ip == *":"* ]]; then
                echo "ip6tables -A OUTPUT -d $ip -j ACCEPT"
            else
                echo "iptables -A OUTPUT -d $ip -j ACCEPT"
            fi
        done

        echo

        jq -r '.[] | select(.category == "Optimize" or .category == "Allow" or .category == "Default") | .urls[]?' "$ENDPOINTS_FILE" | sort -u | while read -r url; do
            processed_url=$(preprocess_url "$url")
            if [[ "$processed_url" != "" ]]; then
                echo "iptables -A OUTPUT -p tcp --dport 80 -m string --string \"$processed_url\" --algo bm -j ACCEPT"
                echo "iptables -A OUTPUT -p tcp --dport 443 -m string --string \"$processed_url\" --algo bm -j ACCEPT"
            fi
        done
    }

    generate_iptables_rules
  '';

  o365fw = pkgs.runCommand "o365fw" {
    buildInputs = [ pkgs.jq ];
  } ''
    ${generateO365FWScript} > $out
  '';

  #runO365FWScript = pkgs.writeShellScriptBin "run-o365fw-script" ''
  #  ${generateO365FWScript}
  #'';
in
{
  inherit o365fw ;
}
