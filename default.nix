{ pkgs ? import <nixpkgs> {} }:

let
  endpointsFile = pkgs.fetchurl {
    url = "https://endpoints.office.com/endpoints/worldwide?clientrequestid=b10c5ed1-bad1-445f-b386-b919946339a7";
    sha256 = "1zly0g23vray4wg6fjxxdys6zzksbymlzggbg75jxqcf8g9j6xnw";
  };

  generateTinyproxyConf = pkgs.writeShellScript "generate-tinyproxy-conf" ''
    #!/usr/bin/env bash
    set -euo pipefail

    ENDPOINTS_FILE="${endpointsFile}"

    echo "Port 3128"
    echo "Timeout 600"
    echo "DefaultErrorFile \"/usr/share/tinyproxy/default.html\""
    echo "StatFile \"/usr/share/tinyproxy/stats.html\""
    echo "LogFile \"/var/log/tinyproxy/tinyproxy.log\""
    echo "LogLevel Info"
    echo "PidFile \"/var/run/tinyproxy/tinyproxy.pid\""

    echo "# Office 365 Allow rules"
    jq -r '.[] | select(.category == "Optimize" or .category == "Allow" or .category == "Default") | .urls[]?' "$ENDPOINTS_FILE" | sort -u | while read -r url; do
      if [[ $url == \** ]]; then
        # For wildcard domains, we'll allow the base domain
        base_domain=$(echo "$url" | sed 's/^\*\.//')
        echo "Allow .$base_domain"
      else
        echo "Allow $url"
      fi
    done

    echo "# Deny all other traffic"
    echo "FilterDefaultDeny Yes"
  '';

  tinyproxyConf = pkgs.runCommand "tinyproxy.conf" {
    buildInputs = [ pkgs.jq ];
  } ''
    ${generateTinyproxyConf} > $out
  '';

  generateO365FWScript = pkgs.writeShellScript "generate-o365fw-script" ''
    #!/usr/bin/env bash

    set -euo pipefail

    ENDPOINTS_FILE="${endpointsFile}"


    generate_iptables_rules() {
        echo "# Office 365 Firewall Rules"
        echo

        # Default policies
        echo "iptables -P INPUT DROP"
        echo "iptables -P FORWARD DROP"
        echo "iptables -P OUTPUT DROP"
        echo "ip6tables -P INPUT DROP"
        echo "ip6tables -P FORWARD DROP"
        echo "ip6tables -P OUTPUT DROP"
        echo

        # Allow loopback
        echo "iptables -A INPUT -i lo -j ACCEPT"
        echo "iptables -A OUTPUT -o lo -j ACCEPT"
        echo "ip6tables -A INPUT -i lo -j ACCEPT"
        echo "ip6tables -A OUTPUT -o lo -j ACCEPT"
        echo

        # Allow DNS (both UDP and TCP)
        echo "iptables -A OUTPUT -p udp --dport 53 -j ACCEPT"
        echo "iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT"
        echo "ip6tables -A OUTPUT -p udp --dport 53 -j ACCEPT"
        echo "ip6tables -A OUTPUT -p tcp --dport 53 -j ACCEPT"
        echo

        # Allow established and related connections
        echo "iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        echo "iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        echo "ip6tables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        echo "ip6tables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
        echo

        # Allow Tinyproxy
        echo "iptables -A INPUT -p tcp --dport 3128 -j ACCEPT"
        echo "iptables -A OUTPUT -p tcp --dport 3128 -j ACCEPT"
        echo "ip6tables -A INPUT -p tcp --dport 3128 -j ACCEPT"
        echo "ip6tables -A OUTPUT -p tcp --dport 3128 -j ACCEPT"
        echo

        # Allow outgoing connections to Office 365 IP ranges through Squid proxy
        jq -r '.[] | select(.category == "Optimize" or .category == "Allow" or .category == "Default") | .ips[]?' "$ENDPOINTS_FILE" | sort -u | while read -r ip; do
            if [[ $ip == *":"* ]]; then
                echo "ip6tables -A OUTPUT -d $ip -p tcp -m tcp --dport 80 -j ACCEPT"
                echo "ip6tables -A OUTPUT -d $ip -p tcp -m tcp --dport 443 -j ACCEPT"
            else
                echo "iptables -A OUTPUT -d $ip -p tcp -m tcp --dport 80 -j ACCEPT"
                echo "iptables -A OUTPUT -d $ip -p tcp -m tcp --dport 443 -j ACCEPT"
            fi
        done

        # Log and drop all other traffic
        echo
        echo "iptables -A INPUT -j LOG --log-prefix \"[IPTABLES INPUT] : \" --log-level 7"
        echo "iptables -A INPUT -j DROP"
        echo "iptables -A OUTPUT -j LOG --log-prefix \"[IPTABLES OUTPUT] : \" --log-level 7"
        echo "iptables -A OUTPUT -j DROP"
        echo "ip6tables -A INPUT -j LOG --log-prefix \"[IP6TABLES INPUT] : \" --log-level 7"
        echo "ip6tables -A INPUT -j DROP"
        echo "ip6tables -A OUTPUT -j LOG --log-prefix \"[IP6TABLES OUTPUT] : \" --log-level 7"
        echo "ip6tables -A OUTPUT -j DROP"
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
  configureFirewall = pkgs.writeShellScriptBin "configure-firewall" ''
    #!/usr/bin/env bash
    set -euo pipefail

    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
      echo "This script must be run as root" >&2
      exit 1
    fi

    # Apply the firewall rules
    echo "Applying Office 365 firewall rules..."
    
    while IFS= read -r line; do
      if [[ $line =~ ^#.*$ ]]; then
        echo "$line"
      else
        echo "Executing: $line"
        eval "$line"
      fi
    done < ${o365fw}

    echo "Firewall rules for Office 365 have been applied."
  '';
  configureFirewallString = pkgs.writeTextFile {
    name = "configure-firewall-string";
    text = ''
      #!/usr/bin/env bash
      set -euo pipefail

      # Check if running as root
      if [ "$(id -u)" -ne 0 ]; then
        echo "This script must be run as root" >&2
        exit 1
      fi

      # Apply the firewall rules
      echo "Applying Office 365 firewall rules..."
      
      ${builtins.readFile o365fw}

      echo "Firewall rules for Office 365 have been applied."
    '';
  };

  startTinyproxy = pkgs.writeShellScriptBin "start-tinyproxy" ''
    #!/usr/bin/env bash
    set -euo pipefail

    # Check if running as root
    if [ "$(id -u)" -ne 0 ]; then
      echo "This script must be run as root" >&2
      exit 1
    fi

    echo "Starting Tinyproxy..."
    ${pkgs.tinyproxy}/bin/tinyproxy -c ${tinyproxyConf}
    echo "Tinyproxy has been started."
  '';
in
{
  inherit o365fw configureFirewall configureFirewallString startTinyproxy;
}
