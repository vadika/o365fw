{ lib
, stdenv
, fetchFromGitHub
, bash
, curl
, jq
}:

stdenv.mkDerivation rec {
  pname = "genfwrules";
  version = "0.1.0";

  src = ./.;

  buildInputs = [ bash curl jq ];

  installPhase = ''
    mkdir -p $out/bin
    cp genfwrules.sh $out/bin/genfwrules
    chmod +x $out/bin/genfwrules
  '';

  meta = with lib; {
    description = "Generate firewall rules for Office 365 endpoints";
    homepage = "https://github.com/yourusername/genfwrules";
    license = licenses.mit;
    maintainers = with maintainers; [ yourusername ];
    platforms = platforms.all;
  };
}
