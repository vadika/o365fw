{ pkgs ? import <nixpkgs> {} }:

pkgs.stdenv.mkDerivation rec {
  pname = "genfwrules";
  version = "0.1.0";

  src = ./.;

  buildInputs = with pkgs; [ bash curl jq ];

  installPhase = ''
    mkdir -p $out/bin
    cp genfwrules.sh $out/bin/genfwrules
    chmod +x $out/bin/genfwrules
  '';

  meta = with pkgs.lib; {
    description = "Generate firewall rules for Office 365 endpoints";
    homepage = "https://github.com/vadika/o365fw";
    license = licenses.mit;
    maintainers = with maintainers; [ vadika ];
    platforms = platforms.all;
  };
}
