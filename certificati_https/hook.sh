#!/usr/bin/env bash
set -e
set -u
set -o pipefail

domain="web-server-h2"
token=" ** TOKEN ACCOUNT DUCKDNS ** "

case "$1" in
    "deploy_challenge")
        curl "https://www.duckdns.org/update?domains=$domain&token=$token&txt=$4"
        ;;
    "clean_challenge")
        curl "https://www.duckdns.org/update?domains=$domain&token=$token&txt=removed&clear=true"
        ;;
    *)
        exit 0
        ;;
esac
