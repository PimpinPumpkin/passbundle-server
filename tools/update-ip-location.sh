#!/usr/bin/env bash
# Puts this month's IP-to-location database in place for the server, which
# shows roughly where a sign-in comes from with it (DESIGN.md, "New-device
# check", in the meta repo). The server never asks another service: it reads
# this file on its own disk (IP_LOCATION_DATABASE, by default
# <data folder>/ip-location.mmdb), and shows no location without it.
#
#   tools/update-ip-location.sh <data folder or .mmdb path> [city|country]
#
# It downloads DB-IP's free "IP to City Lite" (or "IP to Country Lite") in
# the MaxMind DB format, this month's or, early in a month, last month's;
# checks it's a MaxMind DB file; and moves it into place in one step, so the
# server, which reads the file in place, never sees half a file. The server
# notices the new one within a minute. Run it monthly, for example from cron:
#
#   17 4 3 * * /opt/passbundle/tools/update-ip-location.sh /var/lib/passbundle
#
# With Docker, run it on the host against the folder mounted as /data.
#
# License: DB-IP's Lite databases are under the Creative Commons Attribution
# 4.0 International License (https://creativecommons.org/licenses/by/4.0/).
# The server credits DB-IP next to each location it shows
# (IP_LOCATION_ATTRIBUTION, IP_LOCATION_ATTRIBUTION_URL); if you use another
# database, set those to its credit.
set -euo pipefail

if [ $# -lt 1 ] || [ $# -gt 2 ]; then
  echo "usage: $0 <data folder or .mmdb path> [city|country]" >&2
  exit 2
fi
target=$1
kind=${2:-city}
case "$kind" in
  city | country) ;;
  *)
    echo "the second argument is city or country" >&2
    exit 2
    ;;
esac
if [ -d "$target" ]; then
  target="$target/ip-location.mmdb"
fi
dir=$(dirname "$target")
[ -d "$dir" ] || { echo "$dir isn't a folder" >&2; exit 1; }

work=$(mktemp -d "$dir/.ip-location.XXXXXX")
trap 'rm -f "$work"/*; rmdir "$work"' EXIT

fetched=""
for month in "$(date -u +%Y-%m)" "$(date -u -d "$(date -u +%Y-%m-15) -1 month" +%Y-%m 2>/dev/null || date -u -v-1m +%Y-%m)"; do
  url="https://download.db-ip.com/free/dbip-$kind-lite-$month.mmdb.gz"
  if curl -fsSL --proto '=https' --tlsv1.2 --max-time 600 -o "$work/db.mmdb.gz" "$url"; then
    fetched=$month
    break
  fi
done
[ -n "$fetched" ] || { echo "couldn't download DB-IP's $kind database" >&2; exit 1; }

gunzip -c "$work/db.mmdb.gz" > "$work/db.mmdb"
# A MaxMind DB file ends with its metadata, after this marker.
tail -c 131072 "$work/db.mmdb" > "$work/tail"
if ! LC_ALL=C grep -aqF $'\xab\xcd\xefMaxMind.com' "$work/tail"; then
  echo "the download isn't a MaxMind DB file" >&2
  exit 1
fi
chmod 0644 "$work/db.mmdb"
mv -f "$work/db.mmdb" "$target"
echo "IP location database: DB-IP $kind lite $fetched at $target"
