#!/bin/sh
# Build only a controlled FreeRADIUS dictionary include from structured DB values.
set -eu
out_dir=/opt/etc/raddb/radiusstack-generated
out="$out_dir/dictionary.custom-vsa"
tmp="$out.tmp"
mkdir -p "$out_dir"
printf '%s\n' '# Generated from validated RadiusStack settings; do not edit.' > "$tmp"
query="SELECT setting_value FROM settings WHERE setting_key = 'custom_reply_attributes' UNION ALL SELECT setting_value FROM tenant_settings WHERE setting_key = 'custom_reply_attributes'"
mysql -h "$DB_HOST" -u "$DB_USER" -p"$DB_PASSWORD" -D "$DB_NAME" -N -B -e "$query" 2>/dev/null | while IFS= read -r json; do
  printf '%s' "$json" | jq -r '.[]? | select(type == "object") | select((.name // .attribute | type) == "string") | select((.value_type // "string") | IN("string", "integer", "ipv4", "octets")) | select((.vendor_code|type) == "number" and (.vendor_code|floor == . and . >= 1 and . <= 4294967295)) | select((.vendor_attribute_number|type) == "number" and (.vendor_attribute_number|floor == . and . >= 1 and . <= 255)) | [(.vendor_code|tostring), (.vendor_attribute_number|tostring), (.name // .attribute), (.value_type // "string")] | @tsv' 2>/dev/null || true
done | sort -t "$(printf '\t')" -k1,1n -k2,2n -k3,3 | awk -F '\t' '
  $1 ~ /^[0-9]+$/ && $2 ~ /^[0-9]+$/ && $3 ~ /^[A-Za-z][A-Za-z0-9_.-]*$/ && $4 ~ /^(string|integer|ipv4|octets)$/ {
    static_name = ($3 ~ /^(Ubiquiti-Rate-Limit|Ubiquiti-Rate-Limit-DL|Ubiquiti-Rate-Limit-UL|Cisco-AVPair|Cisco-NAS-Port|Cisco-Idle-Limit|Cisco-Session-Timeout|Cisco-Account-Info|Cisco-Command-Code|Juniper-Local-User-Name|Juniper-Allow-Commands|Juniper-Deny-Commands|Juniper-User-Permissions|Mikrotik-Recv-Limit|Mikrotik-Xmit-Limit|Mikrotik-Group|Mikrotik-Rate-Limit|Mikrotik-Address-List|D-Link-AVPair|D-Link-User-Privilege)$/)
    number = $1 ":" $2
    if (!static_name && !seen_name[$3]++ && !seen_number[number]++) rows[++count] = $1 FS $2 FS $3 FS $4
  }
  END {
    for (i = 1; i <= count; i++) {
      split(rows[i], f, FS); type = f[4] == "ipv4" ? "ipaddr" : f[4]
      if (vendor != f[1]) { if (vendor != "") print "END-VENDOR RadiusStack-" vendor; vendor = f[1]; print "VENDOR RadiusStack-" vendor " " vendor; print "BEGIN-VENDOR RadiusStack-" vendor }
      print "ATTRIBUTE " f[3] " " f[2] " " type
    }
    if (vendor != "") print "END-VENDOR RadiusStack-" vendor
  }' >> "$tmp"
mv "$tmp" "$out"
