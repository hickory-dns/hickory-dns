#!/bin/bash
set -e

# This is based on the configure_child.sh script from
# https://github.com/yevheniya-nosyk/imc2023-ede.
#
# Note that the original setup uses a mixture of BIND 9.11.9 and a modern BIND
# package from the VPS's distribution. BIND 9.11.9 is needed because its
# version of dnssec-keygen and dnssec-signzone support obsolete signature
# algorithms and arbitrary NSEC3 iteration counts. In the original scripts,
# the modern version of BIND on the VPSes is used for generating all other
# keys and signing all other zones that don't require those deprecated
# features, and as the authoritative name server for the zones.
#
# In order to simplify the zone creation process, and reduce the number of
# containers needed, this modified script is instead written to use the BIND
# 9.11.9 version of dnssec-keygen and dnssec-signzone for all zones, and the
# BIND 9.11.9 version of named is used to serve the zone out of the same
# containers.
#
# The following changes have been made to this script.
# - Robustness:
#   - Added `set -e` to propagate errors.
#   - Make the regular expressions used when deleting keys for no-zsk and
#     no-ksk more strict, so that they can't have false positive matches on
#     base64-encoded public keys.
# - Integration with dns-test:
#   - Removed modification of named.conf, because the custom configuration file
#     dropped in the container already has the include directive added.
#   - Removed `service bind9 restart` since named is run directly, and not as
#     a service.
#   - Run dnssec-signzone inside faketime when signing the rrsig-exp-all zone,
#     so that we don't need to wait for the zone to expire. (dnssec-signzone
#     does not itself support signing a zone with a backdated expiry)
# - Replacing BIND 9.18/9.19 with BIND 9.11.9:
#   - Generate files for the dsa, rsamd5, nsec3-iter-1, nsec3-iter-51,
#     nsec3-iter-101, nsec3-iter-151, and nsec3-iter-200 zones here, instead
#     of copying existing files.
#   - Replace a hardcoded TTL of 600 in regular expressions with a more
#     permissive pattern, since dnssec-signzone's default TTL has changed.
#   - Delete DS records with the SHA-1 digest algorithm from dsset files, to
#     match the output of modern dnssec-signzone versions. The commands for
#     zones with corrupted DS records expect there to be only one DS record,
#     using SHA-256.
# - Performance:
#   - Removed sleep.
#   - Allow configuring only a subset of the subdomains, to skip unnecessary
#     key generation and signing operations.

# Store the variables
server_ip=$1
domain=$2
a_record=$3
aaaa_record=$4
shift 4
# Remaining arguments are an optional list of subdomains

# Create a directory to store zones or empty an existing one

zones_dir="/etc/bind/zones_ede"
if [ -d "$zones_dir" ]; then
    rm -rf $zones_dir/*
else
    mkdir $zones_dir
fi

# Create a configuration file that will be included by the main configuration file
local_conf="/etc/bind/named.conf.local-ede"
> $local_conf

# Create an empty dsset file, in case the selected subdomains don't have any DS
# records.
touch dsset_for_parent.txt

# Loop through the array of subdomains
if [ "$#" == "0" ]; then
    subdomains=("valid" "rrsig-exp-all" "allow-query-none" "allow-query-localhost" "no-ds" "no-zsk" "no-ksk" "ds-bad-tag" "ds-bad-key-algo" "ds-unassigned-key-algo" "ds-reserved-key-algo" "ds-bogus-digest-value" "ds-unassigned-digest-algo" "rrsig-exp-a" "rrsig-not-yet-a" "rrsig-not-yet-all" "rrsig-no-a" "rrsig-no-all" "nsec3-missing" "nsec3param-missing" "no-nsec3param-nsec3" "bad-nsec3-hash" "bad-nsec3-next" "nsec3-rrsig-missing" "bad-nsec3-rrsig" "bad-nsec3param-salt" "v6-doc" "v4-doc" "bad-zsk" "bad-ksk" "no-rrsig-ksk" "no-rrsig-dnskey" "bad-rrsig-ksk" "bad-rrsig-dnskey" "ed448" "rrsig-exp-before-all" "rrsig-exp-before-a" "no-dnskey-256" "no-dnskey-257" "no-dnskey-256-257" "bad-zsk-algo" "unassigned-zsk-algo" "reserved-zsk-algo" "unsigned" "dsa" "nsec3-iter-1" "nsec3-iter-51" "nsec3-iter-101" "nsec3-iter-151" "nsec3-iter-200" "rsamd5" "not-auth")
else
    subdomains=("$@")
fi

for subdomain in ${subdomains[@]}; do
    # Store the full zone name
    zone=$subdomain.$domain

    # The below domains are not intended to be reachable,
    # because the nameservers are set to documentation IPs
    # Therefore, we do not need to create any zone files, only referrals and glues at the parent
    if [[ $subdomain = "v4-doc" ]]; then
        echo "$zone.      IN      NS     ns1.$zone." >> glues.txt
        echo "ns1.$zone.  IN      A      198.51.100.0" >> glues.txt
        continue
    elif [[ $subdomain = "v6-doc" ]]; then
        echo "$zone.      IN      NS      ns1.$zone." >> glues.txt
        echo "ns1.$zone.  IN      AAAA      2001:db8::1" >> glues.txt
        continue
    # This domain name points to our nameservers, but we do not serve it
    elif [[ $subdomain = "not-auth" ]]; then
        echo "$zone.      IN      NS      ns1.$zone." >> glues.txt
        echo "ns1.$zone.  IN      A       $server_ip" >> glues.txt
        continue
    fi

    # For all the remaining subdomains we create zone files and (mis)configure them
    output_dir=$zones_dir/$zone
    mkdir -p $output_dir

    # Create a basic (valid) zone file
    echo "\$ORIGIN $zone." >> $output_dir/db.$zone
    echo "\$TTL 600" >> $output_dir/db.$zone
    echo "@	SOA	ns1.$zone.	hostmaster.$zone. (" >> $output_dir/db.$zone
    echo "        $(date +%Y%m%d) ; serial" >> $output_dir/db.$zone
    echo "        21600      ; refresh after 6 hours" >> $output_dir/db.$zone
    echo "        3600       ; retry after 1 hour" >> $output_dir/db.$zone
    echo "        604800     ; expire after 1 week" >> $output_dir/db.$zone
    echo "        86400 )    ; minimum TTL of 1 day" >> $output_dir/db.$zone
    echo "" >> $output_dir/db.$zone
    echo "@               IN      NS      ns1.$zone." >> $output_dir/db.$zone
    echo "ns1             IN      A       $server_ip" >> $output_dir/db.$zone
    echo "@               IN      A       $a_record" >> $output_dir/db.$zone
    echo "@               IN      AAAA    $aaaa_record " >> $output_dir/db.$zone


    # First generate a KSK and a ZSK using RSASHA256 algorithm (number 8)
    # and add both to zone files
    # There are two exceptions: domains signed with other algorithms and the unsigned one
    if [[ $subdomain = "ed448" ]]; then
        dnssec-keygen -K $output_dir -a ED448 -n ZONE $zone
        dnssec-keygen -K $output_dir -f KSK -a ED448 -n ZONE $zone
    elif [[ $subdomain = "dsa" ]]; then
        dnssec-keygen -K $output_dir -a DSA -b 1024 -n ZONE $zone
        dnssec-keygen -K $output_dir -f KSK -a DSA -b 1024 -n ZONE $zone
    elif [[ $subdomain = "rsamd5" ]]; then
        dnssec-keygen -K $output_dir -a RSAMD5 -b 1024 -n ZONE $zone
        dnssec-keygen -K $output_dir -f KSK -a RSAMD5 -b 1024 -n ZONE $zone
    elif [[ $subdomain = "unsigned" ]]; then
        # Do not create keys
        true
    else
        dnssec-keygen -K $output_dir -a RSASHA256 -b 2048 -n ZONE $zone
        dnssec-keygen -K $output_dir -f KSK -a RSASHA256 -b 2048 -n ZONE $zone
    fi

    # Add public keys into the zone file, unless the domain is unsigned
    if [[ $subdomain != "unsigned" ]]; then
        cat $output_dir/*.key >> $output_dir/db.$zone
    fi

    # Use no salt and 0 additional iterations for NSEC3, unless otherwise specified.
    # Signatures will expire in almost half a year, unless otherwise specified.
    if [[ $subdomain = "rrsig-exp-all" ]]; then
        # Create an expired signature by running dnssec-signzone with a clock
        # set in the past. Merely specifying an end time in the past causes
        # problems with identifying the active KSK.
        faketime -f -86400 dnssec-signzone -3 - -K $output_dir -e now+300 -o $zone $output_dir/db.$zone
    elif [[ $subdomain = "unsigned" ]]; then
        # Do not sign the zone
        true
    elif [[ $subdomain = "dsa" ]] || [[ $subdomain = "rsamd5" ]]; then
        # These algorithms do not support NSEC3
        dnssec-signzone -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    elif [[ $subdomain = "nsec3-iter-1" ]]; then
        dnssec-signzone -3 - -H 1 -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    elif [[ $subdomain = "nsec3-iter-51" ]]; then
        dnssec-signzone -3 - -H 51 -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    elif [[ $subdomain = "nsec3-iter-101" ]]; then
        dnssec-signzone -3 - -H 101 -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    elif [[ $subdomain = "nsec3-iter-151" ]]; then
        dnssec-signzone -3 - -H 151 -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    elif [[ $subdomain = "nsec3-iter-200" ]]; then
        dnssec-signzone -3 - -H 200 -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    else
        dnssec-signzone -3 - -K $output_dir -e now+15000000 -o $zone $output_dir/db.$zone
    fi

    # Configure subdomains that manipulate DNSKEY flags

    # Set the ZSK Zone Key flag to 0
    if [[ $subdomain = "no-dnskey-256" ]]; then
        sed -i "s/DNSKEY.*256.*3.*8/DNSKEY	0 3 8/g" $output_dir/db.$zone.signed
    # Set the KSK Zone Key flag to 0
    elif [[ $subdomain = "no-dnskey-257" ]]; then
        sed -i "s/DNSKEY.*257.*3.*8/DNSKEY	0 3 8/g" $output_dir/db.$zone.signed
    elif [[ $subdomain = "no-dnskey-256-257" ]]; then
        sed -i "s/DNSKEY.*256.*3.*8/DNSKEY	0 3 8/g" $output_dir/db.$zone.signed
        sed -i "s/DNSKEY.*257.*3.*8/DNSKEY	0 3 8/g" $output_dir/db.$zone.signed
    fi

    # Configure subdomains that manipulate DNSKEYs

    # Comment out the ZSK DNSKEY
    if [[ $subdomain = "no-zsk" ]]; then
        # Find numbers of lines where the key is located
        line_start=$(grep -n 'DNSKEY.*256' $output_dir/db.$zone.signed | cut -f1 -d:)
        line_end=$(grep -n ' ZSK;' $output_dir/db.$zone.signed | cut -f1 -d:)
        sed -i "${line_start},${line_end}d" $output_dir/db.$zone.signed
    # Edit the part of the ZSK
    elif [[ $subdomain = "bad-zsk" ]]; then
        # Find the first line with the ZSK
        line_key=$(grep -A 1 'DNSKEY.*256' $output_dir/db.$zone.signed | tail -1 | xargs )
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-5)
        line_key_new=$rand_substring${line_key:5}
        sed -i "s@$line_key@$line_key_new@g" $output_dir/db.$zone.signed
    # Set the wrong algorithm number for the ZSK
    elif [[ $subdomain = "bad-zsk-algo" ]]; then
        sed -i "s/DNSKEY.*256.*3.*8/DNSKEY	256 3 7/g" $output_dir/db.$zone.signed
    # Set the unassigned algorithm number for the ZSK
    elif [[ $subdomain = "unassigned-zsk-algo" ]]; then
        sed -i "s/DNSKEY.*256.*3.*8/DNSKEY	256 3 100/g" $output_dir/db.$zone.signed
    # Set the reserved algorithm number for the ZSK
    elif [[ $subdomain = "reserved-zsk-algo" ]]; then
        sed -i "s/DNSKEY.*256.*3.*8/DNSKEY	256 3 200/g" $output_dir/db.$zone.signed
    # Edit the part of the KSK
    elif [[ $subdomain = "bad-ksk" ]]; then
        # Find the first line with the KSK
        line_key=$(grep -A 1 'DNSKEY.*257' $output_dir/db.$zone.signed | tail -1 | xargs )
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-5)
        line_key_new=$rand_substring${line_key:5}
        sed -i "s@$line_key@$line_key_new@g" $output_dir/db.$zone.signed
    # Comment out the KSK DNSKEY
    elif [[ $subdomain = "no-ksk" ]]; then
        # Find numbers of lines where the key is located
        line_start=$(grep -n 'DNSKEY.*257' $output_dir/db.$zone.signed | cut -f1 -d:)
        line_end=$(grep -n ' KSK;' $output_dir/db.$zone.signed | cut -f1 -d:)
        sed -i "${line_start},${line_end}d" $output_dir/db.$zone.signed
    fi

    # Configure subdomains that manipulate RRSIGs

    # Remove the signature over the KSK
    if [[ $subdomain = "no-rrsig-ksk" ]]; then
        # Find the ID of the key signing key
        ksk_id=$(grep "KSK;" $output_dir/db.$zone.signed | awk -F' = ' '{print $NF}')
        # Find the line containing the signature over KSK DNSKEY as well as where it starts and ends
        line_rrsig_middle=$(grep  -n "$ksk_id.*no-rrsig-ksk.*" $output_dir/db.$zone.signed | cut -f1 -d:)
        line_rrsig_start_num=$((line_rrsig_middle-1))
        line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
        line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
        sed -i "${line_rrsig_start_num},${line_rrsig_end_num}d" $output_dir/db.$zone.signed
    # Remove both DNSKEY signatures
    elif [[ $subdomain = "no-rrsig-dnskey" ]]; then
        # First delete the signature over the KSK
        ksk_id=$(grep "KSK;" $output_dir/db.$zone.signed | awk -F' = ' '{print $NF}')
        # Find the line containing the signature over KSK DNSKEY as well as where it starts and ends
        line_rrsig_middle=$(grep  -n "$ksk_id.*no-rrsig-dnskey.*" $output_dir/db.$zone.signed | cut -f1 -d:)
        line_rrsig_start_num=$((line_rrsig_middle-1))
        line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
        line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
        sed -i "${line_rrsig_start_num},${line_rrsig_end_num}d" $output_dir/db.$zone.signed
        # Next delete the signature over the ZSK
        line_rrsig_start_num=$(grep -n "RRSIG.*DNSKEY.*8.*3.*[0-9]\+" $output_dir/db.$zone.signed | cut -f1 -d:)
        line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
        line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
        sed -i "${line_rrsig_start_num},${line_rrsig_end_num}d" $output_dir/db.$zone.signed
    # Edit the signature over the KSK
    elif [[ $subdomain = "bad-rrsig-ksk" ]]; then
        # Find the ID of the key signing key
        ksk_id=$(grep "KSK;" $output_dir/db.$zone.signed | awk -F' = ' '{print $NF}')
        # Find the first line of the KSK signature
        line_rrsig=$(grep -A2 'RRSIG.*DNSKEY.*8.*3' $output_dir/db.$zone.signed | grep -A1 ".*${ksk_id}.*" | tail -1 | xargs)
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-5)
        line_rrsig_new=$rand_substring${line_rrsig:5}
        sed -i "s@$line_rrsig@$line_rrsig_new@g" $output_dir/db.$zone.signed
    # Edit both DNSKEY RRSIGs
    elif [[ $subdomain = "bad-rrsig-dnskey" ]]; then
        # Find the ID of the key signing key
        ksk_id=$(grep "KSK;" $output_dir/db.$zone.signed | awk -F' = ' '{print $NF}')
        # Find the ID of the zone signing key
        zsk_id=$(grep "ZSK;" $output_dir/db.$zone.signed | awk -F' = ' '{print $NF}')
        # Edit the KSK signature
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-5)
        line_ksk_rrsig=$(grep -A2 'RRSIG.*DNSKEY.*8.*3' $output_dir/db.$zone.signed | grep -A1 ".*${ksk_id}.*" | tail -1 | xargs)
        line_ksk_rrsig_new=$rand_substring${line_ksk_rrsig:5}
        sed -i "s@$line_ksk_rrsig@$line_ksk_rrsig_new@g" $output_dir/db.$zone.signed
        # Edit the ZSK signature
        line_zsk_rrsig=$(grep -A2 'RRSIG.*DNSKEY.*8.*3' $output_dir/db.$zone.signed | grep -A1 ".*${zsk_id}.*" | tail -1 | xargs)
        line_zsk_rrsig_new=$rand_substring${line_zsk_rrsig:5}
        sed -i "s@$line_zsk_rrsig@$line_zsk_rrsig_new@g" $output_dir/db.$zone.signed
    # Manipulate RRSIGs
    elif [[ $subdomain = "rrsig-exp-a" ]]; then
        # Find line number with a signature over A RRset
        sig_start_line=$(grep -n "RRSIG\sA 8 3" $output_dir/db.$zone.signed | cut -f1 -d:)
        sig_dates_line=$((sig_start_line+1))
        # Get current timestamps
        expiry_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | head -1)
        start_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | tail -1)
        # Compute the last year
        this_year=$(date +'%Y')
        last_year=$((this_year-1))
        # Compute new timestamps
        expiry_date_new="$(echo $last_year)$(echo $expiry_date | cut -c 5-)"
        start_date_new="$(echo $last_year)$(echo $start_date | cut -c 5-)"
        # Replace
        sed -i "${sig_dates_line}s/$expiry_date/$expiry_date_new/" $output_dir/db.$zone.signed
        sed -i "${sig_dates_line}s/$start_date/$start_date_new/" $output_dir/db.$zone.signed
    elif [[ $subdomain = "rrsig-not-yet-a" ]]; then
        # Find line number with a signature over A RRset
        sig_start_line=$(grep -n "RRSIG\sA 8 3" $output_dir/db.$zone.signed | cut -f1 -d:)
        sig_dates_line=$((sig_start_line+1))
        # Get current timestamps
        expiry_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | head -1)
        start_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | tail -1)
        # Compute the next year
        this_year=$(date +'%Y')
        next_year=$((this_year+1))
        in_two_years=$((this_year+2))
        # Compute new timestamps
        expiry_date_new="$(echo $in_two_years)$(echo $expiry_date | cut -c 5-)"
        start_date_new="$(echo $next_year)$(echo $start_date | cut -c 5-)"
        # Replace
        sed -i "${sig_dates_line}s/$expiry_date/$expiry_date_new/" $output_dir/db.$zone.signed
        sed -i "${sig_dates_line}s/$start_date/$start_date_new/" $output_dir/db.$zone.signed
    elif [[ $subdomain = "rrsig-not-yet-all" ]]; then
        # Find line number with a signature over A RRset
        sig_start_line=$(grep -n "RRSIG\sA 8 3" $output_dir/db.$zone.signed | cut -f1 -d:)
        sig_dates_line=$((sig_start_line+1))
        # Get current timestamps
        expiry_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | head -1)
        start_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | tail -1)
        # Compute the next year
        this_year=$(date +'%Y')
        next_year=$((this_year+1))
        in_two_years=$((this_year+2))
        # Compute new timestamps
        expiry_date_new="$(echo $in_two_years)$(echo $expiry_date | cut -c 5-)"
        start_date_new="$(echo $next_year)$(echo $start_date | cut -c 5-)"
        # Replace all the signatures
        sed -i "s/$expiry_date/$expiry_date_new/g" $output_dir/db.$zone.signed
        sed -i "s/$start_date/$start_date_new/g" $output_dir/db.$zone.signed
    elif [[ $subdomain = "rrsig-exp-before-all" ]]; then
        # Find line number with a signature over A RRset
        sig_start_line=$(grep -n "RRSIG\sA 8 3" $output_dir/db.$zone.signed | cut -f1 -d:)
        sig_dates_line=$((sig_start_line+1))
        # Get current timestamps
        expiry_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | head -1)
        start_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | tail -1)
        # Compute various years
        this_year=$(date +'%Y')
        before_2_years=$((this_year-2))
        after_2_years=$((this_year+2))
        # Compute new timestamps
        expiry_date_new="$(echo $before_2_years)$(echo $expiry_date | cut -c 5-)"
        start_date_new="$(echo $after_2_years)$(echo $start_date | cut -c 5-)"
        # Replace all the signatures
        sed -i "s/$expiry_date/$expiry_date_new/g" $output_dir/db.$zone.signed
        sed -i "s/$start_date/$start_date_new/g" $output_dir/db.$zone.signed
     elif [[ $subdomain = "rrsig-exp-before-a" ]]; then
        # Find line number with a signature over A RRset
        sig_start_line=$(grep -n "RRSIG\sA 8 3" $output_dir/db.$zone.signed | cut -f1 -d:)
        sig_dates_line=$((sig_start_line+1))
        # Get current timestamps
        expiry_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | head -1)
        start_date=$(awk "NR==$sig_dates_line" $output_dir/db.$zone.signed | grep -oP "\d{14}" | tail -1)
        # Compute various years
        this_year=$(date +'%Y')
        before_2_years=$((this_year-2))
        after_2_years=$((this_year+2))
        # Compute new timestamps
        expiry_date_new="$(echo $before_2_years)$(echo $expiry_date | cut -c 5-)"
        start_date_new="$(echo $after_2_years)$(echo $start_date | cut -c 5-)"
        # Replace
        sed -i "${sig_dates_line}s/$expiry_date/$expiry_date_new/" $output_dir/db.$zone.signed
        sed -i "${sig_dates_line}s/$start_date/$start_date_new/" $output_dir/db.$zone.signed
    elif [[ $subdomain = "rrsig-no-a" ]]; then
        line_rrsig_start_num=$(grep -n "RRSIG\sA\s8\s3" $output_dir/db.$zone.signed | cut -f1 -d:)
        line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
        line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
        sed -i "${line_rrsig_start_num},${line_rrsig_end_num}d" $output_dir/db.$zone.signed
    elif [[ $subdomain = "rrsig-no-all" ]]; then
        while grep "0.*RRSIG.*" $output_dir/db.$zone.signed > /dev/null; do
            # Delete signatures one by one
            line_rrsig_start_num=$(grep -n "0.*RRSIG.*" $output_dir/db.$zone.signed | head -1 | cut -f1 -d:)
            line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
            line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
            sed -i "${line_rrsig_start_num},${line_rrsig_end_num}d" $output_dir/db.$zone.signed
        done
    fi

    # Configure subdomains that manipulate NSEC3 resource records
    # Note that we need to query non-existing subdomains to trigger their modified behavior

    # Remove NSEC3 records
    if [[ $subdomain = "nsec3-missing" ]]; then
        while grep "IN.*NSEC3.*" $output_dir/db.$zone.signed > /dev/null; do
            # Delete NSEC3 records one by one
            line_start_num=$(grep -n "IN.*NSEC3.*" $output_dir/db.$zone.signed | head -1 | cut -f1 -d:)
            line_end=$(tail -n +$line_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
            line_end_num=$(grep -n "$line_end" $output_dir/db.$zone.signed | cut -f1 -d:)
            sed -i "${line_start_num},${line_end_num}d" $output_dir/db.$zone.signed
        done
    elif [[ $subdomain = "bad-nsec3param-salt" ]]; then
        # Find NSEC3PARAM line number
        nsec3param_line=$(grep -n "0\sNSEC3PARAM" $output_dir/db.$zone.signed | cut -f1 -d:)
        # Find the salt value
        nsec3param_salt=$(grep "0\sNSEC3PARAM" $output_dir/db.$zone.signed | awk '{print $NF}')
        # Update the salt value
        # Change hashed subdomains
        nsec3param_salt_new="573461ade8fcdabb"
        sed -i "${nsec3param_line}s/$nsec3param_salt/$nsec3param_salt_new/" $output_dir/db.$zone.signed
    elif [[ $subdomain = "bad-nsec3-rrsig" ]]; then
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-5)
        for rrsig in $(grep -n "RRSIG.*NSEC3\s8" $output_dir/db.$zone.signed | cut -f1 -d:); do
            line_rrsig_start_num=$rrsig
            line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep ")" | head -1 | xargs)
            line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
            line_rrsig_end_new=$rand_substring${line_rrsig_end:5}
            sed -i "s@$line_rrsig_end@$line_rrsig_end_new@g" $output_dir/db.$zone.signed
        done
    # Remove NSEC3 RRSIG records
    elif [[ $subdomain = "nsec3-rrsig-missing" ]]; then
        while grep "RRSIG.*NSEC3\s8" $output_dir/db.$zone.signed > /dev/null; do
            # Delete signatures one by one
            line_rrsig_start_num=$(grep -n "RRSIG.*NSEC3\s8" $output_dir/db.$zone.signed | head -1 | cut -f1 -d:)
            line_rrsig_end=$(tail -n +$line_rrsig_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
            line_rrsig_end_num=$(grep -n "$line_rrsig_end" $output_dir/db.$zone.signed | cut -f1 -d:)
            sed -i "${line_rrsig_start_num},${line_rrsig_end_num}d" $output_dir/db.$zone.signed
        done
    # Make wrong NSEC3 records
    elif [[ $subdomain = "bad-nsec3-hash" ]]; then
        # Locate NSEC3 records
        nsec3_domain_1=$(grep ".$zone.\s[0-9]\+\sIN\sNSEC3" $output_dir/db.$zone.signed | head -1 | awk '{print $1}')
        nsec3_domain_2=$(grep ".$zone.\s[0-9]\+\sIN\sNSEC3" $output_dir/db.$zone.signed | tail -1 | awk '{print $1}')
        # Change hashed subdomains
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-3 | tr '[:lower:]' '[:upper:]')
        new_nsec3_domain_1=$rand_substring${nsec3_domain_1:3}
        new_nsec3_domain_2=$rand_substring${nsec3_domain_2:3}
        # Replace in the zone file
        sed -i "s/$nsec3_domain_1/$new_nsec3_domain_1/g" $output_dir/db.$zone.signed
        sed -i "s/$nsec3_domain_2/$new_nsec3_domain_2/g" $output_dir/db.$zone.signed
    # Make wrong Next Hashed Owner Name field in NSEC3
    elif [[ $subdomain = "bad-nsec3-next" ]]; then
        # Find NSEC3 hashes
        nsec3_hash_1=$(grep ".$zone.\s[0-9]\+\sIN\sNSEC3" $output_dir/db.$zone.signed | head -1 | awk '{print $1}' | awk -F'.' '{print $1}')
        nsec3_hash_2=$(grep ".$zone.\s[0-9]\+\sIN\sNSEC3" $output_dir/db.$zone.signed | tail -1 | awk '{print $1}' | awk -F'.' '{print $1}')
        # Change next hashed owners
        rand_substring=$(head -c 1000 /dev/urandom | sha1sum | cut -b 1-3 | tr '[:lower:]' '[:upper:]')
        nsec3_hash_1_new=$rand_substring${nsec3_hash_1:3}
        nsec3_hash_2_new=$rand_substring${nsec3_hash_2:3}
        # Replace in the zone file
        sed -i "s/$nsec3_hash_1$/$nsec3_hash_1_new/g" $output_dir/db.$zone.signed
        sed -i "s/$nsec3_hash_2$/$nsec3_hash_2_new/g" $output_dir/db.$zone.signed
    # Remove NSEC3PARAM records
    elif [[ $subdomain = "nsec3param-missing" ]]; then
        sed -i '/NSEC3PARAM.*1/d' $output_dir/db.$zone.signed
    # Remove both NSEC3 and NSEC3PARAM records
    elif [[ $subdomain = "no-nsec3param-nsec3" ]]; then
        # Delete NSEC3 records one by one
        while grep "IN.*NSEC3.*" $output_dir/db.$zone.signed > /dev/null; do
            line_start_num=$(grep -n "IN.*NSEC3.*" $output_dir/db.$zone.signed | head -1 | cut -f1 -d:)
            line_end=$(tail -n +$line_start_num $output_dir/db.$zone.signed | grep -m 1 ")")
            line_end_num=$(grep -n "$line_end" $output_dir/db.$zone.signed | cut -f1 -d:)
            sed -i "${line_start_num},${line_end_num}d" $output_dir/db.$zone.signed
        done
        # Delete the NSEC3PARAM resource record
        sed -i '/NSEC3PARAM.*1/d' $output_dir/db.$zone.signed
    fi

    # Configure subdomains that manipulate DS resource records

    # Start by removing DS records with the SHA-1 digest algorithm, to keep
    # them from interfering with the effects of crafted DS records
    if [[ $subdomain != "unsigned" ]]; then
        sed -i '/8 1 /d' dsset-$zone.
    fi

    # Change the key tag to 0000 in DS record for "ds-bad-tag" subdomain
    if [[ $subdomain = "ds-bad-tag" ]]; then
        sed -i 's/DS.*8 2/DS 0000 8 2/g' dsset-$zone.
    # Set a different DNSKEY algorithm (8 -> 7)
    elif [[ $subdomain = "ds-bad-key-algo" ]]; then
        sed -i 's/8 2/7 2/g' dsset-$zone.
    # Set an unassigned DNSKEY algorithm (8 -> 100)
    elif [[ $subdomain = "ds-unassigned-key-algo" ]]; then
        sed -i 's/8 2/100 2/g' dsset-$zone.
    # Set an unassigned digest algorithm (2 -> 100)
    elif [[ $subdomain = "ds-unassigned-digest-algo" ]]; then
        sed -i 's/8 2/8 100/g' dsset-$zone.
    # Set a reserved DNSKEY algorithm (8 -> 200)
    elif [[ $subdomain = "ds-reserved-key-algo" ]]; then
        sed -i 's/8 2/200 2/g' dsset-$zone.
    # Change the digest value
    elif [[ $subdomain = "ds-bogus-digest-value" ]]; then
        sed -i "s/ 8 2.*/ 8 2 $(echo -n 'I am not a real DNSKEY digest' | sha256sum | cut -d' ' -f1)/" dsset-$zone.
    fi

    # Once all the domain names are configured, we need to correctly
    # serve them and prepare glues/DS records for the parent zone

    # Generate the text file with DS records to be uploaded at the parent
    if [[ $subdomain != "no-ds" && $subdomain != "unsigned" ]]; then
        cat dsset-$zone. >> dsset_for_parent.txt
    fi
    if [[ $subdomain != "unsigned" ]]; then
            mv dsset-$zone. $output_dir/dsset-$zone.
    fi

    # Generate the text file with glue records to be uploaded at the parent
    echo "$zone.      IN      NS      ns1.$zone." >> glues.txt
    echo "ns1.$zone.  IN      A      $server_ip" >> glues.txt

    # Fill in the local configuration file
    if [[ $subdomain = "allow-query-none" ]]; then
        echo "zone \"$zone\" {" >> $local_conf
        echo "        type master;" >> $local_conf
        echo "        file \"$zones_dir/$zone/db.$zone.signed\";" >> $local_conf
        echo "        allow-query { none; };" >> $local_conf
        echo "};" >> $local_conf
    elif [[ $subdomain = "allow-query-localhost" ]]; then
        echo "zone \"$zone\" {" >> $local_conf
        echo "        type master;" >> $local_conf
        echo "        file \"$zones_dir/$zone/db.$zone.signed\";" >> $local_conf
        echo "        allow-query { localhost; };" >> $local_conf
        echo "};" >> $local_conf
    elif [[ $subdomain = "unsigned" ]]; then
        echo "zone \"$zone\" {" >> $local_conf
        echo "        type master;" >> $local_conf
        echo "        file \"$zones_dir/$zone/db.$zone\";" >> $local_conf
        echo "};" >> $local_conf
    else
        echo "zone \"$zone\" {" >> $local_conf
        echo "        type master;" >> $local_conf
        echo "        file \"$zones_dir/$zone/db.$zone.signed\";" >> $local_conf
        echo "};" >> $local_conf
    fi

done
