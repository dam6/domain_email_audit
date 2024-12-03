#!/bin/bash

# Function to display correct usage
usage() {
    echo "Usage: $0 -d <domain1,domain2,...> [-f <file>] [-w <selectors_file>] [--report] [--dns <dns_server>]"
    exit 1
}

# Initialize variables
selectors=()
report=0
domains=()
dns_server="8.8.8.8" # Default DNS server

# Parse command-line options
while getopts ":d:f:w:-:" opt; do
    case $opt in
        d) IFS=',' read -r -a domains <<< "$OPTARG" ;;
        f)
            [[ -f "$OPTARG" ]] && mapfile -t domains < "$OPTARG" || { echo "File $OPTARG does not exist."; exit 1; }
            ;;
        w)
            [[ -f "$OPTARG" ]] && mapfile -t selectors < "$OPTARG" || { echo "File $OPTARG does not exist."; exit 1; }
            ;;
        -)
            case "$OPTARG" in
                report) report=1 ;;
                dns) dns_server="${!OPTIND}"; OPTIND=$((OPTIND + 1)) ;;
                *) usage ;;
            esac
            ;;
        *) usage ;;
    esac
done

# Ensure at least one domain is provided
[[ ${#domains[@]} -eq 0 ]] && usage

# Function to perform dig query
dig_query() {
    local query="$1"
    dig @"$dns_server" +short TXT "$query"
}

# Check SPF record
check_spf() {
    local domain="$1"
    local spf_record
    spf_record=$(dig_query "$domain" | grep -i 'v=spf1')

    [[ -z "$spf_record" ]] && echo "fail record missing" && return
    [[ ${#spf_record} -gt 512 ]] && echo "warn exceeds 512 bytes" && return
    [[ $(echo "$spf_record" | grep -oE '(include:|a|mx|ptr|exists)' | wc -l) -gt 10 ]] && echo "warn exceeds 10 DNS lookups" && return
    [[ ! "$spf_record" =~ "all" ]] && echo "warn missing 'all' mechanism" && return

    echo "ok"
}

# Check DMARC record
check_dmarc() {
    local domain="$1"
    local dmarc_record
    dmarc_record=$(dig_query "_dmarc.$domain" | tr -d '"')

    [[ -z "$dmarc_record" ]] && echo "fail no DMARC record" && return
    [[ ! "$dmarc_record" =~ "v=DMARC1" ]] && echo "fail missing v=DMARC1" && return

    local policy
    policy=$(echo "$dmarc_record" | grep -o 'p=[^;]*' | head -n 1 | cut -d'=' -f2)
    [[ -z "$policy" ]] && echo "fail missing policy" && return
    [[ "$policy" =~ ^none$ ]] && echo "warn none" && return
    [[ ! "$policy" =~ ^(none|quarantine|reject)$ ]] && echo "fail invalid policy" && return

    echo "ok $policy"
}

# Check DKIM records
check_dkim() {
    local domain="$1"
    local found_selectors=()
    local tmpfile
    tmpfile=$(mktemp)

    for selector in "${selectors[@]}"; do
        (
            dkim_record=$(dig_query "${selector}._domainkey.${domain}")
            # If returns a CNAME
            if [[ "$dkim_record" == *"." ]]; then
                cname_target=$(echo "$dkim_record" | tr -d '"')
                dkim_record=$(dig_query "$cname_target")
            fi
            # check if there is any public key
            if [[ "$dkim_record" == *"p="* ]]; then
                echo "$selector"
            fi
        ) >> "$tmpfile" &
    done
    wait

    while IFS= read -r selector; do
        found_selectors+=("$selector")
    done < "$tmpfile"
    rm "$tmpfile"

    if [[ ${#found_selectors[@]} -eq 0 ]]; then
        echo "fail -"
    else
        echo "ok ${found_selectors[*]}"
    fi
}

# Generate report file if requested
if [[ "$report" -eq 1 ]]; then
    timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
    report_file="${0##*/}.$timestamp.csv"
    echo "DOMAIN;DMARC;SPF;DKIM;DMARC_POLICY;SPF_FAILURE_WARN_REASON;DKIM_SELECTORS" > "$report_file"
fi

# Print table header
printf "%-25s %-8s %-8s %-8s %-16s %-30s %-40s\n" "DOMAIN" "DMARC" "SPF" "DKIM" "DMARC POLICY" "SPF FAILURE/WARN REASON" "DKIM SELECTORS"

# Process each domain
for domain in "${domains[@]}"; do
    dmarc_output=$(check_dmarc "$domain")
    dmarc_result=$(echo "$dmarc_output" | awk '{print $1}')
    dmarc_policy=$(echo "$dmarc_output" | cut -d' ' -f2-)

    spf_output=$(check_spf "$domain")
    spf_result=$(echo "$spf_output" | awk '{print $1}')
    spf_reason=$(echo "$spf_output" | cut -d' ' -f2-)

    # If SPF is ok, set '-' for the failure reason
    [[ "$spf_result" == "ok" ]] && spf_reason="-"

    dkim_output=$(check_dkim "$domain")
    dkim_result=$(echo "$dkim_output" | awk '{print $1}')
    dkim_selectors=$(echo "$dkim_output" | cut -d' ' -f2-)

    # Print result for each domain
    printf "%-25s %-8s %-8s %-8s %-16s %-30s %-40s\n" \
        "$domain" "$dmarc_result" "$spf_result" "$dkim_result" "$dmarc_policy" "$spf_reason" "$dkim_selectors"

    # Append to report if needed
    if [[ "$report" -eq 1 ]]; then
        echo "$domain;$dmarc_result;$spf_result;$dkim_result;$dmarc_policy;$spf_reason;$dkim_selectors" >> "$report_file"
    fi
done

# Report file message
if [[ "$report" -eq 1 ]]; then
    echo
    echo "Report successfully generated on file: $report_file"
fi
