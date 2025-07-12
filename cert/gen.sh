#!/bin/bash

set -e

which openssl > /dev/null 2>&1 || { echo "openssl is not installed"; exit 1; }
which date > /dev/null 2>&1 || { echo "date is not installed"; exit 1; }

# Parameter check
# [[ ... ]]: This is a Bash-specific conditional construct that is more robust than [ ... ] for complex conditions, especially when using && or ||
# if [[ $# -ne 1 ]]; then
#     echo "Illegal number of parameters" >&2
#     exit 1
# fi

# if [[ $# -gt 1 && $# -lt 3 ]]; then
#     echo "Illegal number of parameters" >&2
#     exit 1
# fi

if [[ $# -lt 0 || $# -gt 2 ]]; then
    echo "Illegal number of parameters" >&2
    exit 1
fi

echo "Number of input parameter: $#"

PASSWORD="$1"
TO_DIR="$2"

check_dir_exist() {

    local DIR_PATH="$1"
    local CREATE_DIR="false"

    # To check if a folder (directory) exists in Bash, the test command or its shorthand [ or [[ can be used with the -d operator

    # Use: `test -d`
    # if test -d "$DIR_PATH"; then
    #     echo "Directory exists"
    # else
    #     echo "Directory does not exist"
    # fi

    # Use: [ -d ]
    # if [ -d "$DIR_PATH" ]; then
    #     echo "Directory exists"
    # else
    #     echo "Directory does not exist"
    # fi

    # Use `[[ -d ]]` for enhanced functionality
    if [[ -d "$DIR_PATH" ]]; then
        echo "$DIR_PATH, Directory exists"
    else
        echo "$DIR_PATH, Directory does not exist"
        CREATE_DIR="true"      
    fi

    
    if [[ "$CREATE_DIR" == "true" ]]; then
        mkdir -p "$DIR_PATH"
        echo "$DIR_PATH directory created"
    fi
}

if [ "$PASSWORD" = "" ]; then

    str=
    chars='abcdefghijklmnopqrstuvwxyz0123456789'
    n=20

    # Random string
    for ((i = 0; i < n; ++i)); do
        str+=${chars:RANDOM%${#chars}:1}
    done

    PASSWORD="$(echo -n $str | openssl dgst -sha256)"
    echo "message: $str"
    # echo "password: $PASSWORD"
fi

if [ "$TO_DIR" = "" ]; then
    TO_DIR="../assets/cert"
fi

# To access the value stored in a variable, prefix the variable name with a dollar sign ($)
echo "PASSWORD: $PASSWORD"
echo "TO_DIR: $TO_DIR"

check_dir_exist "$TO_DIR"

OUTPUT_DIR=out
OUTPUT_PATH="$OUTPUT_DIR/$(date "+%Y%m%d_%H%M%S")"

mkdir -p "$OUTPUT_PATH"

echo "OUTPUT_PATH: $OUTPUT_PATH"
echo -n "Output path is: $OUTPUT_PATH" > "$OUTPUT_PATH/test.txt"

# TIMESTAMP=$(date "+%Y%m%d_%H%M%S")
# %Y: Year (e.g., 2025)
# %m: Month (01-12)
# %d: Day of month (01-31)
# %H: Hour (00-23)
# %M: Minute (00-59)
# %S: Second (00-59)
# %F: Full date (YYYY-MM-DD) - equivalent to date +%Y-%m-%d
# %T: Time (HH:MM:SS) - equivalent to date +%H:%M:%S
# %s: Seconds since the Unix epoch (January 1, 1970, 00:00:00 UTC)

# Output files
# ca.key: Certificate Authority private key file (this shouldn't be shared in real-life)
# ca.crt: Certificate Authority trust certificate (this should be shared with users in real-life)
# server.key: Server private key, password protected (this shouldn't be shared)
# server.pem: Conversion of server.key into a format gRPC likes (this shouldn't be shared)
# server.csr: Server certificate signing request (this should be shared with the CA owner)
# server.crt: Server certificate signed by the CA (this would be sent back by the CA owner) - keep on server

# Summary 
# Private files: ca.key, server.key, server.pem, server.crt
# "Share" files: ca.crt (needed by the client), server.csr (needed by the CA)

echo "-----------------------------------------------------------------"
# Changes these CN's to match your hosts in your environment if needed.
SERVER_CN=localhost

# Step 1: Generate Certificate Authority + Trust Certificate (ca.crt)
openssl genrsa -passout pass:"$PASSWORD" -des3 -out "$OUTPUT_PATH/ca.key" 4096
openssl req -passin pass:"$PASSWORD" -new -x509 -sha256 -days 365 -key "$OUTPUT_PATH/ca.key" -out "$OUTPUT_PATH/ca.crt" -subj "/CN=${SERVER_CN}"

# Step 2: Generate the Server Private Key (server.key)
openssl genrsa -passout pass:"$PASSWORD" -des3 -out "$OUTPUT_PATH/server.key" 4096

# Step 3: Convert the server certificate to .pem format (server.pem) - usable by gRPC
openssl pkcs8 -topk8 -nocrypt -passin pass:"$PASSWORD" -in "$OUTPUT_PATH/server.key" -out "$OUTPUT_PATH/server.pem"

# Step 4: Get a certificate signing request from the CA (server.csr)
openssl req -passin pass:"$PASSWORD" -new -sha256 -key "$OUTPUT_PATH/server.key" -out "$OUTPUT_PATH/server.csr" -subj "/CN=${SERVER_CN}" -config ssl.cnf

# Step 5: Sign the certificate with the CA we created (it's called self signing) - server.crt
openssl x509 -req -passin pass:"$PASSWORD" -sha256 -days 365 -in "$OUTPUT_PATH/server.csr" -CA "$OUTPUT_PATH/ca.crt" -CAkey "$OUTPUT_PATH/ca.key" -set_serial 01 -out "$OUTPUT_PATH/server.crt" -extensions req_ext -extfile ssl.cnf

echo "-----------------------------------------------------------------"

cp -r -v "$OUTPUT_PATH/" "$TO_DIR"
echo "Copied files to $TO_DIR"

# rm -rf "$OUTPUT_PATH"

echo "-----------------------------------------------------------------"
echo " Process done"
echo "-----------------------------------------------------------------"