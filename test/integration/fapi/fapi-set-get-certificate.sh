
set -e
source helpers.sh

start_up

CRYPTO_PROFILE="RSA"
setup_fapi $CRYPTO_PROFILE

function cleanup {
    tss2 delete --path=/
    shut_down
}

trap cleanup EXIT

KEY_PATH=HS/SRK/myRSACrypt
READ_CERTIFICATE_FILE=$TEMP_DIR/read_certificate.file
WRITE_CERTIFICATE_FILE=$TEMP_DIR/write_certificate.file

cat > $WRITE_CERTIFICATE_FILE <<EOF
    "-----BEGIN CERTIFICATE-----\n\
    MIIDBjCCAe4CCQDcvXBOEVM0UTANBgkqhkiG9w0BAQsFADBFMQswCQYDVQQGEwJE\n\
    RTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0\n\
    cyBQdHkgTHRkMB4XDTE5MDIyODEwNDkyM1oXDTM1MDgyNzEwNDkyM1owRTELMAkG\n\
    A1UEBhMCREUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0\n\
    IFdpZGdpdHMgUHR5IEx0ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB\n\
    AKBi+iKwkgM55iCMwXrLCJlu7TzlMu/LlkyGrm99ip2B5+/Cl6a62d8pKelg6zkH\n\
    jI7+AAPteJiW4O+2qVWF8hJ5BXTjGtYbM0iZ6enCb8eyC54C7xVMc21ZIv3ob4Et\n\
    50ZOuzY2pfpzE3vIaXt1CkHlfyI/hdK+mM/dVvuCz5p3AIlHrEWS3rSNgWbCsB2E\n\
    TM55qSGKaLmtTbUvEKRF0TJrFLntfXkv10QD5pgn52+QV9k59OogqZOsDvkXzKPX\n\
    rXF+XC0gLiGBEGAr1dv9F03xMOtO77bQTdGOeC61Tip6Nb0V3ebMckZXwdFi+Nhe\n\
    FRuU33CaObtV6u5PZvSue/MCAwEAATANBgkqhkiG9w0BAQsFAAOCAQEAcamUPe8I\n\
    nMOHcv9x5lVN1joihVRmKc0QqNLFc6XpJY8+U5rGkZvOcDe9Da8L97wDNXpKmU/q\n\
    pprj3rT8l3v0Z5xs8Vdr8lxS6T5NhqQV0UCsn1x14gZJcE48y9/LazYi6Zcar+BX\n\
    Am4vewAV3HmQ8X2EctsRhXe4wlAq4slIfEWaaofa8ai7BzO9KwpMLsGPWoNetkB9\n\
    19+SFt0lFFOj/6vDw5pCpSd1nQlo1ug69mJYSX/wcGkV4t4LfGhV8jRPDsGs6I5n\n\
    ETHSN5KV1XCPYJmRCjFY7sIt1x4zN7JJRO9DVw+YheIlduVfkBiF+GlQgLlFTjrJ\n\
    VrpSGMIFSu301A==\n\
    -----END CERTIFICATE-----\n"
EOF

EMPTY_FILE=$TEMP_DIR/empty.file
BIG_FILE=$TEMP_DIR/big_file.file

tss2 provision

tss2 createkey --path=$KEY_PATH --type="noDa, restricted, decrypt" \
    --authValue=""

echo "tss2 setcertificate with EMPTY_FILE" # Expected to succeed
tss2 setcertificate --path=$KEY_PATH --x509certData=$EMPTY_FILE

echo "tss2 setcertificate with BIG_FILE" # Expected to succeed
tss2 setcertificate --path=$KEY_PATH --x509certData=$BIG_FILE

tss2 setcertificate --path=$KEY_PATH --x509certData=$WRITE_CERTIFICATE_FILE

tss2 getcertificate --path=$KEY_PATH --x509certData=$READ_CERTIFICATE_FILE \
    --force

if [[ "$(< $READ_CERTIFICATE_FILE)" != "$(< $WRITE_CERTIFICATE_FILE)" ]]; then
  echo "Certificates not equal"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2 setcertificate --x509certData=$WRITE_CERTIFICATE_FILE
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

# Try with missing cert, should set cert to empty
tss2 setcertificate --path=$KEY_PATH
tss2 getcertificate --path=$KEY_PATH --x509certData=$READ_CERTIFICATE_FILE \
    --force

if [[ "$(< $READ_CERTIFICATE_FILE)" != "" ]]; then
  echo "Certificate was not deleted"
  exit 1
fi

expect <<EOF
# Try with missing path
spawn tss2 getcertificate --x509certData=$READ_CERTIFICATE_FILE --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

expect <<EOF
# Try with missing x509certData
spawn tss2 getcertificate --path=$KEY_PATH --force
set ret [wait]
if {[lindex \$ret 2] || [lindex \$ret 3] != 1} {
    Command has not failed as expected\n"
    exit 1
}
EOF

exit 0
