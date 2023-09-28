client
dev tun
proto tcp
remote ${vpn_endpoint} 443
verify-x509-name ${server_name} name
remote-random-hostname
resolv-retry infinite
nobind
remote-cert-tls server
cipher AES-256-GCM
verb 3
reneg-sec 0

<ca>
${ca_body}
</ca>
<cert>
${user_cert_body}
</cert>
<key>
${user_key_body}
</key>
