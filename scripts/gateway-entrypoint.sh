#!/bin/sh
# Prepares the kernel packet filter, then starts the gateway.
#
#   table inet payrelay
#     set banned   { type ipv4_addr; flags timeout; }     <- the gateway adds attackers here
#     chain input  { ip saddr @banned tcp dport 9100 drop }
#
# Needs CAP_NET_ADMIN. Without it the gateway still bans in-process and says so in its log.
set -u
if nft -f - <<EOF 2>/dev/null
table inet payrelay {
  set banned {
    type ipv4_addr
    flags timeout
  }
  chain input {
    type filter hook input priority 0; policy accept;
    ip saddr @banned tcp dport ${GW_PORT:-9100} counter drop
  }
}
EOF
then
  echo "nftables: table inet payrelay ready"
else
  echo "nftables: unavailable (no CAP_NET_ADMIN?) - in-process bans only"
fi
exec pg-gateway
