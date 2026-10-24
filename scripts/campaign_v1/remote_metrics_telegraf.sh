#!/bin/bash
# ARCHIVIRT — remote metrics via Telegraf/InfluxDB (PROPOSAL C1.3, option T1-b) - NOT IMPLEMENTED.
# Querying InfluxDB requires the InfluxDB token, i.e. Vault material. C1.3 is forbidden to touch
# the Vault, so this adapter deliberately reports every metric as ERR (-> NOT_EVALUABLE -> INVALID,
# never a silent VALID) and exits 3. To be designed only after decision T1 + an explicit
# authorisation covering in-memory Vault use.
for k in monitor_mem_available_mib target03_mem_available_mib ens6_rx_dropped ens7_rx_dropped nfq_queue_dropped nfq_user_dropped; do echo "$k=ERR"; done
echo "TELEGRAF_ADAPTER_NOT_CONFIGURED (requires the Vault token; decision T1)" >&2
exit 3
