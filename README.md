# kdp-exporter
Kaspersky DDoS Prevention Suite metrics exporter for Prometheus

Supported metrics:
|Name|Description|Labels|
|----|-----------|------|
|kdp_api_version | Version of KDP API|version, mode: client, admin|
|kdp_client_resource | Client resources|name, group, internal_ip, external_ip, redirection_method|
|kdp_http_hits_rate_direction | HTTP. Number of requests. Direction.|resource, type: clean/dirty|
|kdp_http_hits_rate | HTTP. Number of requests. hits/sec.|resource, type: clean/dirty|
|kdp_http_hits_rate_mult1 | HTTP. Number of requests. Mult1.|resource, type: clean/dirty|
|kdp_http_hits_rate_mult2 | HTTP. Number of requests. Mult2.|resource, type: clean/dirty|
|kdp_http_hits_rate_threshold | HTTP. Number of requests. Threshold.|resource, type: clean/dirty|
|kdp_incoming_icmp_traffic_pps_direction | Incoming ICMP traffic speed in packets per second. Direction.|resource, type: clean/dirty|
|kdp_incoming_icmp_traffic_pps | Incoming ICMP traffic speed in packets per second. pps.|resource, type: clean/dirty|
|kdp_incoming_icmp_traffic_pps_mult1 | Incoming ICMP traffic speed in packets per second. Mult1.|resource, type: clean/dirty|
|kdp_incoming_icmp_traffic_pps_mult2 | Incoming ICMP traffic speed in packets per second. Mult2.|resource, type: clean/dirty|
|kdp_incoming_icmp_traffic_pps_threshold | Incoming ICMP traffic speed in packets per second. Threshold.|resource, type: clean/dirty|
|kdp_incoming_tcp_traffic_pps_direction | Incoming TCP traffic speed in packets per second. Direction.|resource, type: clean/dirty|
|kdp_incoming_tcp_traffic_pps | Incoming TCP traffic speed in packets per second. pps.|resource, type: clean/dirty|
|kdp_incoming_tcp_traffic_pps_mult1 | Incoming TCP traffic speed in packets per second. Mult1.|resource, type: clean/dirty|
|kdp_incoming_tcp_traffic_pps_mult2 | Incoming TCP traffic speed in packets per second. Mult2.|resource, type: clean/dirty|
|kdp_incoming_tcp_traffic_pps_threshold | Incoming TCP traffic speed in packets per second. Threshold.|resource, type: clean/dirty|
|kdp_incoming_traffic_bps_direction | Incoming traffic speed in bits per second. Direction.|resource, type: clean/dirty|
|kdp_incoming_traffic_bps | Incoming traffic speed in bits per second. bps.|resource, type: clean/dirty|
|kdp_incoming_traffic_bps_mult1 | Incoming traffic speed in bits per second. Mult1.|resource, type: clean/dirty|
|kdp_incoming_traffic_bps_mult2 | Incoming traffic speed in bits per second. Mult2.|resource, type: clean/dirty|
|kdp_incoming_traffic_bps_threshold | Incoming traffic speed in bits per second. Threshold.|resource, type: clean/dirty|
|kdp_incoming_traffic_pps_direction | Incoming traffic speed in packets per second. Direction.|resource, type: clean/dirty|
|kdp_incoming_traffic_pps | Incoming traffic speed in packets per second. pps.|resource, type: clean/dirty|
|kdp_incoming_traffic_pps_mult1 | Incoming traffic speed in packets per second. Mult1.|resource, type: clean/dirty|
|kdp_incoming_traffic_pps_mult2 | Incoming traffic speed in packets per second. Mult2.|resource, type: clean/dirty|
|kdp_incoming_traffic_pps_threshold | Incoming traffic speed in packets per second. Threshold.|resource, type: clean/dirty|
|kdp_ip_rate_direction | Number of IP addresses. Direction.|resource, type: clean/dirty|
|kdp_ip_rate_mult1 | Number of IP addresses. Mult1.|resource, type: clean/dirty|
|kdp_ip_rate_mult2 | Number of IP addresses. Mult2.|resource, type: clean/dirty|
|kdp_ip_rate | Number of IP addresses. IPs/min.|resource, type: clean/dirty|
|kdp_ip_rate_threshold | Number of IP addresses. Threshold.|resource, type: clean/dirty|
|kdp_outgoing_traffic_bps_direction | Outgoing traffic speed in bits per second. Direction.|resource, type: clean/dirty|
|kdp_outgoing_traffic_bps_mult1 | Outgoing traffic speed in bits per second. Mult1.|resource, type: clean/dirty|
|kdp_outgoing_traffic_bps_mult2 | Outgoing traffic speed in bits per second. Mult2.|resource, type: clean/dirty|
|kdp_outgoing_traffic_bps | Outgoing traffic speed in bits per second. bps.|resource, type: clean/dirty|
|kdp_outgoing_traffic_bps_threshold | Outgoing traffic speed in bits per second. Threshold.|resource, type: clean/dirty|
|kdp_outgoing_traffic_pps_direction | Outgoing traffic speed in packets per second. Direction.|resource, type: clean/dirty|
|kdp_outgoing_traffic_pps_mult1 | Outgoing traffic speed in packets per second. Mult1.|resource, type: clean/dirty|
|kdp_outgoing_traffic_pps_mult2 | Outgoing traffic speed in packets per second. Mult2.|resource, type: clean/dirty|
|kdp_outgoing_traffic_pps | Outgoing traffic speed in packets per second. pps.|resource, type: clean/dirty|
|kdp_outgoing_traffic_pps_threshold | Outgoing traffic speed in packets per second. Threshold.|resource, type: clean/dirty|
|kdp_resource_anomaly_max_percent | Anomaly. Percent of deviation in measured parameter.|name, parameter, state, color: 0, 2|
|kdp_resource_anomaly_max_value | Anomaly. Value of measured parameter in a max point.|name, parameter, state, color: 0, 2|
|kdp_resource_attack_http_rate | Anomaly. HTTP requests rate during anomaly. hits/s.|name, attack_id, attack_type|
|kdp_resource_attack_incoming_traffic_bps | Anomaly. Incoming traffic during anomaly. bps.|name, attack_id, attack_type|
|kdp_resource_attack_incoming_traffic_pps | Anomaly. Incoming traffic during anomaly. pps.|name, attack_id, attack_type|
|kdp_resource_geo_ratio_prc | Requests by Country. Ratio.|name, country|
|kdp_resource_new_ip_blocks_count | Count of new IP blocked. Count.|name|
|kdp_syn_packets_direction | Number of incoming TCP packets with SYN flag. Direction.|resource, type: clean/dirty|
|kdp_syn_packets_mult1 | Number of incoming TCP packets with SYN flag. Mult1.|resource, type: clean/dirty|
|kdp_syn_packets_mult2 | Number of incoming TCP packets with SYN flag. Mult2.|resource, type: clean/dirty|
|kdp_syn_packets | Number of incoming TCP packets with SYN flag. pps.|resource, type: clean/dirty|
|kdp_syn_packets_threshold | Number of incoming TCP packets with SYN flag. Threshold.|resource, type: clean/dirty|
|kdp_syn_rating_direction | SYN rating. Direction.|resource, type: clean/dirty|
|kdp_syn_rating_mult1 | SYN rating. Mult1.|resource, type: clean/dirty|
|kdp_syn_rating_mult2 | SYN rating. Mult2.|resource, type: clean/dirty|
|kdp_syn_rating | SYN rating. times.|resource, type: clean/dirty|
|kdp_syn_rating_threshold | SYN rating. Threshold.|resource, type: clean/dirty|
