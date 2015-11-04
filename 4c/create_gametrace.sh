../text2pcap -T 12345,55555 4c_verbinungsaufbau_tcp.hex 4c_aufbau.pcap
../text2pcap -u 23456,65432 4c_spieleverbindung_udp.hex 4c_zuege.pcap
../mergecap -a -w 4c_conversation.pcap 4c_aufbau.pcap 4c_zuege.pcap 
