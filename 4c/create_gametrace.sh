../text2pcap -T 12345,55555 -4 10.1.1.1,10.2.2.2 4c_verbinungsaufbau_tcp.hex 4c_aufbau.pcap
../text2pcap -u 23456,44444 -4 10.1.1.1,10.3.3.3 4c_spieleverbindung_udp.hex 4c_zuege.pcap
../mergecap -a -w 4c_conversation.pcap 4c_aufbau.pcap 4c_zuege.pcap 
