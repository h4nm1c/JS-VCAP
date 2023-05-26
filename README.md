# JS-VCAP

Simple python script parsing packet capture files with [scapy](https://scapy.net/) and visualizing IP-communication between nodes using the [anychart .js libraries](https://www.anychart.com/). 
After the parsing is done and the necessary HTML and JSON files are created, a [simplehttpserver](https://docs.python.org/2/library/simplehttpserver.html) is initiated to serve the visualization.  

since pcap files tend to become very large, an appropriate output is provided where a timestamp is added to each step of processing the pcap. 

![output of processing and parsing pcap file](https://github.com/H4NM/JS-VCAP/blob/main/img/show_case_img_1.png?raw=true)

A simple end result.
![Show case of network graph generated from a pcap file](https://github.com/H4NM/JS-VCAP/blob/main/img/show_case_img_2.png?raw=true)
