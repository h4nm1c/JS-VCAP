
LOOKUP_IP_GEOLOCATION = True

#Define subnets or IP ranges
NETWORK_TRANSLATION = {
    'list_of_ips_grouping': {
        'IPv4s': ['10.50.10.11',
                  '10.202.5.250'],
        'image': '',
        'show_grouped_nodes': False
    },
    'subnet_grouping': {
        'IPv4s': '10.0.0.0/8',
        'image': '',
        'show_grouped_nodes': True
    }
}


VARIABLES = {
            "%{CHART_TITLE}":"Network Graph",
            "%{HOSTNAME}": "127.0.0.1",
            "%{PORT}": "5678",
            "%{NETWORK_GRAPH_TEMPLATE}" : "templates/node_network_graph.html",
            "%{SERVER_ICON}": "img/generic_server.png",
            "%{CLIENT_ICON}": "img/generic_client.png",
            "%{ICON_SIZE}": "40",
            "%{NO_VALUE}": "N/A"}

SERVICE_PORTS = {
                 "17": "QOTD",
                 "20": "FTP",
                 "21": "FTP",
                 "22": "SSH",
                 "23": "TELNET",
                 "25": "SMTP",
                 "53": "DNS",
                 "70": "GOPHER",
                 "80": "HTTP",
                 "88": "KERBEROS",
                 "107": "RTELNET",
                 "110": "POP#3",
                 "115": "SFTP",
                 "118": "SQL",
                 "123": "NTP",
                 "143": "IMAP",
                 "194": "IRC",
                 "199": "SNMP",
                 "264": "BGMP",
                 "389": "LDAP",
                 "443": "HTTPS",
                 "514": "SYSLOG",
                 "554": "RTSP",
                 "587": "IMAP",
                 "636": "LDAPS",
                 "853": "DOT",
                 "3306": "MYSQL",
                 "3389": "RDP"
                 }
