import json, os
from scapy.all import * 
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

pcap_file = r"test.pcap"

variables = {
            "%{HOSTNAME}": "127.0.0.1",
            "%{PORT}": "5678",
            "%{NETWORK_GRAPH_DATA_FILE}": "data/"+pcap_file.replace(".","") + ".json",
            "%{NETWORK_GRAPH_TEMPLATE}" : "templates/node_network_graph.html",
            "%{CHART_TITLE}": pcap_file,
            "%{SERVER_ICON}": "img/generic_server.png",
            "%{CLIENT_ICON}": "img/generic_client.png",
            "%{ICON_SIZE}": "40",
            "%{NO_VALUE}": "N/A"}

service_ports = {"20":"FTP",
                 "21":"FTP",
                 "23":"TELNET",
                 "25":"SMTP",
                 "53":"DNS",
                 "80":"HTTP",
                 "123":"NTP",
                 "389":"LDAP",
                 "443":"HTTPS",
                 "587":"IMAP",
                 "636":"LDAPS"}

class HttpHandlerWithoutLogging(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

def http_serve():
  httpd = HTTPServer((variables["%{HOSTNAME}"], int(variables["%{PORT}"])), HttpHandlerWithoutLogging)
  httpd.serve_forever()

def update_data(string_data):
  for var in variables:
      string_data = string_data.replace(var, variables[var])
    
  return string_data

def create_file(filename, data):
  with open(filename, "wt") as file:
    file.write(data)
    file.flush()
    file.close()

def read_file(filename):
  with open(filename, "rt") as file:
    content = file.read()
    file.close()
  return content

def get_percentage(part, whole):
  return str(round(100 * float(part)/float(whole),1))+"%"

def updated_progress_bar(progress_bar, part, whole):
  return "".join(progress_bar) + " " + get_percentage(part, whole)

def print_msg(msg):
  print("[{}]".format(datetime.now().strftime("%H:%M:%S")), msg)

def get_filesize(file, suffix="b"):
  file_bytes = os.path.getsize(file)
  for unit in ["", "k", "m", "g", "t", "p"]:
    if abs(file_bytes) < 1024.0:
        return f"{file_bytes:3.1f}{unit}{suffix}"
    file_bytes /= 1024.0
  raise FileExistsError(f"{file} is too large...")

def is_service_port(port):
   if port in service_ports.keys():
      return True
   return False

def summarize_node_graph_data(network_data):
   node_graph_dict = {
                      "nodes":[],
                      "edges": network_data["communications"]
                     }
   
   for ip in network_data["hosts"]:
      node = {}
      node["id"] = ip
      node["total_packet_count"] = network_data["hosts"][ip]["total_packet_count"]
      node["packets_sent"] = network_data["hosts"][ip]["packets_sent"]
      node["packets_received"] = network_data["hosts"][ip]["packets_received"]
      node["total_bytes"] = network_data["hosts"][ip]["total_bytes"]  
      node["payload_bytes_sent"] = network_data["hosts"][ip]["payload_bytes_sent"]
      node["payload_bytes_received"] = network_data["hosts"][ip]["payload_bytes_received"]

      if network_data["hosts"][ip]["is_server"]:
         node["fill"] = { "src": update_data("http://%{HOSTNAME}:%{PORT}/%{SERVER_ICON}") }
         node["service_ports"] = ",".join( network_data["hosts"][ip]["service_ports"])
         node["services"] = ",".join( network_data["hosts"][ip]["services"])
      else:
         node["fill"] = { "src": update_data("http://%{HOSTNAME}:%{PORT}/%{CLIENT_ICON}") }
         node["service_ports"] = variables["%{NO_VALUE}"]
         node["services"] = variables["%{NO_VALUE}"] 
      node["height"] = int(variables["%{ICON_SIZE}"])
      node_graph_dict["nodes"].append(node)
      
   return node_graph_dict

def load_pcap(pcap_file):
  pcap_file_size = get_filesize(pcap_file)
  print_msg(f"Loading {pcap_file} ({pcap_file_size})..")
  try:
    capture =  rdpcap(pcap_file)
    print_msg(f"Successfully loaded {pcap_file}")
    return capture
  except Exception as e:
    print_msg(f"Unable to load {pcap_file}. {e}. Exiting...")
    exit(1)

def parse_pcap(capture):
  traffic = { 
            "hosts":{},
            "communications":[]
            }

  
  total_packets = len(capture)
  print_msg(f"Processing {total_packets} packets..")

  div_packet_count = round(total_packets/10,0)
  packet_count = 0
  progress_count = 0
  progress_bar = list("[----------]")

  print_msg(updated_progress_bar(progress_bar, packet_count, total_packets))
  for packet in capture:
      packet_count += 1

      if (packet_count % div_packet_count == 0) and progress_count < 10:
        progress_count += 1
        progress_bar[progress_count] = "="
        print_msg(updated_progress_bar(progress_bar, packet_count, total_packets))

      if IP in packet:

        ### DEFINING COMMUNICATION VARIABLES
        src = packet[IP].src
        dst = packet[IP].dst
        packet_bytes = len(packet)
        if TCP in packet:
          src_port = str(packet[TCP].sport)
          dst_port = str(packet[TCP].dport)

          proto = "TCP"
        elif UDP in packet:
          src_port = str(packet[UDP].sport)
          dst_port = str(packet[UDP].dport)

          proto = "UDP"
        else:
          continue

        if not src in traffic["hosts"]:
          traffic["hosts"][src] = {}
          traffic["hosts"][src]["is_server"] = False
          traffic["hosts"][src]["service_ports"] = set()
          traffic["hosts"][src]["services"] = set()
          traffic["hosts"][src]["total_packet_count"] = 1
          traffic["hosts"][src]["packets_sent"] = 1
          traffic["hosts"][src]["packets_received"] = 0
          traffic["hosts"][src]["payload_bytes_sent"] = packet_bytes
          traffic["hosts"][src]["total_bytes"] = packet_bytes
          traffic["hosts"][src]["payload_bytes_received"] = 0
        else:
          traffic["hosts"][src]["total_packet_count"] += 1
          traffic["hosts"][src]["packets_sent"] += 1
          traffic["hosts"][src]["payload_bytes_sent"] += packet_bytes
          traffic["hosts"][src]["total_bytes"] += packet_bytes


        if not dst in traffic["hosts"]:
          traffic["hosts"][dst] = {}
          traffic["hosts"][dst]["is_server"] = False
          traffic["hosts"][dst]["service_ports"] = set()
          traffic["hosts"][dst]["services"] = set()
          traffic["hosts"][dst]["total_packet_count"] = 1
          traffic["hosts"][dst]["packets_received"] = 1
          traffic["hosts"][dst]["packets_sent"] = 0
          traffic["hosts"][dst]["payload_bytes_sent"] = 0
          traffic["hosts"][dst]["payload_bytes_received"] = packet_bytes
          traffic["hosts"][dst]["total_bytes"] = packet_bytes
        else:
          traffic["hosts"][dst]["total_packet_count"] += 1
          traffic["hosts"][dst]["packets_received"] += 1
          traffic["hosts"][dst]["payload_bytes_received"] += packet_bytes
          traffic["hosts"][dst]["total_bytes"] += packet_bytes
        
        if is_service_port(src_port):
          traffic["hosts"][src]["services"].add(service_ports[src_port])
          traffic["hosts"][src]["service_ports"].add(src_port)
          traffic["hosts"][src]["is_server"] = True
        
        if is_service_port(dst_port):
          traffic["hosts"][dst]["services"].add(service_ports[dst_port])
          traffic["hosts"][dst]["service_ports"].add(dst_port)
          traffic["hosts"][dst]["is_server"] = True



        ### EDGE DEFINITION
        flow = {}
        flow["from"] = src
        flow["from_port"] = src_port
        flow["to"] = dst
        flow["to_port"] = dst_port
        flow["proto"] = proto

        if flow not in traffic["communications"]:
            traffic["communications"].append(flow)
  
  print_msg("Finished parsing packets")
  return traffic


if __name__ == "__main__":
  ### Read pcap file
  capture = load_pcap(pcap_file)
  network_data = parse_pcap(capture)

  ### Node Graph Network Chart
  node_graph_data = summarize_node_graph_data(network_data)
  node_graph_data_json = json.dumps(node_graph_data, indent=2)
  node_network_graph_template = read_file(variables["%{NETWORK_GRAPH_TEMPLATE}"])
  create_file(variables["%{NETWORK_GRAPH_DATA_FILE}"], node_graph_data_json)

  ### Node Web Page
  updated_webb_page = update_data(node_network_graph_template)
  create_file("index.html", updated_webb_page)
  print_msg(update_data("Hosting on ==> http://%{HOSTNAME}:%{PORT}"))

  ### HTTP Serve
  http_serve()
