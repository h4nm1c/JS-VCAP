#! /usr/bin/env python3

# Standard libraries
import json, os, sys, ipaddress
from scapy.all import * 
from http.server import HTTPServer, SimpleHTTPRequestHandler
from datetime import datetime

# Custom libraries
from network_settings import * 

class HttpHandlerWithoutLogging(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        return

def http_serve():
  httpd = HTTPServer((VARIABLES["%{HOSTNAME}"], int(VARIABLES["%{PORT}"])), HttpHandlerWithoutLogging)
  httpd.serve_forever()

def update_data(string_data):
  for var in VARIABLES:
      string_data = string_data.replace(var, VARIABLES[var])
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
  return "[" + "".join(progress_bar) + "] " + get_percentage(part, whole)

def print_msg(msg):
  print("[{}]".format(datetime.now().strftime("%H:%M:%S")), msg)

def get_filesize(file):
  file_bytes = os.path.getsize(file)
  #try:
  return get_human_readable_bytesize(file_bytes)
  #except:
  #  raise ValueError(f"{file} is too large...")

def get_human_readable_bytesize(byte_amount):
  for unit in ["", "k", "m", "g", "t", "p"]:
    if abs(byte_amount) < 1024.0:
        return f"{byte_amount:3.1f}{unit}b"
    byte_amount /= 1024.0

def ip_in_range(ip_range, ip):
  if ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(ip_range):
    return True
  return False

def network_translation(ip):
  """
  Translates the corresponding hostname to a given ip.
  This is meant to make the network graph easier to interpret 
  if a host has multiple NICs where the IPS are joined together to a hostname instead
  """
  for alias in NETWORK_TRANSLATION:
    if isinstance(NETWORK_TRANSLATION[alias]['IPv4s'], list):
      if ip in NETWORK_TRANSLATION[alias]['IPv4s']:
        return alias
    elif isinstance(NETWORK_TRANSLATION[alias]['IPv4s'], str):
      if ip_in_range(NETWORK_TRANSLATION[alias]['IPv4s'], ip):
        return alias
  return ip

def is_service_port(port):
   if port in SERVICE_PORTS.keys():
      return True
   return False

def get_grouped_node_data(network_data):
  grouped_node_stage = {}
  for host in network_data["hosts"]:
      grouped_host_counter = 0
      if host in NETWORK_TRANSLATION and NETWORK_TRANSLATION[host]['show_grouped_nodes'] is True:
        for ip in network_data["hosts"][host]["ips"]:
          grouped_host_counter += 1
          grouped_host_name = f"{host}: {grouped_host_counter}"
          if grouped_host_name not in network_data["hosts"]:
            grouped_node_stage[grouped_host_name] = {}
            grouped_node_stage[grouped_host_name]["ips"] = [ip]
            grouped_node_stage[grouped_host_name]["is_server"] = False
            grouped_node_stage[grouped_host_name]["service_ports"] = VARIABLES['%{NO_VALUE}']
            grouped_node_stage[grouped_host_name]["services"] = VARIABLES['%{NO_VALUE}']
            grouped_node_stage[grouped_host_name]["total_packet_count"] = VARIABLES['%{NO_VALUE}']
            grouped_node_stage[grouped_host_name]["total_bytes"] = 0
            grouped_node_stage[grouped_host_name]["packets_sent"] = VARIABLES['%{NO_VALUE}']
            grouped_node_stage[grouped_host_name]["payload_bytes_sent"] = 0
            grouped_node_stage[grouped_host_name]["packets_received"] = VARIABLES['%{NO_VALUE}']
            grouped_node_stage[grouped_host_name]["payload_bytes_received"] = 0
          flow = {}
          flow["from"] = grouped_host_name
          flow["from_port"] = VARIABLES['%{NO_VALUE}']
          flow["to"] = host
          flow["to_port"] = VARIABLES['%{NO_VALUE}']
          flow["proto"] = VARIABLES['%{NO_VALUE}']
          network_data["communications"].append(flow)
  
  #Merge the grouped nodes to the list of hosts
  network_data["hosts"] = network_data["hosts"] | grouped_node_stage

  return network_data
    

def summarize_node_graph_data(network_data):
   network_data = get_grouped_node_data(network_data)
   
   node_graph_dict = {
                      "nodes":[],
                      "edges": network_data["communications"]
                     }
   
   for host in network_data["hosts"]:
      node = {}
      node["id"] = host
      node["ips"] = ",".join(network_data["hosts"][host]["ips"])
      node["total_packet_count"] = network_data["hosts"][host]["total_packet_count"]
      node["packets_sent"] = network_data["hosts"][host]["packets_sent"]
      node["packets_received"] = network_data["hosts"][host]["packets_received"]
      
      node["total_bytes"] = get_human_readable_bytesize(network_data["hosts"][host]["total_bytes"])
      node["payload_bytes_sent"] = get_human_readable_bytesize(network_data["hosts"][host]["payload_bytes_sent"])
      node["payload_bytes_received"] = get_human_readable_bytesize(network_data["hosts"][host]["payload_bytes_received"])

      if network_data["hosts"][host]["is_server"]:
         node["fill"] = { "src": update_data("http://%{HOSTNAME}:%{PORT}/%{SERVER_ICON}") }
         node["service_ports"] = ",".join( network_data["hosts"][host]["service_ports"])
         node["services"] = ",".join( network_data["hosts"][host]["services"])
      else:
         node["fill"] = { "src": update_data("http://%{HOSTNAME}:%{PORT}/%{CLIENT_ICON}") }
         node["service_ports"] = VARIABLES["%{NO_VALUE}"]
         node["services"] = VARIABLES["%{NO_VALUE}"] 
      node["height"] = int(VARIABLES["%{ICON_SIZE}"])
      node_graph_dict["nodes"].append(node)
      
   return node_graph_dict

def parse_pcap(capture):
  traffic = { 
            "hosts":{},
            "communications":[]
            }
  
  total_packets = len(capture)
  tenth = total_packets//10
  print_msg(f"Processing {total_packets} packets..")
  
  if total_packets >= 10:
    tenth_numbers = [index * tenth for index in range(1, 11)] 
    packet_increment = 1
  else:
    tenth = total_packets/10
    tenth_numbers = [index * 1 for index in range(1, 11)]
    packet_increment = tenth

  packet_count = 0
  progress_bar = list("----------")

  for packet in capture:
      
      packet_count += packet_increment
      if packet_count in tenth_numbers:
        progress_bar[tenth_numbers.index(packet_count)] = "="
        print_msg(updated_progress_bar(progress_bar, packet_count, total_packets))


      if IP in packet:        
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
        
        
        for ip_adr in [src, dst]:
          node = network_translation(ip_adr)
          
          if not node in traffic["hosts"]:
            traffic["hosts"][node] = {}
            traffic["hosts"][node]["ips"] = set()
            traffic["hosts"][node]["is_server"] = False
            traffic["hosts"][node]["service_ports"] = set()
            traffic["hosts"][node]["services"] = set()
            traffic["hosts"][node]["total_packet_count"] = 1
            traffic["hosts"][node]["total_bytes"] = packet_bytes
            if ip_adr == src:
              traffic["hosts"][node]["packets_sent"] = 1
              traffic["hosts"][node]["payload_bytes_sent"] = packet_bytes
              traffic["hosts"][node]["packets_received"] = 0
              traffic["hosts"][node]["payload_bytes_received"] = 0
            else:
              traffic["hosts"][node]["packets_sent"] = 0
              traffic["hosts"][node]["payload_bytes_sent"] = 0
              traffic["hosts"][node]["packets_received"] = 1
              traffic["hosts"][node]["payload_bytes_received"] = packet_bytes
          else:
            traffic["hosts"][node]["total_packet_count"] += 1
            traffic["hosts"][node]["total_bytes"] += packet_bytes

            if ip_adr == src:
              traffic["hosts"][node]["packets_sent"] += 1
              traffic["hosts"][node]["payload_bytes_sent"] += packet_bytes
            else:
              traffic["hosts"][node]["packets_received"] += 1
              traffic["hosts"][node]["payload_bytes_received"] += packet_bytes
          traffic["hosts"][node]["ips"].add(ip_adr)

          #Host unique adressing of ports
          #Since the src and dst are in a for-loop there needs to be a check if ip 
          #to avoid duplications 
          
          if ip_adr == src:
            if is_service_port(src_port):
              traffic["hosts"][node]["services"].add(SERVICE_PORTS[src_port])
              traffic["hosts"][node]["service_ports"].add(src_port)
              traffic["hosts"][node]["is_server"] = True
          else:
            if is_service_port(dst_port):
              traffic["hosts"][node]["services"].add(SERVICE_PORTS[dst_port])
              traffic["hosts"][node]["service_ports"].add(dst_port)
              traffic["hosts"][node]["is_server"] = True

        ### EDGE DEFINITION
        flow = {}
        flow["from"] = network_translation(src)
        flow["from_port"] = src_port
        flow["to"] = network_translation(dst)
        flow["to_port"] = dst_port
        flow["proto"] = proto

        if flow not in traffic["communications"]:
            traffic["communications"].append(flow)
  
  print_msg("Finished parsing packets")
  return traffic

def load_pcap(pcap_file):
  pcap_file_size = get_filesize(pcap_file)
  print_msg(f"Loading {pcap_file} ({pcap_file_size})..")
  try:
    capture = rdpcap(pcap_file)
    print_msg(f"Successfully loaded {pcap_file}")
    return capture
  except Exception as e:
    print_msg(f"Unable to load {pcap_file}. {e}. Exiting...")
    exit(1)


if __name__ == "__main__":
  pcap_file = sys.argv[1]
  ### Read pcap file
  capture = load_pcap(pcap_file)
  network_data = parse_pcap(capture)

  ### Node Graph Network Chart
  node_graph_data = summarize_node_graph_data(network_data)
  node_graph_data_json = json.dumps(node_graph_data, indent=2)
  node_network_graph_template = read_file(VARIABLES["%{NETWORK_GRAPH_TEMPLATE}"])
  data_file = "data/"+pcap_file.replace(".","") + ".json"
  VARIABLES['%{NETWORK_GRAPH_DATA_FILE}'] = data_file
  create_file(data_file, node_graph_data_json)

  ### Node Web Page
  updated_webb_page = update_data(node_network_graph_template)
  create_file("index.html", updated_webb_page)
  print_msg(update_data("Hosting on ==> http://%{HOSTNAME}:%{PORT}"))

  ### HTTP Serve
  http_serve()
