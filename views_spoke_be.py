from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
import os
import json
import yaml
import psutil
from netaddr import IPAddress
import netifaces as ni
from pyroute2 import IPRoute
import subprocess
import ipaddress
ipr = IPRoute()
import threading
import dns.resolver
import dns.exception
import re
import socket

file_path = "/etc/reach/reachlink_info.json"

routes_protocol_map = {
    -1: '',
    2: 'kernel',
    3: 'boot/static',
    4: 'static',    
    16: 'dhcp',    
    0: 'Unspecified (default)',
}


@csrf_exempt
def addroute(request: HttpRequest):
    response = [{"message":"Successfully added"}]
    try:         
        data = json.loads(request.body)       
        subnet_info = data["subnet_info"]
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            data1 = yaml.safe_load(f)
            f.close()
        dat=[]
        for rr in data1["network"]["ethernets"]["eth1"]:
            if rr == "routes":
                dat = data1["network"]["ethernets"]["eth1"]["routes"]
        for r in subnet_info:
           try:
              print(r["subnet"])
              print(r["gateway"])
              if (ipaddress.ip_network(r["subnet"], strict=False) and ipaddress.ip_address(r["gateway"])):
                  dat.append({"to": r["subnet"],
                        "via": r["gateway"]}
                        )
                  print(dat)
           except ValueError:
             response = [{"message":"Either subnet or Gateway is not valid IP"}]        
        data1["network"]["ethernets"]["eth1"]["routes"] = dat
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(data1, f, default_flow_style=False)
            f.close()
        os.system("sudo netplan apply")  
    except Exception as e:
        print(e)
        response = [{"message":f"Error while adding route: {e}"}]
    return HttpResponse(response)   

@csrf_exempt
def delroute(request: HttpRequest):
    response = [{"message":"Successfully deleted"}]
    try:         
        data = json.loads(request.body)       
        subnet_info = data["subnet_info"]
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            data1 = yaml.safe_load(f)
            f.close()
        dat=[]
        for rr in data1["network"]["ethernets"]["eth1"]:
            if rr == "routes":
                dat = data1["network"]["ethernets"]["eth1"]["routes"]
        
        for r in subnet_info:            
#            to_delete = {"to": r["subnet"],
 #                        "via": r["gateway"]}
            dat = [item for item in dat if item.get('to') != r['subnet']]
        data1["network"]["ethernets"]["eth1"]["routes"] = dat
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(data1, f, default_flow_style=False)
            f.close()
        os.system("sudo netplan apply")  
    except Exception as e:
        print(e)
        response = [{"message":f"Error while adding route: {e}"}]
    return HttpResponse(response)    

def prefix_length_to_netmask(prefix_length):
    """
    Convert prefix length to netmask.

    Args:
    prefix_length (int): The prefix length.

    Returns:
    str: The netmask in dotted decimal notation.
    """
    netmask = (0xffffffff << (32 - prefix_length)) & 0xffffffff
    return str(ipaddress.IPv4Address(netmask))

@csrf_exempt 
def checksubnet(request: HttpRequest):
  data = json.loads(request.body)  
  ip_addresses = [data["subnet"].split("/")[0]]
  for ip in ip_addresses:    
    try:
        command = (f"ip vrf exec default ping -c 5  {ip}")
        output = subprocess.check_output(command.split()).decode()
        lines = output.strip().split("\n")
        # Extract the round-trip time from the last line of output
        last_line = lines[-1].strip()
        rtt = last_line.split()[3]
        rtt_avg = rtt.split("/")[1]
        response = [{"avg_rtt":rtt_avg}]
        return JsonResponse(response, safe=False)
    except subprocess.CalledProcessError:
        rtt_avg = -1
    response = [{"avg_rtt":rtt_avg}]  
  return JsonResponse(response, safe=False)

@csrf_exempt
def traceroute_spoke(request):
   data = json.loads(request.body)
   print(data)
   host_ip = data.get('trace_ip')
   if host_ip:
      result1 = subprocess.run(['ip', 'vrf', 'exec', 'default','traceroute', '-d', host_ip], capture_output=True, text=True)
      print(result1)
      print(result1.stdout)
      return HttpResponse(result1.stdout, content_type='text/plain')
   return HttpResponse(status=400)


@csrf_exempt 
def changedefaultgw(request: HttpRequest):
  data = json.loads(request.body)  
  os.system(f"ip route replace table 10 default via {data['default_gw']}")
  response ={"message":"Fixed successfully"}
  return JsonResponse(response, safe=False)

@csrf_exempt
def delete(request):
  os.system("ip tunnel del Reach_link1")
  os.system("systemctl stop reachlink")
  os.system("systemctl disable reachlink")
  #os.system("apt remove reachlink")
  #os.system("rm -r /etc/reach")
  response = {"msg":"Successfully deleted"}
  return HttpResponse(response) 

def background_update(data):
    file_name_tar = data.get('file_name')
    url = data.get('url')
    with open(file_path, "r") as f:
        data_json = json.load(f)
        f.close()
    default_gw = data_json["default_gateway"]
    os.system("systemctl stop reachlink")
    os.system(f"ip route replace default via {default_gw}")
    os.system(f'wget {url}')
    os.system(f"tar -xvf {file_name_tar}")
    file_name = file_name_tar.split(".tar")[0]
    os.system(f"cp -r {file_name}/views.py link/views.py")
    os.system(f"cp -r {file_name}/urls.py linkgui/urls.py")
    os.system("apt remove reachlink")
    os.system(f"dpkg -i {file_name}/reachlink.deb")
    os.system(f"cp {file_name}/reachlink.service /etc/systemd/system/")
    os.system("systemctl enable reachlink")
    os.system("systemctl start reachlink")
    os.system("systemctl restart reachlinkgui")
    

@csrf_exempt
def update (request: HttpRequest):
    data = json.loads(request.body)
    background_thread = threading.Thread(target=background_update,  args=(data,))
    background_thread.start()
    response = [{"message": "Update successfull"}]
    return HttpResponse(response)

@csrf_exempt
def download_logfile(request):
    # Read the contents of the logfile
    logfile_content = ""
    if os.path.exists("/var/log/reachlink.log"):
        with open('/var/log/reachlink.log', 'r') as file:
            logfile_content = file.read()
            file.close()
    # Create an HTTP response with the logfile content as a downloadable file
    response = HttpResponse(logfile_content, content_type='text/plain')
    response['Content-Disposition'] = 'attachment; filename="reachlink.log"'
    return response

def prefix_len_to_netmask(prefix_len):
    # Validate the prefix length
    print(prefix_len)
    prefix_len = int(prefix_len)
    if not 0 <= prefix_len <= 32:
        raise ValueError("Prefix length must be between 0 and 32")
    # Calculate the netmask using bitwise operations
    netmask = 0xffffffff ^ (1 << (32 - prefix_len)) - 1
    # Format the netmask into IP address format
    netmask_str = ".".join(str((netmask >> i) & 0xff) for i in [24, 16, 8, 0])
    return netmask_str

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Get the subnet ID and broadcast address
    subnet_id = subnet.network_address
    broadcast_ip = subnet.broadcast_address

    # Extract and return the list of host IPs (excluding subnet ID and broadcast IP)
    #host_ips = [str(ip) for ip in subnet.hosts()]
    
    if subnet.prefixlen == 31:
        # For /31, both IPs can act as hosts (point-to-point links)
        first_host = subnet.network_address
        last_host = subnet.broadcast_address
    else:
        # For other subnets, calculate first and last host IPs
        first_host = subnet.network_address + 1
        last_host = subnet.broadcast_address - 1

   
    host_ips = [first_host, last_host]    
    return {
        "Subnet_ID": str(subnet_id),
        "Broadcast_IP": str(broadcast_ip),
        "Host_IPs": host_ips
    }


def calculate_subnet_id(ip_address, netmask):
    try:
        # Split the IP address and netmask into octets
        ip_octets = [int(octet) for octet in ip_address.split('.')]
        netmask_octets = [int(octet) for octet in netmask.split('.')]
        # Calculate the subnet ID
        subnet_id_octets = [ip_octets[i] & netmask_octets[i] for i in range(4)]
        # Convert the subnet ID octets back to a string
        subnet_id = '.'.join(map(str, subnet_id_octets))
    except Exception as e:
        return ip_address       
    return subnet_id


def  validateIP(ip_address):
    octet = ip_address.split(".")
    prefix_len = ip_address.split("/")[1]
    if prefix_len == 32:
        return False
    if octet[0] == "10":
        if int(prefix_len) > 7:
            return True
    if octet[0] == "172":
        if 15 < int(octet[1]) < 32:
            if int(prefix_len) > 15:
                return True
    if octet[0] == "192" and octet[1] == "168":
        if int(prefix_len) > 23:
            return True    
    return False



def validate_dns_server(dns_ip, domain='google.com'):
    try:
        # Construct the command to run a DNS query in the default VRF
        cmd = f"ip vrf exec default dig +short {domain} @{dns_ip}"

        # Run the command using subprocess and capture the output
        result = subprocess.run(
            cmd, shell=True, text=True, capture_output=True, timeout=3
        )

        # Check if the command was successful and output is non-empty
        if result.returncode == 0 and result.stdout.strip():
            print(f"{dns_ip} is a valid DNS server.")
            print("Resolved IP(s):", result.stdout.strip())
            return True
        else:
            print(f"Failed to resolve {domain} using {dns_ip}.")
            print(f"Error: {result.stderr.strip()}")
            return False

    except subprocess.TimeoutExpired:
        print(f"DNS query timed out for {dns_ip}.")
        return False
    except Exception as e:
        print(f"An error occurred: {e}")
        return False

def get_lan_info():
    interface = psutil.net_if_addrs()
    lan_addr = "none"     
    for intfc_name in interface:
        if intfc_name == "eth1":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                                    
                    
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    lan_addr = str(address.address)+"/"+str(pre_len)
                    return lan_addr 
    return lan_addr  

def get_wan_info():
    interface = psutil.net_if_addrs()
    lan_addr = "none"     
    for intfc_name in interface:
        if intfc_name == "eth0":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                                    
                    
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    lan_addr = str(address.address)+"/"+str(pre_len)
                    return lan_addr 
    return lan_addr  

def is_ip_in_network(ip, network):
    try:
        # Convert IP and network to objects
        ip_obj = ipaddress.ip_address(ip)
        network_obj = ipaddress.ip_network(network, strict=False)

        # Check if the IP is part of the network
        if ip_obj in network_obj:
            print(f"{ip} belongs to the network {network}.")
            return True
        else:
            print(f"{ip} does not belong to the network {network}.")
            return False
    except ValueError as e:
        print(f"Invalid IP or network: {e}")
        return False
@csrf_exempt
def dhcp_config(request):
    try:
        data = json.loads(request.body)
        ip_address = data.get("ipaddress")
        domain_name = data.get("primary_dns","8.8.8.8")
        optional_dns = data.get("secondary_dns", "8.8.4.4")
        if not validate_dns_server(domain_name):
            response = {"message": f"Error: Primary DNS server is not valid DNS server"} 
            return JsonResponse(response, safe=False)
        if not validate_dns_server(optional_dns):
            response = {"message": f"Error: Secondary DNS server is not valid DNS server"} 
            return JsonResponse(response, safe=False)       

        #configuring DHCP Range accordingly 
        netmask = prefix_len_to_netmask(ip_address.split("/")[1])
        ip_addr = ip_address.split("/")[0]                
        lan_address = calculate_subnet_id(ip_addr, netmask)
        ip_addresses = get_ip_addresses(ip_addr, netmask)  
        dhcp_start_address = data.get("dhcp_start_addr", ip_addresses["Host_IPs"][0])
        dhcp_end_address = data.get("dhcp_end_addr",ip_addresses["Host_IPs"][1])
        network = get_lan_info()
        if network:
            if not is_ip_in_network(dhcp_start_address, network) or dhcp_start_address == ip_addresses["Subnet_ID"]:
                response = {"message": f"Error: DHCP start address is not in LAN subnet"} 
                return JsonResponse(response, safe=False) 
            if not is_ip_in_network(dhcp_start_address, network) or dhcp_end_address == ip_addresses[ "Broadcast_IP"]:
                response = {"message": f"Error: DHCP end address is not in LAN subnet"} 
                return JsonResponse(response, safe=False)       
                                    
        
        bracket = "{"
        closebracket ="}"                
        #Configure dhcpd.conf file
        with open("/etc/dhcp/dhcpd.conf", "w") as f:
            f.write(f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet {lan_address} netmask {netmask} {bracket} \n range {dhcp_start_address} {dhcp_end_address}; \n option routers {ip_addr}; \n option subnet-mask {netmask}; \n option domain-name-servers {domain_name}, {optional_dns}; \n{closebracket}")
            f.close() 
        os.system("systemctl restart isc-dhcp-server")   
        response = {"message": "DHCP configured successfully"}
        with open("/etc/systemd/resolved.conf", "r") as f:
            dns_data = f.read()
            f.close()
        # Define the regex pattern to match any existing IP address for the interface
        pattern = rf"DNS=\S+"

        # Check if the pattern matches
        if re.search(pattern, dns_data):           
            dns_data = re.sub(pattern, f"DNS={domain_name} {optional_dns}\n", dns_data)
        with open("/etc/systemd/resolved.conf", "w") as f:
            f.write(dns_data)
            f.close()
        os.system("sudo systemctl restart systemd-resolved")                
        
    except Exception as e:
        response = {"message": f"Error: {e}"} 
    return JsonResponse(response, safe=False)


@csrf_exempt
def lan_info(request):
    try:
        response = {}
        lan_addr = get_lan_info()
        out1 = subprocess.check_output(["awk", "/range/ {print  $2, $3} /domain-name-servers/ {print $3, $4}", "/etc/dhcp/dhcpd.conf"]).decode()
        out2 = out1.split("\n")
        dhcp_start_addr = out2[0].split(" ")[0]
        dhcp_end_addr = out2[0].split(" ")[1].split(";")[0]
        primary_dns = out2[1].split(",")[0]
        sec_dns = out2[1].split(" ")[1].split(";")[0]
        response = {"dhcp_start_addr":dhcp_start_addr,
                   "dhcp_end_addr":dhcp_end_addr,
                   "primary_dns":primary_dns,
                   "sec_dns":sec_dns,
                   "lan_ipaddr": lan_addr}
    except Exception as e:
        print(e)
    print(response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def lan_config(request):
    try:
        data = json.loads(request.body)
        ip_address = data.get("ipaddress")
        if not (validateIP(ip_address)):
            response = {"message": "Error: IP should be in private range"} 
            print(response)  
            return JsonResponse(response, safe=False)
        netmask = prefix_len_to_netmask(ip_address.split("/")[1])
        ip_addr = ip_address.split("/")[0]       
        ip_addresses = get_ip_addresses(ip_addr, netmask) 
        wan_info = get_wan_info()
        if is_ip_in_network(ip_addr, wan_info):
            response = {"message": "Error: Conflict with WAN IP Range"}  
            print(response) 
            return JsonResponse(response, safe=False)
        if is_ip_in_network(ip_addr, "10.200.202.2/24"):
            response = {"message": "Error: Conflict with Tunnel IP"}
            return JsonResponse(response, safe=False)        
        print(ip_addresses["Subnet_ID"]) 
        lan_address = ip_addresses["Subnet_ID"]
        print(ip_addresses[ "Broadcast_IP"])
        if ip_addr == ip_addresses["Subnet_ID"] or ip_addr ==  ip_addresses[ "Broadcast_IP"]:
            response = {"message": "Error: Either Subnet ID or Broadcast IP is not able to assign"}  
            print(response) 
            return JsonResponse(response, safe=False)
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            network_config = yaml.safe_load(f)
            f.close()
        network_config["network"]["ethernets"]["eth1"]["addresses"] = [ip_address]
        with open("/etc/netplan/00-installer-config.yaml", "w") as f:
            yaml.dump(network_config, f, default_flow_style=False)
            f.close()
        os.system("netplan apply")

        #configuring DHCP Range accordingly 
        
        dhcp_start_address = ip_addresses["Host_IPs"][0]
        dhcp_end_address = ip_addresses["Host_IPs"][1]                             
        domain_name = "8.8.8.8"
        optional_dns = "8.8.4.4"
        bracket = "{"
        closebracket ="}"                
        #Configure dhcpd.conf file
        with open("/etc/dhcp/dhcpd.conf", "w") as f:
            f.write(f"default-lease-time 600;\nmax-lease-time 7200;\nauthoritative;\nsubnet {lan_address} netmask {netmask} {bracket} \n range {dhcp_start_address} {dhcp_end_address}; \n option routers {ip_addr}; \n option subnet-mask {netmask}; \n option domain-name-servers {domain_name}, {optional_dns}; \n{closebracket}")
            f.close() 
        os.system("systemctl restart isc-dhcp-server")   
        response = {"message": "Lan address configured successfully"}            
        
    except Exception as e:
        response = {"message": f"Error: {e}"} 
    print(response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def add_ip_rule(request):
    try:
        data = json.loads(request.body)
        #First delete the rule if already have
        cmd = f"sudo ip rule del from {data['realip_subnet']} table 10"
        result = subprocess.run(
                                cmd, shell=True, text=True, capture_output=True, timeout=3
                                )
        #Add new rule for Real IP get inetrnet via HUB
        cmd = f"sudo ip rule add from {data['realip_subnet']} table 10"
        result = subprocess.run(
                                cmd, shell=True, text=True, capture_output=True, timeout=3
                                )
        with open("/etc/reach/iprules", "a") as f:
            f.write(f"ip rule add from {data['realip_subnet']} table 10\n")
            f.close()
        response = {"message": f"Ip rule added successfully in {data['tunnel_ip']}"}
        with open("/etc/reach/iprules", 'r') as f:
            lines = f.readlines()
            f.close()
        # Use a set to store unique lines
        unique_lines = list(dict.fromkeys(lines))
        with open("/etc/reach/iprules", 'w') as f:
            f.writelines(unique_lines)
            f.close()
    except Exception as e:
        print(e)
        response = {"message": f"Error while applying ip rule: {e}"}
    return JsonResponse(response, safe=False)


def get_routing_table(request):
    routing_table = []
    try:        
        ipr = IPRoute()
        routes = ipr.get_routes(family=socket.AF_INET)
        for route in routes:
            if route['type'] == 1:
                destination = "0.0.0.0"
                metric = 0
                gateway = "-"
                protocol = int(route['proto'])
                multipath = 0
                dst_len = route['dst_len']
                for attr in route['attrs']:
                    if attr[0] == 'RTA_OIF':
                        intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                        if str(table) != "Main Routing Table":
                            command = (f"ip link show {intfc_name}")
                            output = subprocess.check_output(command.split()).decode()
                            lines = output.strip().split("\n")
                            try:
                                table = lines[0].split("master")[1].split(" ")[1]
                            except IndexError:
                                table = table
                    if attr[0] == 'RTA_GATEWAY':
                        gateway = attr[1]
                    if attr[0] == 'RTA_PRIORITY':
                        metric = attr[1]
                    if attr[0] == 'RTA_DST':
                        destination = attr[1]
                    if attr[0] == 'RTA_TABLE':
                        if attr[1] == 254:
                            table = "Main Routing Table"
                        else:
                            table = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    gateway = attr2[1] 
                                    multipath = 1
                                    routing_table.append({"outgoing_interface_name":str(intfc_name),
                                                    "gateway":str(gateway),
                                                    "destination":str(destination)+"/"+str(dst_len),
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map.get(protocol, "static"),
                                                    "table_id":table
                                                    })
                if multipath == 0:      
                    routing_table.append({"outgoint_interface_name":str(intfc_name),
                                  "gateway":str(gateway),
                                  "destination":str(destination)+"/"+str(dst_len),
                                  "metric":int(metric),
                                  "protocol":routes_protocol_map.get(protocol,"static"),
                                  "table_id": table
                                })                
        
    except Exception as e:
        print(e)
    return JsonResponse(routing_table, safe=False)

def get_interface_details(request):
    try:
        interface_details = []
        interface = psutil.net_if_addrs()
        intfc_ubuntu = []
        for intfc_name in interface:            
            if intfc_name == "gre0" or intfc_name == "gretap0" or intfc_name == "erspan0" or intfc_name =="lo":   
                continue
            colect = {"interface_name":intfc_name}
            if intfc_name == "eth1":
                colect.update({"type":"ether"})
            addresses = interface[intfc_name]
            interface_addresses = []
            for address in addresses:      
                if address.family == 2:
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                    interface_addresses.append({
                                    "IPv4address_noprefix":str(address.address),
                                    "IPv4address":ipaddr_prefix,
                                    "netmask":str(address.netmask),
                                    "broadcast":str(address.broadcast)
                                  })
                if address.family == 17:
                    colect.update({
                                    "mac_address":str(address.address)
                                   })         
            colect.update({"addresses":interface_addresses})   
            intfc_ubuntu.append(colect)
            interface_details.append(colect)
        #By using pyroute module, we get the default route info & conclude which interface is WAN.  
        # And about its Gateway
        default_route = ipr.get_default_routes(family = socket.AF_INET)
        for route in default_route:
#            print(route)
            multipath = 0
            for attr in route['attrs']:
                if attr[0] == 'RTA_OIF':
                    intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                if attr[0] == 'RTA_GATEWAY':
                    gateway = attr[1]
                if attr[0] == 'RTA_MULTIPATH':
                    multipath = 1
                    for elem in attr[1]:
                        intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                        for attr2 in elem['attrs']:
                            if attr2[0] == 'RTA_GATEWAY':
                                gateway = attr2[1] 
                                for intfc in interface_details:
                                    if intfc["interface_name"] == intfc_name:
                                        intfc["gateway"] = gateway
                                        intfc["type"] = "ether"
            if multipath == 0:
                for intfc in interface_details:
                    if intfc["interface_name"] == intfc_name:
                        intfc["gateway"] = gateway
                        intfc["type"] = "ether" 
                    if "." in intfc["interface_name"]:
                        intfc["type"] = "VLAN"
                    elif "eth" in intfc["interface_name"]:
                         intfc["type"] = "ether"
                    if intfc["interface_name"] == "Reach_link1" or intfc["interface_name"] == "tun0":
                        intfc["type"] = "ReachLink interface"
                    if "vrf" in intfc["interface_name"]:
                        intfc["type"] = "VRF"
    except Exception as e:
        response = [{"message":f"Error while getting interface details: {e}"}]
        print(response)
    return JsonResponse(interface_details, safe=False) 

def configured_address():
    try:
        interface_addresses= []
        interface = psutil.net_if_addrs()        
        for intfc_name in interface:  
            if intfc_name == "gre0" or intfc_name == "gretap0" or intfc_name == "erspan0" or intfc_name =="lo":   
                continue
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                    interface_addresses.append(ipaddr_prefix)
    except Exception as e:
        print(e)
    return interface_addresses

@csrf_exempt
def create_vlan_interface(request):
    try:
        data = json.loads(request.body)
        interface_addresses = configured_address()
#        print(interface_addresses)
        for vlan_address in data["addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
 #               print("corrected_subnet", corrected_subnet)
 #               print("vlan_adress", vlan_address)
                ip_obj = ipaddress.ip_address(vlan_address.split("/")[0])
                #network = ipaddress.IPv4Network(corrected_subnet, strict=False)  
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring VLAN interface due to address conflict {vlan_address}"}]
                    return JsonResponse(response, safe=False)
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()           
            # Ensure the `vlans` section exists
            if "vlans" not in network_config["network"]:
                network_config["network"]["vlans"] = {}

            # Create the VLAN interface name
            vlan_int_name = f"{data['link']}.{data['vlan_id']}"
            if vlan_int_name not in network_config["network"]["vlans"]:
            # Add VLAN configuration
                network_config["network"]["vlans"][vlan_int_name] = {
                                                                "id": int(data["vlan_id"]),
                                                                "link": data["link"],
                                                                "addresses": data["addresses"],
                                                                "nameservers": {"addresses": data["nameservers"]},
                                                                }

                # Write the updated configuration back to the file
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                os.system("netplan apply")
                response = [{"message": f"Successfully configured VLAN Interface: {vlan_int_name}"}]
            else:
                response = [{"message": f"Error already VLAN: {vlan_int_name} exist."}]
        else:
            vlan_int_name = data["link"] + "." + str(data["vlan_id"])
            cmd = f"sudo ip link add link {data['link']} name {vlan_int_name} type vlan id {str(data['vlan_id'])}"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                )
            for ip_addr in data["addresses"]:
                cmd = f"sudo ip addr add {ip_addr} dev eth1.100"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )
            cmd = f"sudo ip link set dev {vlan_int_name} up"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                )
            response = [{"message": f"Successfully configured VLAN Interface: {vlan_int_name}"}]

    except Exception as e:
        response = [{"message": f"Error while configuring VLAN interface with id {data['vlan_id']}: {e}"}]
    print(response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def interface_config(request):  
    try:
        data = json.loads(request.body)
        if data["intfc_name"] == "eth0":
            response = [{"message": f"Error dont try to modify WAN interface address: {data['intfc_name']}"}]
            print(response)
            return JsonResponse(response, safe= False)
        for addr in data["current_addresses"]:
            os.system(f"sudo ip addr del {addr} dev {data['intfc_name']}")
        interface_addresses = configured_address()
        #print(interface_address)
        for int_addr in data["new_addresses"]:
            for address in interface_addresses:
                corrected_subnet = ipaddress.ip_network(address, strict=False)
                ip_obj = ipaddress.ip_address(int_addr.split("/")[0])
                if ip_obj in corrected_subnet:  
                    response = [{"message": f"Error while configuring interface due to address conflict {int_addr}"}]
                    return JsonResponse(response, safe=False)
        intfc_name = data["intfc_name"]
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()             
            if "." in data["intfc_name"]:
                # Ensure the `vlans` section exists
                if "vlans" not in network_config["network"]:
                    network_config["network"]["vlans"] = {}
                # Add VLAN configuration
                network_config["network"]["vlans"][intfc_name]["addresses"] = data["new_addresses"]                
            else:                
                network_config["network"]["ethernets"][intfc_name]["addresses"] = data["new_addresses"]                                                                       
            # Write the updated configuration back to the file
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(network_config, f, default_flow_style=False)
            os.system("netplan apply")
            response = [{"message": f"Successfully configured Interface: {intfc_name}"}]
        else:            
            for ip_addr in data["addresses"]:
                cmd = f"sudo ip addr add {ip_addr} dev {intfc_name}"
                result = subprocess.run(
                                cmd, shell=True, text=True
                                )            
            response = [{"message": f"Successfully configured Interface: {intfc_name}"}]
    except Exception as e:
        print(e)
        response = [{"message": f"Error while configuring interface with  {data['intfc_name']}: {e}"}]
        print("excep", response)
    return JsonResponse(response, safe=False)

@csrf_exempt
def vlan_interface_delete(request):  
    try:
        data = json.loads(request.body) 
        intfc_name = data["intfc_name"]
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()             
            if "." in data["intfc_name"]:
                # Ensure the `vlans` section exists
                if "vlans" not in network_config["network"]:
                    response = [{"message": f"No such VLAN available"}]
                # Add VLAN configuration
                else:
                    if intfc_name in network_config["network"]["vlans"]:
                        del network_config["network"]["vlans"][intfc_name]          
                    response = [{"message": f"Successfully deleted the VLAN Interface: {intfc_name}"}]                                              
            # Write the updated configuration back to the file
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(network_config, f, default_flow_style=False)
            os.system("netplan apply")            
            cmd = f"sudo ip link del {intfc_name}"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                )    
        else:            
            cmd = f"sudo ip link del {intfc_name}"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                )            
            response = [{"message": f"Successfully  deleted VLAN Interface: {intfc_name}"}]
    except Exception as e:
        response = [{"message": f"Error while deleting the VLAN interface interface {data['intfc_name']}: {e}"}]
    print(response)
    return JsonResponse(response, safe=False)            

def configured_address_interface():
    try:
        interface_addresses= []
        interface = psutil.net_if_addrs()        
        for intfc_name in interface:  
            if intfc_name == "gre0" or intfc_name == "gretap0" or intfc_name == "erspan0" or intfc_name =="lo":   
                continue
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:
                    pre_len = IPAddress(address.netmask).netmask_bits()
                    ipaddr_prefix = str(address.address)+"/"+str(pre_len)
                    interface_addresses.append({"intfc_name":intfc_name,
                                                "intfc_addr": ipaddr_prefix
                                                }
                                                )
    except Exception as e:
        print(e)
    return interface_addresses
@csrf_exempt
def addstaticroute(request: HttpRequest):
    response = [{"message":"Successfully added"}]
    try:         
        data = json.loads(request.body)       
        subnet_info = data["subnet_info"]
        subnets = []
        interface_addresses = configured_address_interface()
        gateway_intfc_aval = False
        #print(interface_address)
        for address in interface_addresses:
            corrected_subnet = ipaddress.ip_network(address["intfc_addr"], strict=False)
            ip_obj = ipaddress.ip_address(data["subnet_info"][0]['gateway'])
            if ip_obj in corrected_subnet:  
                gateway_intfc = address["intfc_name"]
                gateway_intfc_aval = True
                break
        print("gateway_intfc", gateway_intfc)
        if gateway_intfc_aval:
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                data1 = yaml.safe_load(f)
                f.close()
            dat=[]
            if "eth" in gateway_intfc:
                network = "ethernets"
            if "Reach" in gateway_intfc:
                network = "tunnels"
            if "." in gateway_intfc:
                network = "vlans"
            print("networ", network)
            for rr in data1["network"][network][gateway_intfc]:
                if rr == "routes":
                    dat = data1["network"][network][gateway_intfc]["routes"]
            for r in subnet_info:
                try:                    
                    if (ipaddress.ip_network(r["subnet"], strict=False) and ipaddress.ip_address(r["gateway"])):
                        dat.append({"to": r["subnet"],
                                    "via": r["gateway"]}
                                    )
                    
                except ValueError:
                    response = [{"message":"Either subnet or Gateway is not valid IP"}]        
            data1["network"][network][gateway_intfc]["routes"] = dat
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(data1, f, default_flow_style=False)
                f.close()
            os.system("sudo netplan apply")              
            response = [{"message":f"Successfully {len(dat)} route(s) added"}]
        else:
            response = [{"message":f"Error in adding route. pl check gateway"}]      
    except Exception as e:
        print(e)
        response = [{"message":f"Error while adding route"}]
    return JsonResponse(response, safe=False)   

@csrf_exempt
def addstaticroute1(request: HttpRequest):
    response = [{"message":"Successfully added"}]
    try:         
        data = json.loads(request.body)       
        subnet_info = data["subnet_info"]
        subnets = []
        for subnet in subnet_info:
            cmd = f"sudo ip route replace {subnet['subnet']} via {subnet['gateway']}"
            result = subprocess.run(
                                cmd, shell=True, text=True
                                ) 
            subnets.append(subnet["subnet"])
        response = [{"message":f"Successfully {len(subnets)} route(s) added"}]
              
    except Exception as e:
        print(e)
        response = [{"message":f"Error while adding route"}]
    return JsonResponse(response, safe=False)    

@csrf_exempt
def getpbrinfo(request: HttpRequest):
    try:         
        command = (f"ip rule show")
        output = subprocess.check_output(command.split()).decode()
        lines = output.strip().split("\n")
        pbr_info = []
        for line in lines:
            src_address = " "
            dst_address = " "
            if "vrf1" in line:
                if "from" in line:
                    src_address = line.split("from")[1].split(" ")[1]
                if "to" in line:
                    dst_address = line.split("to")[1].split(" ")[1]
                else:
                    dst_address = "any"
                new_routing_mark = line.split("lookup")[1].split(" ")[1]
                pbr_info.append({"new_routing_mark":new_routing_mark,
                            "src_address": src_address,
                            "dst_address": dst_address})     
    except Exception as e:
        print(e)
    return JsonResponse(pbr_info, safe=False) 
