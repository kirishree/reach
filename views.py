from django.shortcuts import render
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.hashers import make_password
from django.contrib.auth.decorators import login_required
from django.contrib.auth.views import LoginView
from django.urls import reverse_lazy
from django.contrib.auth import logout
from django.shortcuts import redirect
from .forms import RegisterForm, WANSettingsForm, LANSettingsForm, OptionalAdapterSettingsForm, TimeZoneForm, ChangePassword, PingForm, TraceRouteForm
from django.http import HttpRequest, HttpResponse,  JsonResponse
from django.views.decorators.csrf import csrf_exempt
import os
import json
import yaml
import requests
import socket
from datetime import datetime, date
from netaddr import IPAddress
import netifaces as ni
from pyroute2 import IPRoute
import psutil
import subprocess
import ipaddress
ipr = IPRoute()

file_path = "/etc/reach/reachlink_info.json"

routes_protocol_map = {
    -1: '',
    2: 'kernel',
    3: 'boot',
    4: 'static',    
    16: 'dhcp',    
}

def get_system_uuid():
    try:
        # Read the product_uuid file to get the system UUID
        with open('/sys/class/dmi/id/product_uuid', 'r') as file:
            uuid = file.read().strip()
        return uuid
    except Exception as e:
        print(f"Error: {e}")
        return None

class CustomLoginView(LoginView):
    template_name = 'login.html'
    redirect_authenticated_user = True
    success_url = reverse_lazy('dashboard')  # Redirect to contact page after login

def logout_view(request):
    logout(request)
    return redirect('login')  # Redirect to the login page

def get_city_name():
    try:
        response = requests.get('https://ipinfo.io/json')
        data = response.json()
        print(data)
        city = data.get('city') + "@" + data.get('country')        
        return city
    except Exception as e:
        print(f"Error: {e}")
        return None

def get_wan_info():
    interface = psutil.net_if_addrs() 
    wan_info = {}       
    for intfc_name in interface:
        if intfc_name == "eth0":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                          
                    gws = ni.gateways()                        
                    wan_info = {"IPv4address_noprefix": str(address.address),                                 
                                "netmask": str(address.netmask),
                                "gateway": gws['default'][ni.AF_INET][0]   
                                } 
                    return wan_info 
    return wan_info    

def change_password(username, new_password):
    try:
        # Retrieve the user object
        user = User.objects.get(username=username)        
        # Change the password
        user.password = make_password(new_password)
        user.save()
        return True        
    except ObjectDoesNotExist:
        return False
    except Exception as e:
        return False

def get_opt_int_info():
    interface = psutil.net_if_addrs() 
    opt_info = {}       
    for intfc_name in interface:
        if intfc_name == "eth2":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                          
                    gws = ni.gateways()  
                    gateway = '' 
                    for gw in gws:
                        if gw != 'default':
                            if gws[gw][0][1] == "eth2":
                                gateway = gws[gw][0][0]                     
                    opt_info = {"IPv4address_noprefix": str(address.address),                                 
                                "netmask": str(address.netmask),
                                "gateway": gateway   
                                } 
                    return opt_info 
    return opt_info    

def get_lan_info():
    interface = psutil.net_if_addrs()
    lan_info = {}        
    for intfc_name in interface:
        if intfc_name == "eth1":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                                          
                    lan_info = {"IPv4address_noprefix": str(address.address),                                 
                                "netmask": str(address.netmask)                                
                                } 
                    return lan_info  
    return lan_info      

def check_tunnel_connection():
    try:       
        command = (f"ping -c 3  10.200.201.1")
        output = subprocess.check_output(command.split()).decode()          
        return True      
    except subprocess.CalledProcessError:        
        return False 

def get_routing_table():
    routing_table = []
    try:        
        ipr = IPRoute()
        routes = ipr.get_routes(family=socket.AF_INET)
        for route in routes:
            if route['type'] == 1:
                destination = "0.0.0.0"
                metric = 0
                gateway = "none"
                protocol = int(route['proto'])
                multipath = 0
                dst_len = route['dst_len']
                for attr in route['attrs']:
                    if attr[0] == 'RTA_OIF':
                        intfc_name = ipr.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
                    if attr[0] == 'RTA_GATEWAY':
                        gateway = attr[1]
                    if attr[0] == 'RTA_PRIORITY':
                        metric = attr[1]
                    if attr[0] == 'RTA_DST':
                        destination = attr[1]
                    if attr[0] == 'RTA_MULTIPATH':
                        for elem in attr[1]:
                            intfc_name = ipr.get_links(elem['oif'])[0].get_attr('IFLA_IFNAME')
                            for attr2 in elem['attrs']:
                                if attr2[0] == 'RTA_GATEWAY':
                                    gateway = attr2[1] 
                                    multipath = 1
                                    routing_table.append({"interface_name":str(intfc_name),
                                                    "gateway":str(gateway),
                                                    "destination":str(destination)+"/"+str(dst_len),
                                                    "metric":int(metric),
                                                    "protocol":routes_protocol_map[protocol]
                                                    })
                if multipath == 0:      
                    routing_table.append({"interface_name":str(intfc_name),
                                  "gateway":str(gateway),
                                  "destination":str(destination)+"/"+str(dst_len),
                                  "metric":int(metric),
                                  "protocol":routes_protocol_map[protocol]
                                })                
        return routing_table
    except Exception as e:
        return routing_table
@login_required
def dashboard(request):
    global url
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        form1 = WANSettingsForm(request.POST)
        form2 = LANSettingsForm(request.POST)
        form3 = OptionalAdapterSettingsForm(request.POST)
        form4 = TimeZoneForm(request.POST)
        form5 = ChangePassword(request.POST)        
        logfile_content = []
        if os.path.exists("/var/log/reachlink.log"):
            with open('/var/log/reachlink.log', 'r') as file:
                logfile_content = file.readlines()
                file.close()
        if form.is_valid():
            # Process form data            
            email = form.cleaned_data['Registered_mail']
            password = form.cleaned_data['password']  
            hub_ip = form.cleaned_data['hub_ip']
            url = "http://" + hub_ip + ":5000/"
            branch_location = get_city_name()                    
            reg_data = { "registered_mail_id": email,
                         "registered_password": password,
                         "location": branch_location,
                         "hub_ip": hub_ip
                         }
            system_uuid = get_system_uuid()
            try:
                system_name = os.getlogin() + "@" + socket.gethostname()
            except Exception as e:
                system_name = "etel@reachwan"            
            collect = { "username": reg_data["registered_mail_id"], 
                    "password": reg_data["registered_password"],
                    "uuid": system_uuid,               
                    "system_name": system_name,                    
                    "branch_location": reg_data["location"]
                    }
            # Convert the Python dictionary to a JSON string
            json_data = json.dumps(collect)        
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}
            # Make the POST request
            response = requests.post(url+"login", data=json_data, headers=headers)
            # Check the response
            if response.status_code == 200:                        
                print("POST request successful!")
                json_response = response.text.replace("'", "\"")  # Replace single quotes with double quotes
                json_response = json.loads(json_response)   

                if json_response["message"] == "Successfully Registered" or   json_response["message"] == "This device is already Registered":
                    # Convert date string to date object
                    date_object = datetime.strptime(json_response["expiry_date"] , "%Y-%m-%d").date()
                    # Get today's date
                    today_date = date.today()
                    # Compare date_object with today's date
                    if date_object > today_date:
                        reg_data["registration_response"] = json_response["message"]
                        reg_data["expiry_date"] = json_response["expiry_date"]  
                        reg_data["subnet"] = ["None"]                          
                        with open(file_path, 'w') as f:
                            json.dump(reg_data, f)
                            f.close()
                        os.system("systemctl enable reachlink")
                        os.system("systemctl start reachlink")
                        return render(request, 'success.html')
                    else:
                        return render(request, 'error_expired.html')
                else:
                    return render(request, 'not_reg.html')     
            else:
                return render(request, 'error.html')        
        if form1.is_valid():
            # Process form data
            protocol = form1.cleaned_data['protocol']
            if protocol == "DHCP":
                with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                    network_config = yaml.safe_load(f)
                    f.close()
                network_config["network"]["ethernets"]["eth0"] = {"dhcp4": True,
                                                                    "nameservers": {
                                                                                    'addresses': ['8.8.8.8','8.8.4.4']
                                                                                    },
                                                                    "match":{"macaddress": network_config["network"]["ethernets"]["eth0"]["match"]["macaddress"]},
                                                                    "set-name": "eth0"
                                                                    }
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                    f.close()
                os.system("netplan apply")
                return render(request, 'conf_success.html')
            ip_addr = form1.cleaned_data['ip_address']
            netmask = form1.cleaned_data['netmask']
            gateway = form1.cleaned_data['gateway'] 
            pre_len = IPAddress(netmask).netmask_bits()
            ip_address = str(ip_addr) + "/" + str(pre_len)
            primary_dns = form1.cleaned_data['primary_dns'] 
            secondary_dns = form1.cleaned_data['secondary_dns'] 
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()
            network_config["network"]["ethernets"]["eth0"]["dhcp4"] = False
            network_config["network"]["ethernets"]["eth0"]["addresses"] = [ip_address]
            network_config["network"]["ethernets"]["eth0"]['gateway4'] = gateway
            network_config["network"]["ethernets"]["eth0"]['nameservers']= {'addresses': [primary_dns, secondary_dns]}
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(network_config, f, default_flow_style=False)
                f.close()
            os.system("netplan apply")
            return render(request, 'conf_success.html')
        if form2.is_valid():                              
            ip_addr = form2.cleaned_data['ip_address_lan']
            netmask = form2.cleaned_data['netmask_lan']
            pre_len = IPAddress(netmask).netmask_bits()
            ip_address = str(ip_addr) + "/" + str(pre_len)            
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()
            network_config["network"]["ethernets"]["eth1"]["addresses"] = [ip_address]
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(network_config, f, default_flow_style=False)
                f.close()
            os.system("netplan apply")
            return render(request, 'conf_success.html')
        if form3.is_valid():
            # Process form data
            protocol_opt = form3.cleaned_data['protocol_opt']
            if protocol_opt == "DHCP":
                with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                    network_config = yaml.safe_load(f)
                    f.close()
                network_config["network"]["ethernets"]["eth2"] = {"dhcp4": True,
                                                                    "nameservers": {
                                                                                    'addresses': ['8.8.8.8','8.8.4.4']
                                                                                    },
                                                                    "match":{"macaddress": network_config["network"]["ethernets"]["eth2"]["match"]["macaddress"]},
                                                                    "set-name": "eth2"
                                                                    }
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                    f.close()
                os.system("netplan apply")
                return render(request, 'conf_success.html')
            ip_addr_opt = form3.cleaned_data['ip_address_opt']
            netmask_opt = form3.cleaned_data['netmask_opt']
            gateway_opt = form3.cleaned_data['gateway_opt'] 
            primary_dns_opt = form3.cleaned_data['primary_dns_opt'] 
            secondary_dns_opt = form3.cleaned_data['secondary_dns_opt'] 
            if primary_dns_opt == '':
                primary_dns_opt = '8.8.8.8'
            if secondary_dns_opt == '':
                secondary_dns_opt = '8.8.4.4'
            pre_len = IPAddress(netmask_opt).netmask_bits()
            ip_address_opt = str(ip_addr_opt) + "/" + str(pre_len)
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()
            network_config["network"]["ethernets"]["eth2"]["dhcp4"] = False
            network_config["network"]["ethernets"]["eth2"]["addresses"] = [ip_address_opt]
            if gateway_opt != '':
                network_config["network"]["ethernets"]["eth2"]['gateway4'] = gateway_opt
            network_config["network"]["ethernets"]["eth2"]['nameservers']= {'addresses': [primary_dns_opt, secondary_dns_opt]}
            with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                yaml.dump(network_config, f, default_flow_style=False)
                f.close()
            os.system("netplan apply")
            return render(request, 'conf_success.html')
        if form4.is_valid():
            selected_time_zone = form4.cleaned_data['time_zone']
            os.system(f"timedatectl set-timezone {selected_time_zone}") 
            os.system("systemctl restart reachlink")            
            return render(request, 'conf_success.html')
        if form5.is_valid():
            new_password = form5.cleaned_data['new_password']
            status = change_password('etel', new_password)
            if status:
                return redirect('login')
            else:
                return render(request, 'error.html') 
                         
    else:        
        if os.path.exists(file_path):
            if check_tunnel_connection():
                initial_reg_data = {"status": "Your device is linked with ReachLink HUB",                                
                                    "Registered_mail": " ",
                                    "password": " "
                                    }
                reg_status = True
            else:
                initial_reg_data = {"status": "Register your device with ReachLink HUB",                                    
                                    "Registered_mail": " ",
                                    "password": " "                                                           
                                    }
                reg_status = False
        else:
            initial_reg_data = {"status": "Register your device with ReachLink HUB",                                
                                "Registered_mail": " ",
                                "password": " "
                                } 
            reg_status = False                               
        form = RegisterForm(initial = initial_reg_data) 
        wan_intfc_info = get_wan_info() 
        opt_intfc_info = get_opt_int_info()         
        with open("/etc/netplan/00-installer-config.yaml", "r") as f:
            network_config = yaml.safe_load(f)
            f.close()
        primary_dns = network_config["network"]["ethernets"]["eth0"]['nameservers']['addresses'][0]
        sec_dns = network_config["network"]["ethernets"]["eth0"]['nameservers']['addresses'][1]
        proto =  network_config["network"]["ethernets"]["eth0"]["dhcp4"]
        lan_intfc_info = get_lan_info()
        if proto == False:
            protocol = "static"
        else:
            protocol = "DHCP"
        
        initial_wan_data = {"ip_address": wan_intfc_info.get("IPv4address_noprefix", ""),
                            "netmask":wan_intfc_info.get("netmask", ""),
                            "gateway":wan_intfc_info.get("gateway", ""),
                            "primary_dns": primary_dns,
                            "secondary_dns":sec_dns,
                            "protocol":protocol
                            }        
        initial_lan_data = {"ip_address_lan": lan_intfc_info.get("IPv4address_noprefix", "") ,
                            "netmask_lan":lan_intfc_info.get("netmask", "")                      
                            }    
        pri_dns_opt = network_config["network"]["ethernets"]["eth2"]['nameservers']['addresses'][0]
        sec_dns_opt = network_config["network"]["ethernets"]["eth2"]['nameservers']['addresses'][1]
        proto_opt =  network_config["network"]["ethernets"]["eth2"]["dhcp4"]        
        if proto_opt == False:
            protocol_opt = "static"
        else:
            protocol_opt = "DHCP"
        if bool(opt_intfc_info):
            initial_opt_data = {"ip_address_opt": opt_intfc_info.get("IPv4address_noprefix", ""),
                            "netmask_opt":opt_intfc_info.get("netmask", ""),
                            "gateway_opt":opt_intfc_info.get("gateway", ""),
                            "primary_dns_opt": pri_dns_opt,
                            "secondary_dns_opt":sec_dns_opt,
                            "protocol_opt":protocol_opt
                            } 
        else: 
            initial_opt_data = {}                    
        form1 = WANSettingsForm(initial = initial_wan_data)
        form2 = LANSettingsForm(initial = initial_lan_data)
        form3 = OptionalAdapterSettingsForm(initial = initial_opt_data)        
        if os.path.exists("/var/log/reachlink.log"):
            with open('/var/log/reachlink.log', 'r') as file:
                logfile_content = file.readlines()
                file.close()
        else:
            logfile_content = []
        logfile_content.reverse()
        with open("/etc/timezone", "r") as f:
            time_data1 = f.read()
            f.close()
        time_data = {"current_time_zone": time_data1}
        form4 = TimeZoneForm(initial = time_data)   
        form5 = ChangePassword()
        form6 = PingForm()
        form7 = TraceRouteForm()
        routing_table = get_routing_table()
    return render(request, 'dashboard.html', {'status': reg_status, 'routing_table':routing_table,  'form': form, 'form1':form1, 'form3_info': initial_opt_data, 'form2': form2, 'logfile_content':logfile_content, 'form3':form3, 'form4':form4, 'form5':form5, 'form6':form6, 'form7':form7})


def ping(request: HttpRequest):
    if request.method == 'POST':
        form6 = PingForm(request.POST)
        if form6.is_valid():
            host = form6.cleaned_data['ping_host']
            # Perform ping operation
            result = subprocess.run(['ping', '-c', '4', host], capture_output=True, text=True)
            return HttpResponse(result.stdout, content_type='text/plain')
    return HttpResponse(status=400)

def traceroute(request: HttpRequest):
    if request.method == 'POST':
        form7 = TraceRouteForm(request.POST)
        if form7.is_valid():
            host = form7.cleaned_data['trace_host']
            # Perform ping operation
            result1 = subprocess.run(['traceroute', '-d', host], capture_output=True, text=True)
            return HttpResponse(result1.stdout, content_type='text/plain')
    return HttpResponse(status=400)

def poweroff(request: HttpRequest):
    os.system("init 0")
    return HttpResponse("System shutting down...")

def restart(request: HttpRequest):
    os.system("init 6")         
    return HttpResponse("System restarting...")

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
            dat.append({"to": r["subnet"],
                        "via": r["gateway"]}
                        )        
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

def get_ip_addresses(ip_address, netmask):
    # Create an IPv4Network object representing the subnet
    subnet = ipaddress.IPv4Network(f"{ip_address}/{netmask}", strict=False)
    # Extract and return the list of IP addresses (excluding network and broadcast addresses)
    return [str(ip) for ip in subnet.hosts()]
@csrf_exempt 
def checksubnet(request: HttpRequest):
  data = json.loads(request.body)  
  ip_address = data["subnet"].split("/")[0]
  prefix_length =int(data["subnet"].split("/")[1])
  netmask = prefix_length_to_netmask(prefix_length)
  ip_addresses = get_ip_addresses(ip_address, netmask)
  for ip in ip_addresses:    
    try:
        command = (f"ping -c 5  {ip}")
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
def changedefaultgw(request: HttpRequest):
  data = json.loads(request.body)  
  os.system("ip route replace default via 10.200.201.1")
  response ={"message":"Fixed successfully"}
  return JsonResponse(response, safe=False)
