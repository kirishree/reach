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
import threading
from datetime import datetime

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
    try:
       gws = ni.gateways()
       gw = gws['default'][ni.AF_INET][0]
    except:
       gw = "none"
    for intfc_name in interface:
        if intfc_name == "eth0":
            addresses = interface[intfc_name]
            for address in addresses:      
                if address.family == 2:                          
                    gws = ni.gateways()                        
                    wan_info = {"IPv4address_noprefix": str(address.address),                                 
                                "netmask": str(address.netmask),
                                "gateway": gw
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
def create_gre_tunnel(gretunnel_ip, remote_ip, hub_gre_endpoint):
    try:
        if os.path.exists("/etc/netplan/00-installer-config.yaml"):
            # Open and read the Netplan configuration
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()           
            # Ensure the `vlans` section exists
            if "tunnels" not in network_config["network"]:
                network_config["network"]["tunnels"] = {}

            # Create the VLAN interface name
            
            if "Reach_link1" not in network_config["network"]["vlans"]:
            # Add VLAN configuration
                network_config["network"]["tunnels"]["Reach_link1"] = {
                                                                "mode": "gre",
                                                                "local": "0.0.0.0",
                                                                "remote": remote_ip,
                                                                "addresses": [gretunnel_ip],
                                                                "mtu": "1476",
                                                                "routes": [{"to":"0.0.0.0/0",
                                                                            "via":hub_gre_endpoint,
                                                                            "table":"10"
                                                                            }]
                                                                }
                # Write the updated configuration back to the file
                with open("/etc/netplan/00-installer-config.yaml", "w") as f:
                    yaml.dump(network_config, f, default_flow_style=False)
                os.system("netplan apply")
                return True            
    except Exception as e:
        print(e)
    return False

def register_post(form):           
    # Process form data            
        # Process form data            
            email = form.cleaned_data['Registered_mail']
            password = form.cleaned_data['password']  
            hub_ip = "185.69.209.251"
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
                system_name = "etel@reachlink"            
            collect = { "username": reg_data["registered_mail_id"], 
                    "password": reg_data["registered_password"],
                    "uuid": system_uuid,               
                    "system_name": system_name,                    
                    "branch_location": reg_data["location"]
                    }
            print("collect", collect)
            # Convert the Python dictionary to a JSON string
            json_data = json.dumps(collect)        
            # Set the headers to indicate that you are sending JSON data
            headers = {"Content-Type": "application/json"}
            # Make the POST request
            response = requests.post(url+"login", data=json_data, headers=headers)
            # Check the response
            if response.status_code == 200:                        
                print("POST request successful!")
                message_header = response.headers.get('X-Message')
                if message_header:
                    message_data = json.loads(message_header)  # Parse the JSON message    
                    if "spokedevice_name" in  message_data[0]:
                        with open(f"{message_data[0]['spokedevice_name']}.conf", "wb") as f:
                            f.write(response.content)
                            f.close()   
                        os.system(f"cp {message_data[0]['spokedevice_name']}.conf /etc/openvpn/client.conf")   
                        os.system("systemctl restart openvpn@client") 
                        os.system("systemctl enable openvpn@client") 
                        reg_data["registration_response"] = message_data[0]["message"]
                        reg_data["expiry_date"] = message_data[0]["expiry_date"]
                        reg_data["gretunnel_ip"] = message_data[0]["gretunnel_ip"]            
                        reg_data["spokedevice_name"] = message_data[0]['spokedevice_name'] 
                        reg_data["subnet"] = []  
                        reg_data["remote_ip"]  = message_data[0]['remote_ip'] 
                        reg_data["hub_gretunnel_endpoint"] = message_data[0]["hub_gretunnel_endpoint"] 
                        # Convert date string to date object
                        date_object = datetime.strptime(reg_data["expiry_date"], "%Y-%m-%d").date()
                        # Get today's date
                        today_date = date.today()
                        # Compare date_object with today's date
                        if date_object > today_date:
                            with open(file_path, 'w') as f:
                                json.dump(reg_data, f)
                                f.close()
                            #os.system("systemctl enable reachlink")
                            os.system("systemctl enable linkbe")
                            #os.system("systemctl start reachlink")
                            tunnelsetup = create_gre_tunnel(reg_data["gretunnel_ip"], reg_data["remote_ip"], reg_data["hub_gretunnel_endpoint"])
#                            os.system(f"ip route add 0.0.0.0/0 via {reg_data['hub_gretunnel_endpoint']} table 10")
                            if tunnelsetup:
                                return "success"
                            else:
                                return "Error while configuring tunnel"
                            
                        else:
                            return "Error your subscription expired"
                    else:                        
                        return message_data[0]["message"]
                else:                    
                    return "Error while registering. pl try again."
            else:
                return "Error not Reachable" 

def wan_post(form1):
    try:
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
                return 'success'
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
            return 'success'
    except Exception as e:
        return 'error'
    
def lan_post(form2):
    try:      
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
            return 'success'
    except Exception as e:
        return 'error'

@login_required
def dashboard(request):
            if os.path.exists(file_path):
                with open(file_path, "r") as f:
                    data_json = json.load(f)
                    f.close()           
                if "expiry_date" in data_json:
                    # Parse the expiry date string (format: YYYY-MM-DD)
                    expiry_date = datetime.strptime(data_json["expiry_date"], "%Y-%m-%d").date()

                    # Get the current date
                    current_date = datetime.today().date()

                    # Compare dates
                    if current_date < expiry_date:
                        status = "false"
                    else:
                        status = "true"
                else:
                    status = "true"
            else:
                status = "true"   

            print("status..:", status)
                  
            wan_intfc_info = get_wan_info()                    
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()
            primary_dns = network_config["network"]["ethernets"]["eth0"]['nameservers']['addresses'][0]
            sec_dns = network_config["network"]["ethernets"]["eth0"]['nameservers']['addresses'][1]
            proto =  network_config["network"]["ethernets"]["eth0"]["dhcp4"]
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
            form = WANSettingsForm(initial = initial_wan_data)     
            return render(request, 'dashetel.html', {'form': form, 'status':status})   

@login_required
def contact(request, tab_name):
    if request.method == 'POST':

        if tab_name == 'register':
            form = RegisterForm(request.POST)  # Handle form submission
            if form.is_valid():
                status = register_post(form)                
                return JsonResponse({'status': status, 'message': 'Registered successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
            
        if tab_name == 'configurewan':
            form = WANSettingsForm(request.POST)  # Handle form submission
            if form.is_valid():
                print("hi")
                status = wan_post(form)                
                return JsonResponse({'status': status, 'message': 'WAN settings updated successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
            
        if tab_name == 'configurelan':
            form = LANSettingsForm(request.POST)  # Handle form submission
            if form.is_valid():
                status = lan_post(form)                
                return JsonResponse({'status': status, 'message': 'LAN settings updated successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
            
        if tab_name == 'timezone':
            form = TimeZoneForm(request.POST)  # Handle form submission
            if form.is_valid():
                selected_time_zone = form.cleaned_data['time_zone']
                os.system(f"timedatectl set-timezone {selected_time_zone}")
                os.system("systemctl restart reachwan.service")
                os.system("systemctl restart reachedge.service")                  
                return JsonResponse({'status': 'success', 'message': 'Time Zone settings updated successfully.'})
            else:
                return JsonResponse({'status': 'error', 'errors': form.errors})
        if tab_name == 'changepassword':
            form = ChangePassword(request.POST)  # Handle form submission
            if form.is_valid():
                new_password = form5.cleaned_data['new_password']
                status = change_password('etel', new_password)
                if status:               
                    return JsonResponse({'status': status, 'message': 'Time Zone settings updated successfully.'})
                else:
                    return JsonResponse({'status': 'error', 'errors': form.errors})
            else:
                    return JsonResponse({'status': 'error', 'errors': form.errors})        

        logfile_content = ["ReachLink is not configured yet"]
        if os.path.exists("/var/log/reachlink.log"):
            with open("/var/log/reachlink.log", "r") as file:
                logfile_content = file.readlines()
                file.close()   
        form = RegisterForm(request.POST)
        form1 = WANSettingsForm(request.POST)
        form2 = LANSettingsForm(request.POST)
        form3 = OptionalAdapterSettingsForm(request.POST)
        form4 = TimeZoneForm(request.POST)
        form5 = ChangePassword(request.POST)
                      
    else:  
        if tab_name == 'register':        
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
            return render(request, 'register.html', {'form': form})   
        elif tab_name == 'configurewan':
            wan_intfc_info = get_wan_info()                    
            with open("/etc/netplan/00-installer-config.yaml", "r") as f:
                network_config = yaml.safe_load(f)
                f.close()
            primary_dns = network_config["network"]["ethernets"]["eth0"]['nameservers']['addresses'][0]
            sec_dns = network_config["network"]["ethernets"]["eth0"]['nameservers']['addresses'][1]
            proto =  network_config["network"]["ethernets"]["eth0"]["dhcp4"]
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
            form = WANSettingsForm(initial = initial_wan_data)
            return render(request, 'configurewan.html', {'form': form})     
        elif tab_name == 'configurelan':
            lan_intfc_info = get_lan_info()
            initial_lan_data = {"ip_address_lan": lan_intfc_info.get("IPv4address_noprefix", "") ,
                            "netmask_lan":lan_intfc_info.get("netmask", "")                      
                            }  
            form = LANSettingsForm(initial = initial_lan_data)
            return render(request, 'configurelan.html', {'form': form})     
        elif tab_name == 'log':         
            logfile_content = ["ReachLink is not configured yet"]
            if os.path.exists("/var/log/reachlink.log"):
                with open("/var/log/reachlink.log", "r") as file:
                    logfile_content = file.readlines()
                    file.close() 
            logfile_content.reverse()  
            return render(request, 'log.html', {'logfile_content':logfile_content})     
        elif tab_name == 'timezone':      
            with open("/etc/timezone", "r") as f:
                time_data1 = f.read()
                f.close()
            time_data = {"current_time_zone":time_data1}
            form = TimeZoneForm(initial = time_data)  
            return render(request, 'timezone.html', {'form': form})   
        elif tab_name == 'diagnostics':        
            form1 = ChangePassword()     
            form2 = PingForm()   
            return render(request, 'diagnostics.html', {'form1': form1, 'form2':form2}) 
           
        elif tab_name == 'routingtable':           
            routing_table = get_routing_table()            
            return render(request, 'routingtable.html', {'routing_table':routing_table})

def ping(request):
    if request.method == 'POST':
        host_ip = request.POST.get('host_ip', None)
        if host_ip:            
            # Perform ping operation
            result = subprocess.run(['ping', '-c', '4', host_ip], capture_output=True, text=True)
            print(result)
            return HttpResponse(result.stdout, content_type='text/plain')
    return HttpResponse(status=400)       


def traceroute(request):
    if request.method == 'POST':
        host_ip = request.POST.get('host_ip', None)
        if host_ip:           
            result1 = subprocess.run(['traceroute', '-d', host_ip], capture_output=True, text=True)
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
