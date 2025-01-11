"""
URL configuration for linkgui project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from link.views import addroute, download_logfile, delroute, checksubnet, changedefaultgw
from link.views import delete, update, traceroute_spoke, lan_config, lan_info, dhcp_config, add_ip_rule, get_routing_table, get_interface_details, create_vlan_interface, interface_config, vlan_interface_delete, addstaticroute, getpbrinfo
from django.views.generic import RedirectView
urlpatterns = [
    path('delete', delete, name='delete'),
    path('lan_config', lan_config, name='lan_config'),
    path('lan_info', lan_info, name='lan_info'),
    path('dhcp_config', dhcp_config, name='dhcp_config'),
    path('update', update, name='update'),
    path('traceroute_spoke', traceroute_spoke, name='traceroute_spoke'),    
    path('addroute', addroute, name='addroute'),
    path('delroute', delroute, name='delroute'),
    path('checksubnet', checksubnet, name='checksubnet'),
    path('changedefaultgw', changedefaultgw, name='changedefaultgw'),
    path('download-log/', download_logfile, name='download_logfile'),
    path('add_ip_rule', add_ip_rule, name='add_ip_rule'),
    path('get_routing_table', get_routing_table, name='get_routing_table'),
    path('get_interface_details', get_interface_details, name='get_interface_details'),
    path('create_vlan_interface', create_vlan_interface, name='create_vlan_interface'),
    path('interface_config', interface_config, name='interface_config'),
    path('vlan_interface_delete', vlan_interface_delete, name='vlan_interface_delete'),
    path('addstaticroute', addstaticroute, name='addstaticroute'),
    path('getpbrinfo', getpbrinfo, name='getpbrinfo'),
]
