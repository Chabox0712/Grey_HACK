//command: nmap
clear_screen
if params.len < 1 or params.len > 2 or params[0] == "-h" or params[0] == "--help" then exit("x [-h --help] [x IP_ADDRESS all]")	
if not is_valid_ip(params[0]) then exit("nmap: invalid ip address")
if not get_shell.host_computer.is_network_active then exit("nmap: No internet access.")
ipAddress = params[0]
isLanIp = is_lan_ip( ipAddress )
if isLanIp then
   router = get_router;
else 
   router = get_router( ipAddress )
end if
if router == null then exit("nmap: ip address not found")
ports = null
if not isLanIp then
   ports = router.used_ports
else
   ports = router.device_ports(ipAddress)
end if
if ports == null then exit("nmap: ip address not found")
if typeof(ports) == "string" then exit(ports)   
info = "<b>PORT STATE SERVICE VERSION LAN"   
print("\nStarting nmap v1.1 at " + current_date)
print("Interesting ports on " + params[0] + "\n")
if(ports.len == 0) then print("Scan finished. No open ports.")
for port in ports
   service_info = router.port_info(port)
   lan_ips = port.get_lan_ip
   port_status = "open"
   if(port.is_closed and not isLanIp) then
      port_status = "closed"
   end if
   info = info + "\n" + port.port_number + " " + port_status + " " + service_info + " " + lan_ips
end for
print(format_columns(info))
if params.len == 1 then exit
if params[1] == "all" then
print("\n<b> <<<<==== All Devices =====>>>>")
ips = router.devices_lan_ip
routers = []
i = 0
for ip in ips
	switch = get_switch(ip)
	if switch != null then
		i = i+1
		print("<color=red><b>["+i+"] <<<<=== Switch at : <color=white>"+switch.local_ip+"<color=red> ===>>>>")
		rules = switch.firewall_rules
		if not rules then print("<b><color=blue>FIREWALL STATUS : <color=white>NONE")
		info = "<b><color=blue>ACTION PORT SOURCE_IP DESTINATION_IP"
		for rule in rules
			info = info+"\n<b><color=white>"+rule
		end for
		if rules then print(format_columns(info))
		routers = switch
	end if
	if not switch then
		if routers then
			i = i+1
			print("<color=red><b>["+i+"] Router at : <color=white>"+routers.local_ip+"<color=red> ===>>>>")
			rules1 = routers.firewall_rules
			if not rules1 then print("<b><color=blue>FIREWALL STATUS : <color=white>NONE")
			info = "<b><color=blue>ACTION PORT SOURCE_IP DESTINATION_IP"
			for rule in rules1
				info = info+"\n<b><color=white>"+rule
			end for
			if rules1 then print(format_columns(info))
		end if
		if not routers then
			routers = get_router(ip)
			if routers then
				i = i+1
				print("<color=red><b>["+i+"] Router at : <color=white>"+routers.local_ip+"<color=red> ===>>>>")
				rules2 = routers.firewall_rules
				if not rules2 then print("<b><color=blue>FIREWALL STATUS : <color=white>NONE")
				info = "<b><color=blue>ACTION PORT SOURCE_IP DESTINATION_IP"
				for rule in rules2
					info = info+"\n<b><color=white>"+rule
				end for
				if rules2 then print(format_columns(info))
			end if
		end if
		ips_ = []
		if routers != null or switch != null then
			ips_ = routers.devices_lan_ip
		end if
		if ips_ != [] then
			for p in ips_
				pots = routers.device_ports(p)
				if not pots then
					print("<b>"+p+" <color=red>No Ports")
					continue
				end if
				for pot in pots
					if pot.len == 1 then
						continue
					end if
					if pot == null then continue
					if pot then
						if(pot.is_closed and not isLanIp) == true then
							print("<b>"+p+" ["+pot.port_number+"] <b><color=red>CLOSED")
						else
							print("<b>"+p+" ["+pot.port_number+"] <b><color=yellow>OPEN")	
						end if
					end if
				end for
			end for
			continue
		end if
		continue
	end if
	continue
	ports = router.device_ports(ip)
	if not ports then
		print("<b>"+ip+" <color=red>No Ports")
		continue
	end if
	for port in ports
		if port then
			if (port.is_closed and not isLanIp) == true then
				print("<b>"+ip+" ["+port.port_number+"] <b><color=red>CLOSED")
			else
				print("<b>"+ip+" ["+port.port_number+"] <b><color=yellow>OPEN")	
			end if
		end if
	end for
end for
end if
print("\n<b> <<<<==== Additional INFO =====>>>>")
print("<color=blue>BSSID => [<b> "+router.bssid_name+" </b>]")
print("<color=blue>ESSID => [<b> "+router.essid_name+" </b>]")
print("<color=blue>Router_Version => [<b> "+router.kernel_version+" </b>]")
print("<color=blue>Local_Ip_Address => [<b> "+router.local_ip+" </b>]")
print("<color=blue>Public_Ip_Address => [<b> "+router.public_ip+" </b>]")
//router = get_router (params[0])
