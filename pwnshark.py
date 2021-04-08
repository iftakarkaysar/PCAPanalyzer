#!/usr/bin/env python3

import pyshark
import sys
import time
from datetime import datetime
import math
import numpy as np
import matplotlib.pyplot as plt
import re
import itertools
import pyfiglet
import statistics
import warnings


#pfile = sys.argv[1]
#cap = pyshark.FileCapture(pfile)
all_ips = {} #Dictionary of all IP information captured from scan.
syn_count = 0
sus_packs = []
sus_http = []

dirtrav = '../../'
sql_inj = ['SELECT', 'load_file', 'union']


####### Initial pcap scan #######
def synport(cap):
    x = cap
    for packet in x:
        try:
            src = packet['ip'].src
            dst = packet['ip'].dst
            src_flag = packet['tcp'].flags
            dst = packet['ip'].dst
            dst_port = packet['tcp'].dstport
            numb = packet.number.show
            #Analyze if packet is a syn packet                     
            if src_flag == '0x00000002':
                if src not in all_ips:
                    all_ips[src] = {}
                    all_ips[src]['syn'] = 1
                    all_ips[src]['ports'] = []
                    all_ips[src]['packs'] = []
                    all_ips[src]['packs'].append(numb)
                    all_ips[src]['dst'] = []
                    all_ips[src]['dst'].append(dst)
           
                elif src in all_ips:
                    all_ips[src]['syn'] += 1
                    all_ips[src]['ports'].append(dst_port)
                    all_ips[src]['packs'].append(numb)
                    all_ips[src]['dst'].append(dst)
            if dst_port == '80':
                uri_p = packet.http.request_uri_query_parameter
                uri = packet.http.request_uri      
                if dirtrav in uri_p:
                    print('####Directory Traversal Detected####')
                    print('Investigate Packet: {0}'.format(numb))
                    print('Possible Attacker IP: {0}'.format(src))
                    print('Possible Victim IP: {0}'.format(dst))
                

                for x in sql_inj:
                    if x.lower() in uri_p.lower():
                        print('####Possible SQL Injection Detected####')
                        print('Investigate Packet: {0}'.format(numb))
                        print('Possible Attacker IP: {0}'.format(src))
                        print('Possible Victim IP: {0}'.format(dst))



            if dst_port == '445':
                if src not in all_ips:
                    all_ips[src]['ports'] = []
                    all_ips[src]['ports'].append(dst_port)
                elif src in all_ips:
                    all_ips[src]['ports'].append(dst_port)

            if dst_port == '389':
                 if src not in all_ips:
                     all_ips[src]['ports'] = []
                     all_ips[src]['ports'].append(dst_port)
                 elif src in all_ips:
                     all_ips[src]['ports'].append(dst_port)
            

        except:
            pass


    

###### Analyzing IP Dictionary statistics and funneling for anamolies ######
    for ip in all_ips:
       # print('Accessing all malicious IP Activity')

        ports = all_ips[ip]['ports']
        unique_list = []

        for x in ports:
            if x not in unique_list:
                unique_list.append(x)

        uniq_p = len(all_ips[ip]['ports'])
        uniq_s = len(unique_list)
        ssh_count = all_ips[ip]['ports'].count('22')
        ftp_count = all_ips[ip]['ports'].count('21')
        ldap_count = all_ips[ip]['ports'].count('389')
        smb_count = all_ips[ip]['ports'].count('445')
        victim_l = all_ips[ip]['dst']
        victim = max(victim_l,key=victim_l.count)
####### If the IP scanned over 100 Unique ports, flag as suspicious #######
        if uniq_s > 100:
            print('Possible Port Scan from IP: ' + ip)
            print('{0} unique ports have been scanned'.format(uniq_p))
            pack_1 = all_ips[ip]['packs'][0]
            pack_2 = len(all_ips[ip]['packs']) - 1
            print('Suspicious Packets: {0} ==> {1}'.format(pack_1,pack_2))
            print('Possible Victim IP: {0}'.format(victim))
##### Nmap scan type processsor ########
            if uniq_s > 900:
                print("Nmap Scan Type: Top 1000")
            elif uniq_s > 500:
                print("Nmap Scan Type: Top 500")
            elif uniq_s >= 100:
                print("Nmap Scan Type: Top 100")

 ######SSH Brute Force counter #######   
        if ssh_count > 15:
            print("Possible SSH Brute Force Detected")
            print("{0} has failed to login {1} times".format(ip, ssh_count))
            print('Possible Victim IP: {0}'.format(victim))

        if ftp_count > 15:
            print("Possible FTP Brute Force Detected")
            print("{0} has failed to login {1} times".format(ip, ftp_count))
            print('Possible Victim IP: {0}'.format(victim))

        if ip in sus_http:
            print(all_ips[ip]['uri_req'])

        if smb_count > 75:
            print('Possible SMB Enumeration Detected')
            print('{0} Requests sent to port 445 from {1}'.format(smb_count, ip))
            print('Possible Victim IP: {0}'.format(victim))

        if ldap_count > 75:
            print('Possible LDAP Enumeration Detected')
            print('{0} Requests sent to port 389 from {1}'.format(ldap_count, ip))
            print('Possible Victim IP: {0}'.format(victim))


### Goal: segment pcap file into equal or near-equal blocks ###

# define a function that returns all packets
def all_packets_ftp(cap, block_size, IP):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of ftp-existence list
	ftp_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of ftp request
			### ftp requests are separated into Client & Server
			### 	So add focus on attacker	
			# pull out ftp protocol markers
			if (str(packet.tcp.dstport) == '20' or str(packet.tcp.dstport)=='21') and (str(packet.ip.dst) == str(IP)) :
				ftp_exist.append('1')			
			else:
				ftp_exist.append('0')
				pass

		except AttributeError:
			ftp_exist.append('0')			
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = ftp_exist
	#print("ftp Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of ftp requests in whole packet
	Num_ftp = ftp_exist.count('1')
	#print(Num_ftp)
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap ftp density
	pcap_ftp_density = Num_ftp/pcap_time_range
	# calculate probability of finding ftp request in whole packet
	Prob_whole = Num_ftp / len(ftp_exist)
	# calculate entropy of whole capture file
	#Entr_whole = -(Prob_whole * math.log((Prob_whole),2))
	# calculate entropy density per time for pcap
	#Entr_pcap_density = Entr_whole/pcap_time_range
	# print number of ftps in, probability of ftps in, and entropy of: whole capture file
	print("\n")	
	print("============================================================")
	print("\n")
	print(f"Number of ftp Requests in PCAP: {Num_ftp}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"ftp density per time for this pcap is {pcap_ftp_density}")
	print(f"Probability of ftp Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive 1/q% increment block segments of ftp requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q (number chosen)
	# FIXED in lines 147 -> 160
	block_size = int(math.floor(len(a)/q)) # make block size to be user-defined input *SAME FOR LINE 124*
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		ftp_block = a[element-block_size:element]
		#print("current ftp_block is:", ftp_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		ftp_exist_block  = d[element-block_size:element]
		#print("current ftp_exist_block is:", ftp_exist_block)
		
		running_total += len(ftp_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == int(q): # make count to be user-defined input *SAME FOR LINE 96*
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				ftp_block.append(nums)
			### same for missing "ones" in ftp existence block
			for nims in d[-(extra):]:
				ftp_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(ftp_block)==len(ftp_exist)==len(time_block)
			except:
				break
			
		Num_ftp_sub = ftp_exist_block.count('1')
		#print(f"Number of ftp Requests in block: {Num_ftp_sub}")
		
		packet_range = f"{ftp_block[0]} -> {ftp_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		ftp_density = Num_ftp_sub/time_range
		#print(f"ftp density per time for this block is {ftp_density}")

		Prob_block = Num_ftp_sub / len(ftp_block)
		#print(f"Probability of ftp Requests in block: {Prob_block}")

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be ftp_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		x.append(ftp_block[-1])
		y.append(ftp_density)
		#z.append(Entr_density)
		######################
		
	######################
	global t
	t = x
	global u
	u = y
	#print(t, 't')
	#print(u, 'u')
	
def all_packets_ssh(cap, block_size, IP):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of ssh-existence list
	ssh_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of ssh request
			### SSH requests are separated into Client & Server
			### 	So add focus on attacker	
			# pull out ssh protocol markers
			if (str(packet.tcp.dstport) == '22') and (str(packet.ip.dst) == str(IP)) :
				ssh_exist.append('1')			
			else:
				ssh_exist.append('0')
				pass

		except AttributeError:
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = ssh_exist
	#print("ssh Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of SSH requests in whole packet
	Num_ssh = ssh_exist.count('1')
	#print(Num_ssh)
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap ssh density
	pcap_ssh_density = Num_ssh/pcap_time_range
	# calculate probability of finding SSH request in whole packet
	Prob_whole = Num_ssh / len(ssh_exist)
	# calculate entropy of whole capture file
	#Entr_whole = -(Prob_whole * math.log((Prob_whole),2))
	# calculate entropy density per time for pcap
	#Entr_pcap_density = Entr_whole/pcap_time_range
	# print number of SSHs in, probability of SSHs in, and entropy of: whole capture file
	print(f"Number of SSH Requests in PCAP: {Num_ssh}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"ssh density per time for this pcap is {pcap_ssh_density}")
	print(f"Probability of SSH Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive 1/q% (or other) increment block segments of ssh requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q (number chosen)
	# FIXED in lines 147 -> 160
	block_size = int(math.floor(len(a)/q)) # make block size to be user-defined input
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		ssh_block = a[element-block_size:element]
		#print("current ssh_block is:", ssh_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		ssh_exist_block  = d[element-block_size:element]
		#print("current ssh_exist_block is:", ssh_exist_block)
		
		running_total += len(ssh_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == q: # make count to be user-defined input
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				ssh_block.append(nums)
			### same for missing "ones" in ssh existence block
			for nims in d[-(extra):]:
				ssh_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(ssh_block)==len(ssh_exist)==len(time_block)
			except:
				break
			
		Num_ssh_sub = ssh_exist_block.count('1')
		#print(f"Number of SSH Requests in block: {Num_ssh_sub}")
		
		packet_range = f"{ssh_block[0]} -> {ssh_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		ssh_density = Num_ssh_sub/time_range
		#print(f"ssh density per time for this block is {ssh_density}")

		Prob_block = Num_ssh_sub / len(ssh_block)
		#print(f"Probability of SSH Requests in block: {Prob_block}")

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be ssh_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		#x.append(ssh_block[-1])
		y.append(ssh_density)
		#z.append(Entr_density)
		######################
		
	global v
	v = y
	#print(v, 'v')

def all_packets_syn(cap, block_size, IP):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of syn-existence list
	syn_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of SYN request
			### SYN requests naturally filter out response flags,
			### 	allowing focus on attacker	
			# pull out tcp protocol flag
			tcp_src_flag = packet['tcp'].flags
			# if protocol flag is a SYN
			if (tcp_src_flag == '0x00000002') and (str(packet.ip.dst) == str(IP)) :
				# append 1			
				syn_exist.append('1')
			# if not a SYN flag
			else:
				# append 0
				syn_exist.append('0')
		except AttributeError:
			# pull out udp protocol flag
			udp_src_flag = packet.udp
			syn_exist.append('0')	
		
		except:
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = syn_exist
	#print("Syn Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of SYN requests in whole packet
	Num_syn = syn_exist.count('1')
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap syn density
	pcap_syn_density = Num_syn/pcap_time_range
	# calculate probability of finding SYN request in whole packet
	Prob_whole = Num_syn / len(syn_exist)
	# print number of SYNs in, probability of SYNs in, and entropy of: whole capture file
	print(f"Number of SYN Requests in PCAP: {Num_syn}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"syn density per time for this pcap is {pcap_syn_density}")
	print(f"Probability of SYN Requests in PCAP: {Prob_whole}")

	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive q% increment block segments of syn requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q
	# FIXED in lines 174 -> 188
	block_size = int(math.floor(len(a)/q)) 
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		syn_block = a[element-block_size:element]
		#print("current syn_block is:", syn_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		syn_exist_block  = d[element-block_size:element]
		#print("current syn_exist_block is:", syn_exist_block)
		
		running_total += len(syn_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == int(q):
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				syn_block.append(nums)
			### same for missing "ones" in syn existence block
			for nims in d[-(extra):]:
				syn_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(syn_block)==len(syn_exist)==len(time_block)
			except:
				break
			
		Num_syn_sub = syn_exist_block.count('1')
		#print(f"Number of SYN Requests in block: {Num_syn_sub}")
		
		packet_range = f"{syn_block[0]} -> {syn_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		syn_density = Num_syn_sub/time_range
		#print(f"syn density per time for this block is {syn_density}")

		Prob_block = Num_syn_sub / len(syn_block)
		#print(f"Probability of SYN Requests in block: {Prob_block}")
		

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be syn_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		#x.append(syn_block[-1])
		y.append(syn_density)
		#z.append(Entr_density)
		######################
	
	global w
	w = y
	#print(w, 'w')
#######################
# define a function that returns all packets
### goal: look for large data exfil spikes
### calculate data size of each packet
### add data packets in packet range
### calculate time range
### divide data sum in packet range by diff in timerange associated with same packet range
### count number of hexdump characters
### OR  pkt.captured_length for number of bytes in packet
### look at pkt.captured_length.startswith/endswith
#######################
def data_exfil(cap, block_size, IP):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of packet size
	pkt_size = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)			
			# choose IP address
			if str(packet.ip.src) == str(IP):
				# create list of packet sizes
				pkt_size.append(int(packet.captured_length))
			else:
				pkt_size.append(0)
		except:	
			pkt_size.append(0)		
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = pkt_size
	#print("Packet Sizes:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# add data sizes together for whole pcap
	data_pcap = sum(pkt_size)
	#print(data_pcap)
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap data time density
	pcap_data_time_density = data_pcap / pcap_time_range
	# calculate density of data in whole pcap
	pcap_whole = data_pcap / len(pkt_size)
	
	print(f"Total data transferred in PCAP: {data_pcap}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"Data time density for this pcap is {pcap_data_time_density} bytes per second")
	print(f"Density of data in PCAP: {pcap_whole} bytes per packet")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive 1/q% increment block segments of ftp requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q (number chosen)
	block_size = int(math.floor(len(a)/q)) # make block size to be user-defined input 
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		data_block = a[element-block_size:element]
		#print("current data_block is:", data_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		pkt_size_block  = d[element-block_size:element]
		#print("current pkt_size_block is:", pkt_size_block)
		
		running_total += len(data_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == int(q): # make count to be user-defined input *SAME FOR LINE 96*
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				data_block.append(nums)
			### same for missing "ones" in ftp existence block
			for nims in d[-(extra):]:
				pkt_size_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(data_block)==len(pkt_size)==len(time_block)
			except:
				print("block size mismatch")				
				break
			
		data_pcap_sub = sum(pkt_size_block)
		#print(f"Amount of data transfer in block: {data_pcap_sub}")
		
		packet_range = f"{data_block[0]} -> {data_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		data_time_density = data_pcap_sub/time_range
		#print(f"data density per time for this block is {data_time_density}")

		data_block_density = data_pcap_sub / len(data_block)
		#print(f"Density of Data in block: {data_block_density}")

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be ftp_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		x.append(data_block[-1])
		y.append(data_time_density)
		######################
		#break
	######################
	global m	
	m = y
	

def all_packets_ldap(cap, block_size, IP):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of ldap-existence list
	ldap_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of LDAP request
			### LDAP requests naturally filter out response flags,
			### 	allowing focus on attacker	
			# pull out tcp protocol flag
			if (str(packet.tcp.srcport) == '389') and (str(packet.ip.src) == str(IP)):
				ldap_exist.append('1')			
			else:
				ldap_exist.append('0')
				pass
		except AttributeError:
			ldap_exist.append('0')	
		
		except:
			ldap_exist.append('0')	
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = ldap_exist
	#print("Syn Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of LDAP requests in whole packet
	Num_ldap = ldap_exist.count('1')
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap ldap density
	pcap_ldap_density = Num_ldap/pcap_time_range
	# calculate probability of finding LDAP request in whole packet
	Prob_whole = Num_ldap / len(ldap_exist)
	# print number of LDAPs in, probability of LDAPs in, and entropy of: whole capture file
	print(f"Number of LDAP Requests in PCAP: {Num_ldap}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"ldap density per time for this pcap is {pcap_ldap_density}")
	print(f"Probability of LDAP Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive q% increment block segments of ldap requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q
	# FIXED in lines 174 -> 188
	block_size = int(math.floor(len(a)/q)) 
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		ldap_block = a[element-block_size:element]
		#print("current ldap_block is:", ldap_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		ldap_exist_block  = d[element-block_size:element]
		#print("current ldap_exist_block is:", ldap_exist_block)
		
		running_total += len(ldap_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == int(q):
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				ldap_block.append(nums)
			### same for missing "ones" in ldap existence block
			for nims in d[-(extra):]:
				ldap_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(ldap_block)==len(ldap_exist)==len(time_block)
			except:
				break
			
		Num_ldap_sub = ldap_exist_block.count('1')
		#print(f"Number of LDAP Requests in block: {Num_ldap_sub}")
		
		packet_range = f"{ldap_block[0]} -> {ldap_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		ldap_density = Num_ldap_sub/time_range
		#print(f"ldap density per time for this block is {ldap_density}")

		Prob_block = Num_ldap_sub / len(ldap_block)
		#print(f"Probability of LDAP Requests in block: {Prob_block}")
		

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be ldap_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		#x.append(ldap_block[-1])
		y.append(ldap_density)
		#z.append(Entr_density)
		######################
	
	######################
	global lda	
	lda = y

def all_packets_smb(cap, block_size, IP):
	q = block_size
	# initialize list of all packet numbers
	pkts = []
	# initialize list of all timestamps
	timestamps = []
	# initialize list of smb-existence list
	smb_exist = []
	# loop through packets in capture file, one by one
	for packet in cap:	
		try:		
			# find pcap-generated packet ordinal number	
			numb = packet.number.show
			# append associated packet ordinal number			
			pkts.append(numb)
			# define packet timestamp
			src_time = packet.sniff_timestamp
			# append associated timestamp
			timestamps.append(src_time)
			### create list of 1s and 0s that correspond to existence of SMB request
			### SMB requests naturally filter out response flags,
			### 	allowing focus on attacker	
			# pull out tcp protocol flag
			if (str(packet.tcp.srcport)) == '445' and (str(packet.ip.src) == str(IP)):
				smb_exist.append('1')			
			else:
				smb_exist.append('0')
				pass
		except AttributeError:
			smb_exist.append('0')	
		
		except:
			smb_exist.append('0')	
			pass
	a = pkts
	#print("all packets:", a)
	b = timestamps # datetime.datetime objects
	#print("Timestamps:", b)
	d = smb_exist
	#print("Syn Existence:", d)
	### replace each datetime.datetime list object 
	### with difference of that list object with first list object
	c = []
	c.append(float(0))
	[c.append(float(b[i]) - float(b[0])) for i in range(1,len(b))]
	#print("Relative Timestamps:", c)
	
	# Count number of SMB requests in whole packet
	Num_smb = smb_exist.count('1')
	# calculate whole pcap packet range
	pcap_range = f"{a[0]} -> {a[-1]}"
	# calculate time elapsed for entire pcap
	pcap_time_range = c[-1] - c[0]
	# calculate pcap smb density
	pcap_smb_density = Num_smb/pcap_time_range
	# calculate probability of finding SMB request in whole packet
	Prob_whole = Num_smb / len(smb_exist)
	# calculate entropy of whole capture file
	# print number of SMBs in, probability of SMBs in, and entropy of: whole capture file
	print(f"Number of SMB Requests in PCAP: {Num_smb}")
	print(f"pcap_range is {pcap_range}")
	print(f"Time elapsed for this pcap is: {pcap_time_range} seconds")
	print(f"smb density per time for this pcap is {pcap_smb_density}")
	print(f"Probability of SMB Requests in PCAP: {Prob_whole}")
	#print(f"Entropy of PCAP: {Entr_whole}")
	#print(f"Entropy density per time for PCAP is: {Entr_pcap_density}")
	print("\n")	
	print("============================================================")
	print("\n")
	######################
	######################
	### From beginning of packet capture	
	### take consecutive q% increment block segments of smb requests
	### and analyze each block segment individually
	### if not suspicious: discard, and move to next block
	### if suspicious: give alert, and move to next block
	#######################
	# segment automatically
	pcap_length = int(len(a)+1)
	# WARNING: leaves off ending packets if pcap not divisible by q
	# FIXED in lines 174 -> 188
	block_size = int(math.floor(len(a)/q)) 
	# initialize graph x values
	x = []	
	# initialize graph y values
	y = []
	# initialize graph z values
	z = []	
	# initialize running total of pcap length
	running_total = 0
	# intialize counter to keep track of what block loop is on
	count = 0
	for element in range(block_size, pcap_length, block_size):
		sub_block=list(range(element-block_size,element)) 
		#print("current sub_block is:", sub_block)
		
		smb_block = a[element-block_size:element]
		#print("current smb_block is:", smb_block)
		
		time_block = c[element-block_size:element]
		#print("current time_block is:", time_block)
		
		smb_exist_block  = d[element-block_size:element]
		#print("current smb_exist_block is:", smb_exist_block)
		
		running_total += len(smb_block)
		count += 1
		extra = len(a) - running_total
		### if total length of all blocks does not equal length of pcap file
		if running_total != len(a) and count == int(q):
			### then append the missing packets to the most recent block
			for nums in a[-(extra):]:
				smb_block.append(nums)
			### same for missing "ones" in smb existence block
			for nims in d[-(extra):]:
				smb_exist_block.append(nims)
			### same for missing time block
			for noms in c[-(extra):]:
				time_block.append(noms)
			try: 
				len(smb_block)==len(smb_exist)==len(time_block)
			except:
				break
			
		Num_smb_sub = smb_exist_block.count('1')
		#print(f"Number of SMB Requests in block: {Num_smb_sub}")
		
		packet_range = f"{smb_block[0]} -> {smb_block[-1]}"
		#print(f"packet_range is {packet_range}")

		time_range = time_block[-1] - time_block[0]
		#print(f"Time elapsed for this block is: {time_range}")
		
		smb_density = Num_smb_sub/time_range
		#print(f"smb density per time for this block is {smb_density}")

		Prob_block = Num_smb_sub / len(smb_block)
		#print(f"Probability of SMB Requests in block: {Prob_block}")
		

		######################
		######################
		### make probability graph with x values to be packet numbers
		### and y values to be smb_density per time
		### entropy graph with x values to be packet numbers
		### and z values to be entropy density per time
		######################
		### add plotting here
		#x.append(smb_block[-1])
		y.append(smb_density)
		#z.append(Entr_density)
		######################
	
	######################
	global smb	
	smb = y

def print_func(ticks, IP):
	warnings.filterwarnings("ignore")
	q = ticks	
	#######################
	# print all 3 outputs 
	global t
	global u
	global v
	global w
	global m
	global lda
	global smb
	
	#print(m, "m")
	#print(M, "M")
	max_y1 = (1.25)*max(max(u),max(v),max(w))
	max_y2 = (1.25)*max(m)
	max_y4 = (1.25)*max(lda)
	max_y5 = (1.25)*max(smb)

	plt.subplot(3,2,1)
	plt.ylim(0,max_y1)
	plt.bar(t,u, align='edge', width=-1.0, alpha=0.5, label = str(IP) + 'Inbound FTP Density per time')
	plt.legend(loc='best')
	
	plt.grid(axis = 'x', color = 'black', linestyle = '--', linewidth = 0.25)

	plt.subplot(3,2,3)
	plt.ylim(0,max_y1)
	plt.bar(t,v, align='edge', width=-1.0, alpha=0.5, label = str(IP) + 'Inbound SSH Density per time')
	plt.legend(loc='best')

	plt.grid(axis = 'x', color = 'black', linestyle = '--', linewidth = 0.25)

	plt.subplot(3,2,5)
	plt.ylim(0,max_y1)
	plt.bar(t,w, align='edge', width=-1.0, alpha=0.5, label = str(IP) + ' Inbound SYN Density per time')
	plt.legend(loc='best')
	plt.xticks(rotation=45)
	plt.grid(axis = 'x', color = 'black', linestyle = '--', linewidth = 0.25)

	plt.subplot(3,2,2)
	plt.ylim(0,max_y2)
	plt.bar(t,m, align='edge', width=-1.0, alpha=0.5, label = str(IP) + ' Outbound Data Density per time (Bytes/second)')
	plt.legend(loc='best')	
	
	plt.grid(axis = 'x', color = 'black', linestyle = '--', linewidth = 0.25)

	plt.subplot(3,2,4)
	plt.ylim(0,max_y4)
	plt.bar(t,lda, align='edge', width=-1.0, alpha=0.5, label = str(IP) + ' Outbound LDAP Density per time')
	plt.legend(loc='best')	
	
	plt.grid(axis = 'x', color = 'black', linestyle = '--', linewidth = 0.25)

	plt.subplot(3,2,6)
	plt.ylim(0,max_y5)
	plt.bar(t,smb, align='edge', width=-1.0, alpha=0.5, label = str(IP) + ' Outbound SMB Density per time')
	plt.legend(loc='best')
	plt.xticks(rotation=45)
	plt.grid(axis = 'x', color = 'black', linestyle = '--', linewidth = 0.25)
	
	plt.xlabel('Packet Ranges')
	plt.subplots_adjust(hspace = .1)
	out = plt.show()

######################
### Run Program
######################
if __name__ == "__main__":
	# start timer
	begin = time.time()	
	# take user input and output to file variable
	f = sys.argv[1]
	cap = pyshark.FileCapture(f)
	#######################
	# check for .pcap ending
	if f.lower().endswith(('.pcap','.pcapng')):
		# add user defined granularity
		p = 0
		while p <= 1:		
			p = int(input("Enter integer number of sub-divisions for graphs: "))
			if p == 0:		
				print("please input a positive value")
			elif p == 1:
				print("please choose at least 2 sub-divisions")
			elif p > 1:		
				print("\n")	
				print("============================================================")
				print("\n")
				#######################
				# use ascii text
				ascii_banner=pyfiglet.figlet_format("pWn ShARk")
				print(ascii_banner)
				#######################
				print("\n")	
				print("============================================================")
				print("\n")
				#######################	
				# run synport function
				synport(cap)
				#######################
				print("\n")	
				print("============================================================")
				print("\n")
				#######################	
				IP = (input("Please input IP address to analyze: "))
				# run ftp packets function	
				all_packets_ftp(cap,p, IP)
				# run ssh output function	
				all_packets_ssh(cap,p, IP)
				# run syn output function
				all_packets_syn(cap,p, IP)
				# run smb output function
				all_packets_smb(cap, p, IP)
				# run ldap output function
				all_packets_ldap(cap, p, IP)
				# run data exfil function
				data_exfil(cap, p, IP)
				# end timer
				end = time.time()
				# show runtime
				print(f"Sharks Pwned in {end - begin} seconds")
				# run print function
				print_func(p, IP)
	else:
		print("Please input a pcap or pcapng file")
