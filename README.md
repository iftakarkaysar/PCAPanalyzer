# PCAPanalyzer / PWNShark

A python script built with Pyshark to parse PCAP files and detect malicious behavior and cyberattacks.
By leveraging the pyshark library- PWNshark is able to parse through a pcap file and search for malicious behaviors and IOC's
The motivation for this project was to create a script that analysts could use in order to get summarized high level view on what’s taking place in a large set of data before actually getting into the file.


The Process:
We first had to decide what malicious traffic looked like. How could we identify IOC's in a network packet capture amongst all the noise
So we started small and defined the characteristics of a port scan and how we could locate it. 
We know that port scan works when a single IP address sends multiple syn packets to another IP address and to multiple Unique ports.
So our first detection in pwnshark was to create a data structure of IP address and attributes connected to their traffic. Which IP's are they talking too?
What ports are they connecting to? How often are they sending traffic. 
By setting these conditions the script is now able to detect and display possible port scans.
We also used a similar method to detect Brute force login attempts. Setting conditions to detect anomalous behavior sent to a single port such as port 22 for ssh. 

We were also able to parse the HTTP requests from the internet traffic. This allowed us to scan the uri parameters for get reuests  use regular expressions or even just hard code to search for common character signatures related to sql injections, cross site scripting, and directory traversals. 

Data Visualization:
PWNShark is also able to create graphs that display the syn packet density by time. This gives a visual representation of what’s happening with all the requests and traffic.
