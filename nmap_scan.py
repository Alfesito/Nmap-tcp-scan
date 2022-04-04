import nmap # https://pypi.org/project/python-nmap/
import os

import itertools
import threading
import time
import sys

#INPUTS
print("TCP connect scan")
ip = input("[+] Introduce la IP objetivo: ")

dirsearch_ports = list()

done = False
# Scan animation
def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rScanning TCP ports ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    #sys.stdout.write('\rDone!     ')


#DEFINICIÓN Y DECLARACIÓN DE FUNCIONES
def nmap_func(ip, args): # TCP-connect()
	open_ports="-p "
	count = 0
	nm = nmap.PortScanner()
	results = nm.scan(hosts=ip, arguments=args)
	print("Host : %s" % ip)
	print("State : %s" % nm[ip].state())
	for proto in nm[ip].all_protocols():
		print("Protocol : %s" % proto)
		print()
		lport = nm[ip][proto].keys()
		sorted(lport)
		for port in lport:
			print("Port: %s\tState: %s\tProtc: %s\tVersion: %s" % (port, nm[ip][proto][port]["state"],nm[ip][proto][port]["name"],nm[ip][proto][port]["version"]))
			if count==0:
				open_ports=open_ports+str(port)
				count=1
			else:
				open_ports=open_ports+","+str(port)
		print("\nOpen ports: "+ open_ports +" "+str(ip))

def dirsearch(ip,ports):
	os.system("python3 dirsearch.py -u http://%s:%s -e php,html" % (ip,ports))

if (True):
	args = "-sT -n -sV -Pn"
	t = threading.Thread(target=animate)
	t.start()
	#Long process here
	nmap_func(ip, args)
	done = True
	print("")

	ds=input("\n[+] Do you want to dirsearch a port?(Y/n): ")
	while (ds.lower()=="y"):
		if(ds.lower() == "y"):
			try:
				dp=int(input("[+] What port do you want to dirsearch (extensions: php,html)?: "))
				if(type(dp)==int):
					dirsearch(ip,dp)
					ds=input("[+] Do you want to dirsearch other port?(Y/n): ")
			except:
				print("The port must be an INTERGER!!!\n")
				ds=input("[+] Do you want to dirsearch other port?(Y/n): ")
else:
	print("Only TCP")

print("End of scan. Good luck:)")

