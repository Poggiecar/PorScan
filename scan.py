#!/user/bin/python3

import nmap



print("  [] Herramienta para escanear puertos abiertos en una direccion IP")
print("  [] Escrita en Python con Sublime, utiliza Nmap")
print("  [] Proximamente nuevas veriones")

nombre_escaneo= input ("[+] Nombre del escaneo: ")
ip= input("[+] Ip objetivo: ")
nm= nmap.PortScanner()
results= nm.scan(ip)
puertos_abiertos="-p"
count=0
results= nm.scan(hosts=ip, arguments=" -sT -n -Pn -T3 ")
print("\nHost : %s" % ip)
print("State : %s" % nm[ip].state())
for proto in nm[ip].all_protocols():
    print("Protocol : %s" % proto)
    lport = nm[ip][proto].keys()
    sorted(lport)
    for port in lport:
        print ('port : %s\tstate : %s' % (port, nm[ip][proto][port]['state']))
        if count==0:
            puertos_abiertos= puertos_abiertos + " " + str(port)
            count=1
        else:
            puertos_abiertos= puertos_abiertos + "," + str(port)

print("Puertos abiertos: "+puertos_abiertos+ " " + str(ip)) 	
print("Escaneo con Scripts y versiones: nmap -sC -sV "+puertos_abiertos + " " + str(ip) + " -oN "+ str(nombre_escaneo)+".txt")
print("Escaneo sigiloso sin ping y fragmentacion de paquetes: nmap -T3 -Pn -f " + puertos_abiertos + "" + str(ip) + "-oN" + str(nombre_escaneo)+".txt")
print("Para mas informacion sobre la herramienta visita https://nmap.org/book/man.html")



#print(results)