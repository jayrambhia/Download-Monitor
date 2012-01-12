#!/usr/bin/python2.7

import pcap, dpkt, socket

pc = pcap.pcap('eth0')
ports = (80, 8080, 443, 888)

def process():
  mem = sport = dport = 0
  try:
    for ts, pkt in pc:
      eth = dpkt.ethernet.Ethernet(pkt)
      ip = eth.data
    
      if ip.__class__ == dpkt.ip.IP:
        ip1, ip2 = map(socket.inet_ntoa, [ip.src, ip.dst])
        if ip.p == socket.IPPROTO_TCP:
          I7 = ip.data
          sport, dport = [I7.sport, I7.dport]
    
        if sport in ports or dport in ports:
          if len(I7.data) > 0:
            print 'From %s to %s, length: %d' %(ip1, ip2, len(I7.data))
            mem = mem + len(I7.data)
  except KeyboardInterrupt:
    return int(mem)
    
def main():
  mem = process()
  print float(mem/(1024*1024)), 'mb'
  return
  
if __name__ == '__main__':
  main()
