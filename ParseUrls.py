#encoding=utf-8
from scapy.all import *
import scapy_http.http as http
def     get_urls(filename):
        pkts = rdpcap(filename)
        #print(type(packets),len(packets))
        req_list = []
        for pkt in pkts:
            if pkt.haslayer(http.HTTPRequest):
                http_header = pkt[http.HTTPRequest].fields
                if pkt[http.HTTPRequest].Method==b"POST":
                    #print((pkt[http.HTTPRequest]))
                    pass
                req_url = b"http://"+ http_header["Host"] + http_header["Path"]+b"\nUser-Agent:"+http_header["User-Agent"]
                req_list.append(req_url)
            if pkt.haslayer(http.HTTPResponse):
                http_header = pkt[http.HTTPResponse].fields
                #print(pkt[http.HTTPResponse].payload)
        return req_list
