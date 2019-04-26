#encoding=utf-8
from scapy.all import *
import scapy_http.http as http
def     get_urls(filename):
        pkts = rdpcap(filename)
        #print(type(packets),len(packets))
        req_list = {}
        for pkt in pkts:
            if pkt.haslayer(http.HTTPRequest):
                http_header = pkt[http.HTTPRequest].fields
                if pkt[http.HTTPRequest].Method==b"POST":
                    #print((pkt[http.HTTPRequest]))
                    pass
                req_url = (b"http://"+ http_header["Host"] + http_header["Path"]).decode('utf-8')
                ua=(b"User-Agent:"+http_header["User-Agent"]).decode('utf-8')
                req_list[req_url]=ua
            if pkt.haslayer(http.HTTPResponse):
                http_header = pkt[http.HTTPResponse].fields
                #print(pkt[http.HTTPResponse].payload)
        return req_list
