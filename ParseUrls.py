#encoding=utf-8
from scapy.all import *
import scapy_http.http as http
import collections
import requests
def judgeAttack(url):
    black = [
        'select.*from',
        'update.*set',
        'delete.*from',
        'insert.*into',
        '<.*>.*</.*>'
    ]
    tmpdic = {}
    for pattern in black:
        size = len(re.findall(pattern, url, re.I))
        tmpdic[pattern] = size
    v = list(tmpdic.values())
    if v[-1] >= 1:
        catgory = "xss"
    elif any(v[:-2]):
        catgory = "sqli"
    else:
        catgory = "normal"
    return catgory


def     get_urls(filename):
        pkts = rdpcap(filename)
        #print(type(packets),len(packets))
        req_list = {}
        for pkt in pkts:
            if pkt.haslayer(http.HTTPRequest):
                http_header = pkt[http.HTTPRequest].fields
                #if pkt[http.HTTPRequest].Method==b"POST":
                    #print((pkt[http.HTTPRequest]))
                #    pass
                req_url = (b"http://"+ http_header["Host"] + http_header["Path"]).decode('utf-8')
                ua=(b"User-Agent:"+http_header["User-Agent"]).decode('utf-8')
                _type=judgeAttack(req_url)
                req_list[req_url]=[ua,_type,pkt.getlayer(IP).src,pkt.getlayer(IP).dst]
            #if pkt.haslayer(http.HTTPResponse):
                #http_header = pkt[http.HTTPResponse].fields
                #print(pkt[http.HTTPResponse].payload)
        return req_list


def checkip(ip):
    URL = 'http://ip.taobao.com/service/getIpInfo.php'
    try:
        r = requests.get(URL, params=ip, timeout=3)
    except requests.RequestException as e:
        print(e)
        return "error"
    else:
        json_data = r.json()
    if json_data[u'code'] == 0:
        info=json_data['data']['country']
        info+=":"+json_data['data']['region']
        info+=":"+json_data['data']['city']
        return info
    else:
        return 'error'

'''
print('请输入您想要查询的IP地址：')
ip = {'ip': '202.102.193.68'}
checkip(ip)
'''

