#encoding=utf-8
from scapy.all import *
import scapy_http.http as http
from ip2Region import Ip2Region
from user_agents import parse

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
        catgory = "<font color=red>xss</font>"
    elif any(v[:-2]):
        catgory = "<font color=red>sqli</font>"
    else:
        catgory = "normal"
    return catgory


def     get_urls(filename):
        pkts = rdpcap(filename)
        proto_flow_dict = collections.OrderedDict()
        proto_flow_dict['TCP'] = 0
        proto_flow_dict['UDP'] = 0
        proto_flow_dict['ARP'] = 0
        proto_flow_dict['ICMP'] = 0
        proto_flow_dict['DNS'] = 0
        proto_flow_dict['HTTP'] = 0
        proto_flow_dict['HTTPS'] = 0
        req_list = {}
        for pkt in pkts:
            if pkt.haslayer(http.HTTPRequest):
                http_header = pkt[http.HTTPRequest].fields
                #if pkt[http.HTTPRequest].Method==b"POST":
                    #print((pkt[http.HTTPRequest]))
                #    pass
                req_url = (b"http://"+ http_header["Host"] + http_header["Path"]).decode('utf-8')
                try:
                    ua=(b"User-Agent:"+http_header["User-Agent"]).decode('utf-8')
                except:
                    ua=""
                _type=judgeAttack(req_url)
                t = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(pkt.time))
                req_list[req_url]=[ua,_type,pkt.getlayer(IP).src,pkt.getlayer(IP).dst,t]
            if pkt.haslayer(TCP):
                tcp = pkt.getlayer(TCP)
                dport = tcp.dport
                sport = tcp.sport
                if dport == 80 or sport == 80:
                    proto_flow_dict['HTTP'] += 1
                elif dport == 443 or sport == 443:
                    proto_flow_dict['HTTPS'] += 1
                else:
                    proto_flow_dict['TCP'] += 1
            elif pkt.haslayer(UDP):
                udp = pkt.getlayer(UDP)
                dport = udp.dport
                sport = udp.sport
                if dport == 5353 or sport == 5353:
                    proto_flow_dict['DNS'] += 1
                else:
                    proto_flow_dict['UDP'] += 1
            if pkt.haslayer(ARP):
                proto_flow_dict['ARP'] += 1
            elif pkt.haslayer(ICMP):
                proto_flow_dict['ICMP'] += 1
            elif pkt.haslayer(DNS):
                proto_flow_dict['DNS'] += 1
            elif pkt.haslayer(ICMPv6ND_NS):
                proto_flow_dict['ICMP'] += 1
        return (req_list,proto_flow_dict)


def checkip(ip):
    # '''
    # URL = 'http://ip.taobao.com/service/getIpInfo.php'
    # try:
    #     r = requests.get(URL, params=ip, timeout=3)
    # except requests.RequestException as e:
    #     print(e)
    #     return "error"
    # else:
    #     json_data = r.json()
    # if json_data[u'code'] == 0:
    #     info=json_data['data']['country']
    #     info+=":"+json_data['data']['region']
    #     info+=":"+json_data['data']['city']
    #     return info
    # else:
    #     return 'error'
    # '''
    searcher = Ip2Region("C:/Users/Yogurt-Mai/Documents/GitHub/ParseUrl/static/ip2region.db")
    data = searcher.binarySearch(ip)
    return data["region"].decode('utf-8')

def check_ua(ua):
    user_agent = parse(ua)  # 解析成user_agent
    bw = user_agent.browser.family  # 判断是什么浏览器
    s = user_agent.os.family  # 判断是什么操作系统
    juge_pc = user_agent.is_pc  # 判断是不是桌面系统
    phone = user_agent.device.family
    return " ".join((bw, s))

