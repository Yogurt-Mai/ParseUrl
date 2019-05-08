#encoding=utf-8
from scapy.all import *
import scapy_http.http as http

def JudgeAttack(url):
    ds = url.split('?')
    black = [
        'select [^ ]+ from  ',
        'update [^ ]+ set  ',
        'delete [^ ]+ from  ',
        ' union all select  ',
        ' union select  ',
        ' order by  ',
        ' group by  ',
        ' limit 1[ )] ',
        'begin [^ ]+ end ',
        'create database  ',
        'create table  ',
        'drop database  ',
        'drop table  ',
        'insert into  ',
        'alter table  ',
        'bulk insert  ',
        ' into outfile  ',
        ' waitfor delay  ',
        'sp_addextendedproc ',
        'xp_cmdshell ',
        'sp_oacreate ',
        'sp_addlogin ',
        'sp_sp_password ',
        'sp_addsrvrolemember ',
        'xp_dirtree ',
        'xp_servicecontrol ',
        'xp_regread ',
        'declare @ ',
        ' cursor for ',
        ';.*exec *( ',
        'db_name() ',
        '@@version',
        '@@servername ',
        'system_user ',
        ' and user ',
        'version() ',
        'database() ',
        'user() ',
        'system_user() ',
        'session_user() ',
        'host_name() ',
        '@@version_compile_os ',
        '@@basedir ',
        '@@datadir ',
        '@@tmpdir ', 'is_srvrolemember *( ',
        'is_member *( ', ' or [^ ]+=[^ ]+ ', ' or [^ <]+>[^ ]+ ', ' or [^ >]+<[^ ]+ ', ' and [^ ]+=[^ ]+ ',
        ' and [^ <]+>[^ ]+ ', ' and [^ >]+<[^ ]+ ', ' or [^ ]+ like [^ ]+ ', ' or [^ ]+ in [^ ]+ ',
        ' or [^ ]+ between [^ ]+ ', ' and [^ ]+ like [^ ]+ ', ' and [^ ]+ in [^ ]+ ', ' and [^ ]+ between [^ ]+ ',
        '\\.[sysdatabases] ', '\\.[sysobjects] ', '\\.sys\\.all_objects ', '[\\. (]+xtype= ', '.[syscolumns] ',
        ' information_schema\\.tables  ', ' information_schema\\.columns  ', ' table_schema  ', ' mysql\\.user  ',
        ' v\\$parameter  ', ' v\\$database  ', ' v\\$version  ', ' sys.dba_users  ', 'utl_inaddr\\.get_host_name',
        'sys.v_\\$database ', ' session_roles ', ' user_role_privs ', ' user_tables ', ' user_tab_columns ',
        'granted_role ', '[( =,]+load_file *( ', '[( =,]+count(\\*) ', '[( =,]+serverproperty *( ',
        '[( =,]+substring *( ', '[( =,]+cast *( ', '[( =,]+varchar *( ', '[( =,]+nvarchar *( ', '[( =,]+len *( ',
        '[( =,]+unicode *( ', '[( =,]+length *( ', '[( =,]+ascii *( ', '[( =,]+substr *( ', '[( =,]+concat *( ',
        '[( =,]+sys_context *( ', '[( =,]+count *( ', '[( =,]+asc *( ', '[( =,]+mid *( ', '@@pack_received ',
        'bitand( ', 'connection_id( '
    ]
    if len(ds) > 1:
        arg = ds[1]
        for pattern in black:
            # print(pattern)
            try:
                if re.search(pattern, arg) != None:
                    return "sqli"
            except:
                continue

        return 'normal'
    else:
        return 'normal'

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
                _type=JudgeAttack(req_url)
                req_list[req_url]=[ua,_type]
            if pkt.haslayer(http.HTTPResponse):
                http_header = pkt[http.HTTPResponse].fields
                #print(pkt[http.HTTPResponse].payload)
        return req_list
