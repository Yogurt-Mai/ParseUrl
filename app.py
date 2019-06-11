#!flask/bin/python

# Author: Ngo Duy Khanh
# Email: ngokhanhit@gmail.com
# Git repository: https://github.com/ngoduykhanh/flask-file-uploader
# This work based on jQuery-File-Upload which can be found at https://github.com/blueimp/jQuery-File-Upload/

import os
import PIL
from PIL import Image
import simplejson
import traceback
import time,datetime

from flask import Flask, request, render_template, redirect, url_for, send_from_directory, session
from flask_bootstrap import Bootstrap
from werkzeug import secure_filename
from urllib import parse
import ParseUrls
from lib.upload_file import uploadfile
from flask_mysqldb import MySQL


app = Flask(__name__)
app.config['SECRET_KEY'] = 'hard to guess string'
app.config['UPLOAD_FOLDER'] = r'D:/web/flask-file-uploader-master/data'
app.config['THUMBNAIL_FOLDER'] = r'D:/web/flask-file-uploader-master/data/thumbnail/'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'root'
app.config['MYSQL_DB'] = 'url'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'
mysql = MySQL(app)

ALLOWED_EXTENSIONS = set(['pcap'])
IGNORED_FILES = set(['.gitignore'])

bootstrap = Bootstrap(app)
urls=[]


def allowed_file(filename):
    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


def gen_file_name(filename):
    """
    If file was exist already, rename it and return a new name
    """

    i = 1
    while os.path.exists(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        name, extension = os.path.splitext(filename)
        filename = '%s_%s%s' % (name, str(i), extension)
        i += 1

    return filename


def create_thumbnail(image):
    try:
        base_width = 80
        img = Image.open(os.path.join(app.config['UPLOAD_FOLDER'], image))
        w_percent = (base_width / float(img.size[0]))
        h_size = int((float(img.size[1]) * float(w_percent)))
        img = img.resize((base_width, h_size), PIL.Image.ANTIALIAS)
        img.save(os.path.join(app.config['THUMBNAIL_FOLDER'], image))

        return True

    except:
        print(traceback.format_exc())
        return False


@app.route('/user')
def users():
    cur = mysql.connection.cursor()
    cur.execute('''SELECT user_name, password FROM url.user''')
    rv = cur.fetchall()
    return str(rv)


@app.route('/File')
def listFile():
    return render_template("File.html")

@app.route("/upload", methods=['GET', 'POST'])
def upload():
    if request.method == 'POST':
        files = request.files['file']

        if files:
            filename = secure_filename(files.filename)
            filename = gen_file_name(filename)
            mime_type = files.content_type

            if not allowed_file(files.filename):
                result = uploadfile(name=filename, type=mime_type, size=0, not_allowed_msg="File type not allowed")

            else:
                # save file to disk
                uploaded_file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                files.save(uploaded_file_path)

                # create thumbnail after saving
                if mime_type.startswith('image'):
                    create_thumbnail(filename)
                
                # get file size after saving
                size = os.path.getsize(uploaded_file_path)
                timestart=datetime.datetime.now()
                # return json for js call back
                result = uploadfile(name=filename, type=mime_type, size=size)
                name=os.path.join(app.config['UPLOAD_FOLDER'], filename)
                finalres,proto_flow =ParseUrls.get_urls(name)
                proto=["TCP", "UDP", "ARP", "ICMP", "DNS", "HTTP", "HTTPS"]
                flowstr="["
                for i in range(len(proto)):
                    flowstr+=str(proto_flow[proto[i]])+","
                flowstr=flowstr.strip(',')+"]"
                #print(flowstr)
                urls.clear()
                line='''{"className":"<a href='%s' title='%s'>%s</a>", 
                    "methodName":"0",
                    "description":"%s",
                    "spendTime":"%s",
                    "status":"%s",
                    "ipRegion":"%s",
                    "log":[
                        "%s"
                            ]
                },
                '''
                attackcnt=0
                for i in finalres.values():
                    if i[1]!="normal":
                        attackcnt+=1
                for url,item in finalres.items():
                    urls.append(line%(parse.quote(url),parse.quote(url),parse.quote(url[:50]),item[1],item[4],ParseUrls.check_ua(item[0]),item[3]+":"+ParseUrls.checkip(item[3]),item[0]))
                urls.append(proto_flow)
                timend=datetime.datetime.now()
                jsondata={"name": filename+"分析报告",
                    "size": size, 
                    "url": "/report?Filename=%s&Size=%d&cnt=%d&time=%s"%(filename,len(urls),attackcnt,timend-timestart),
                    "deleteUrl": "delete/%s" % name, 
                    "deleteType": "DELETE",}
                os.remove(uploaded_file_path)
                return simplejson.dumps({"files": [jsondata]})
            
            return simplejson.dumps({"files": [result.get_file()]})

    if request.method == 'GET':
        # get all file in ./data directory
        files = [f for f in os.listdir(app.config['UPLOAD_FOLDER']) if os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'],f)) and f not in IGNORED_FILES ]        
        
        file_display = []

        for f in files:
            size = os.path.getsize(os.path.join(app.config['UPLOAD_FOLDER'], f))
            file_saved = uploadfile(name=f, size=size)
            file_display.append(file_saved.get_file())

        return simplejson.dumps({"files": file_display})

    return redirect(url_for('index'))

@app.route('/report')
def about():
    #print(''.join(urls))
    Filename=request.args.get("Filename","")
    Size=request.args.get("Size",0)
    attacknum=request.args.get("cnt",0)
    runtime = request.args.get("time",0)
    print(Filename,Size)
    proto_flow=urls[-1]
    proto = ["TCP", "UDP", "ARP", "ICMP", "DNS", "HTTP", "HTTPS"]
    pkeys='["TCP", "UDP", "ARP", "ICMP", "DNS", "HTTP", "HTTPS"]'
    flowstr = "["
    for i in range(len(proto)):
        flowstr += str(proto_flow[proto[i]]) + ","
    flowstr = flowstr.strip(',') + "]"
    # print(flowstr)
    return render_template("report.html",pcap_keys=pkeys,pcap_count=proto_flow,data="".join(urls[:-2]),flowdata=flowstr,normal=int(Size)-int(attacknum),alltime=runtime, filename=Filename,attack=attacknum,size=Size,time=time.ctime(time.time()))


@app.route("/delete/<string:filename>", methods=['DELETE'])
def delete(filename):
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file_thumb_path = os.path.join(app.config['THUMBNAIL_FOLDER'], filename)

    if os.path.exists(file_path):
        try:
            os.remove(file_path)

            if os.path.exists(file_thumb_path):
                os.remove(file_thumb_path)
            
            return simplejson.dumps({filename: 'True'})
        except:
            return simplejson.dumps({filename: 'False'})


# serve static files
@app.route("/thumbnail/<string:filename>", methods=['GET'])
def get_thumbnail(filename):
    return send_from_directory(app.config['THUMBNAIL_FOLDER'], filename=filename)


@app.route("/data/<string:filename>", methods=['GET'])
def get_file(filename):
    return send_from_directory(os.path.join(app.config['UPLOAD_FOLDER']), filename=filename)


@app.route('/', methods=['GET', 'POST'])
def index():
    if not 'user_name' in session:
        return redirect(url_for('login'))
    return render_template("index.html",user_name=session['user_name'], user_group=session['user_group'])

@app.route('/login', methods=['POST','GET'])
def login():
    session.pop('user_name', None)
    session.pop('user_group', None)
    if request.method == 'POST':
        # if(request.form['uname'] and request.form['psw']):
        #     user_name = request.form['uname']
        #     password = request.form['psw']
        #     cur = mysql.connection.cursor()
        #     cur.execute("INSERT INTO user (user_name,user_pwd,user_group) values('%s','%s','user')"%(user_name,password))
        if (request.form['uname'] and request.form['psw']):
            user_name = request.form['uname']
            password = request.form['psw']
            cur = mysql.connection.cursor()
            cur.execute("select user_pwd,user_group from user where user_name='%s'"%(user_name))
            result = cur.fetchall()
            if result:
                for row in result:
                    if password == row['user_pwd']:
                        session['user_name'] = user_name
                        session['user_group'] = row['user_group']
                        return render_template('index.html')
                    else:
                        return redirect(url_for('login'))
            else:
                return redirect(url_for('login'))
    else:
        return render_template('login.html')

@app.route('/register', methods=['POST','GET'])
def register():
    if request.method == 'POST':
        pass
    else:
        return render_template('register.html')

if __name__ == '__main__':
    app.run(debug=True, port=9191)
