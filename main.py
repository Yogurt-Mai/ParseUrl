from flask import Flask
from flask import request
from flask  import render_template
import os
from flask import send_from_directory
from flask import Flask, request, redirect, url_for
import ParseUrls

UPLOAD_FOLDER = '/Users/cosmop01tain/PycharmProjects/web'
ALLOWED_EXTENSIONS = set(['pcap'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1] in ALLOWED_EXTENSIONS

@app.route('/about')
def about():
    name = request.args.get('name','')
    return render_template("about.html",name=name)
@app.route('/', methods=['GET', 'POST'])
def upload_file():
    if request.method == 'POST':
        file = request.files['file']
        if file and allowed_file(file.filename):
            filename=file.filename
            file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
            #return redirect(url_for('uploaded_file',filename=filename))
            name=os.path.join(app.config['UPLOAD_FOLDER'], filename)
            finalres=ParseUrls.get_urls(name)
            finalres=[str(i) for i in finalres]
            return "<br>".join(finalres)
    return '''
    <!doctype html>
    <title>Upload new File</title>
    <h1>Upload new File</h1>
    <form action="" method=post enctype=multipart/form-data>
      <p><input type=file name=file>
         <input type=submit value=Upload>
    </form>
    '''


if __name__ == '__main__':
    app.debug = True
    app.run()