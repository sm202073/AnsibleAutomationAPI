from flask import  Flask,request, jsonify, make_response, Response, redirect, url_for
import pandas as pd
from functools import wraps
from werkzeug.wrappers import Response
import bcrypt as bc
import ansible_runner
import time
from pathlib import Path
from datetime import datetime


app = Flask(__name__)
app.config["DEBUG"] = True

cred_dir = "Encrypted_Credentials.csv"
credentials = ('Username','Password','Email')
credentials_data_frame = pd.read_csv(cred_dir, names=credentials)

'''
old code
for credential in list(credentials_data_frame):
    for i in list(credential):
        #convert to bytes and hash with bcrypt, save back into dataframe
        byte = i.encode()
        hashed = bc.hashpw(byte, bc.gensalt())
        i = hashed
'''

'''
checks to see whether passed credentials match the hashed local versions
params:
    -user_credentials: a list of credentials sent with the request
returns:
    -bool representing whether those credentials match a verified user
'''
def check_credentials(user_credentials : list) -> bool:
    matrix = credentials_data_frame.to_numpy()
    for i in range(len(list(matrix[0]))-1):
      if bc.checkpw(user_credentials[0].encode(), matrix[i+1][0][2:-1].encode()):
          for j in range(len(list(matrix))):
              if not bc.checkpw(user_credentials[j].encode(), matrix[i+1][j][2:-1].encode()):
                  print('access denied')
                  return False

          return True
    return False

#initialize the artifact directory for Ansible runner and starting job_id
artifact_dir = './artifact'
with open("job_id.txt", 'r') as f:
    job_id = int(f.read())

#checks username and looks for the playbook name for an accurate redirect
@app.route('/ansibleapi',methods=['GET'], strict_slashes=False)
def home():
    if request.method == 'GET':
        return '''
            <form action="/playbook-redirect" method="POST">
                <div><label>PlaybookName: <input type="text" name="PlaybookName"></label></div>
                <input type="submit" value="Submit">
            </form>'''
    else:
        return "", 400

#redirects to the correct route to display the appropriate parameters
@app.route('/playbook-redirect', methods=['POST'], strict_slashes=False)
def redirect_to_playbook():
    playbook_name = request.form.get('PlaybookName')
    return redirect(url_for(f'{playbook_name}'))


'''
Special Version of the Template
When redirected to the status page, a user can obtain the status of their job by 
submitting their jobID
'''
@app.route('/status',methods=['POST', 'GET'], strict_slashes=False)
def get_status():
    if request.method == 'POST':
        req_job_id = request.form.get('JobID')
        status = open('%s/%s/status' % (artifact_dir,req_job_id),'r').read()
        if status == 'successful':
            content = Path('artifact/%s/out.txt' % (req_job_id)).read_text()
            resp = jsonify({'content' : content, 'status' : "%s" % (status)})
        else: 
            resp = jsonify({"status": "%s" % (status)})
        resp.status_code = 200
        return resp
    if request.method == 'GET':
        return '''
            <form method="POST">
                <div><label>JobID: <input type="text" name="JobID"></label></div>
                <input type="submit" value="Submit">
            </form>'''
    else:
        return "", 400

'''
Template for App Routing on the Ansible API
On Get, asks for credentials and parameters, then posts
On Post, verifies credentials, than runs the playbook and returns the output
All Editables are marked with the language appropriate comments of "params"
'''
@app.route('/2min',methods=['POST', 'GET'], strict_slashes=False)
def twomin():
    if request.method == 'POST':
        username = request.form.get('Username')
        password = request.form.get('Password')
        email = request.form.get('Email')
        if not check_credentials([username, password, email]):
            return "", 403
        content = { 'Name' : request.form.get('Name'),'Title' :  request.form.get('Title')} #params
        global job_id
        job_id += 1
        with open("job_id.txt", 'w') as f:
            f.write(str(job_id))
        runner = ansible_runner.interface.run_async(ident=job_id,
                                            private_data_dir='./',
                                            artifact_dir=artifact_dir,
                                            playbook='2min_playbook.yml',
                                            json_mode=True,quiet=True, 
                                            extravars={'name': content['Name'], 'title': content['Title'], 'JobID' : job_id}) #params
        
        time.sleep(1)
        f = open('%s/%s/status' % (artifact_dir,job_id),'w')
        f.write(runner[1].status)
        f.close
        now = datetime.now()
        contentstring = {'name': content['Name'], 'title': content['Title'], 'JobID' : job_id}
        f = open('call_log.txt', 'a')
        f.write(str(username) + " " + str(now) + " twomin, vars:" + str(contentstring) + "\n")  #params
        return "", 200
    if request.method == 'GET':
        return '''
            <form method="POST">
                <div><label>Username: <input type="text" name="Username"></label></div>
                <div><label>Password: <input type="text" name="Password"></label></div>
                <div><label>Email: <input type="text" name="Email"></label></div>
                <div><label>Name: <input type="text" name="Name"></label></div>             <!-- Params -->
                <div><label>Title: <input type="text" name="Title"></label></div>           <!-- Params -->
                <input type="submit" value="Submit">
            </form>'''
    else:
        return "", 400

app.run()
