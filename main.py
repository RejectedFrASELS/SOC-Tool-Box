from flask import Flask, render_template, redirect, url_for, request, send_file, flash, jsonify, session
from flask_wtf import FlaskForm
from flask_bootstrap import Bootstrap
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, DataRequired, Length, EqualTo, ValidationError
#from models import db, User 
from IPChecker import iptester
from blacklist import blacklist_add
from whitelist import whitelist_add

from flask_login import login_user, LoginManager, login_required, current_user, logout_user
import ldap3 as ldap
from flask_sqlalchemy import SQLAlchemy
import os
from datetime import timedelta, datetime
from apscheduler.schedulers.background import BackgroundScheduler

from cron import cronjob
from logcron import Cronlog
from gevent.pywsgi import WSGIServer
import subprocess as sp
import sqlite3
import tempfile
#from OpenSSL import SSL
import logging
#from waitress import serve


'''
############################################
SOC TOOLBOX VER 1
############################################
'''

print("SERVER STARTING\n")

global server_url, domain, session_lifetime, automation_interval

conn = sqlite3.connect('database.db')
cursor = conn.cursor()

cursor.execute('SELECT value FROM config WHERE type = "address"')
server_addr = cursor.fetchone()[0]
print("SERVER ADDRESS is "+server_addr)

cursor.execute('SELECT value FROM config WHERE type = "ldapurl"')
server_url = cursor.fetchone()[0]
print("LDAP SERVER URL is "+server_url)

cursor.execute('SELECT value FROM config WHERE type = "ldapdomain"')
domain = cursor.fetchone()[0]
print("LDAP SERVER DOMAIN is "+domain)

cursor.execute('SELECT value FROM config WHERE type = "sessionlifetime"')
session_lifetime = (cursor.fetchone())[0]
print("SERVER SESSION LIFETIME is "+session_lifetime)


cursor.execute('SELECT value FROM config WHERE type = "crontime"')
automation_interval = (cursor.fetchone())[0]
print("CRONJOB INTERVAL is "+automation_interval)

conn.close()

#pathing for logging
dir_path = os.path.dirname(os.path.realpath(__file__))
log_path = os.path.join(dir_path, 'logs', 'log.log')

now = datetime.now()
formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
with open(log_path, 'a') as f:
    f.write(formatted_time+" PORTAL "+"STARTING"+"\n")
    f.write(formatted_time+" PORTAL "+"SERVER ADDRESS is "+server_addr+"\n")
    f.write(formatted_time+" PORTAL "+"LDAP SERVER URL is "+server_url+"\n")
    f.write(formatted_time+" PORTAL "+"LDAP SERVER DOMAIN is "+domain+"\n")
    f.write(formatted_time+" PORTAL "+"SERVER SESSION LIFETIME is "+session_lifetime+"\n")
    f.write(formatted_time+" PORTAL "+"CRONJOB INTERVAL is "+automation_interval+"\n")

session_lifetime = int(session_lifetime)
automation_interval = int(automation_interval)
#server_url = "ldap://localhost:389" #ldap server uri
#domain = "dc=example,dc=org"        #ldap domain
#session_lifetime = 10
#automation_interval = 5

###LOGGING
logging.basicConfig(filename=log_path, level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

now = datetime.now()
formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]

### LOG FORMAT
#with open(log_path, 'a') as f:
 #   f.write(formatted_time+" PORTAL"+" LOGIN PAGE"+" Tried to login :"+"messages"+"\n")




app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(50)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db' #artik kullanilmiyor silmeye korkuyorum
app.config['SQLALCHEMY_BINDS'] = {
                    'blacklist': 'sqlite:///database.db',
                    'whitelist': 'sqlite:///database.db',
                    'triedToAdd': 'sqlite:///database.db',
                    'config': 'sqlite:///database.db',
                    'cronlinks': 'sqlite:///database.db',
                    'apik': 'sqlite:///database.db'
                    }


app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=session_lifetime) #session lifetime
db = SQLAlchemy(app)

Bootstrap(app)

login_manager = LoginManager()
login_manager.init_app(app)

class User:
    def __init__(self, name):
        self.name = name    
    def is_authenticated(self):
        return True   
    def is_active(self):
        return True   
    def is_anonymous(self):
        return False    
    def get_id(self):
        return self.name
    
#LOGIN MANAGER
@login_manager.user_loader
def load_user(get_id):     
    return User(get_id)

# CREATE TABLES IN DB ###################################
class Blacklist(db.Model):
    __bind_key__ = 'blacklist'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100))
    value = db.Column(db.String(1000), unique=True)
    addedBy = db.Column(db.String(1000))
    addTime = db.Column(db.String(100))
    isPassive = db.Column(db.Integer)
    modificationTime = db.Column(db.String(100))
    modifiedBy = db.Column(db.String(100))

    def to_dict(blacklist):
        return {
            'id': blacklist.id,
            'type': blacklist.type,
            'value': blacklist.value,
            'addedBy': blacklist.addedBy,
            'addTime': blacklist.addTime,
            'isPassive': blacklist.isPassive,
            'modificationTime': blacklist.modificationTime,
            'modifiedBy': blacklist.modifiedBy
        }
    
class TriedToAddList(db.Model):
    __bind_key__ = 'triedToAdd'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(1000))
    addedBy = db.Column(db.String(1000))
    addTime = db.Column(db.String(100))

class Whitelist(db.Model):
    __bind_key__ = 'whitelist'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(1000), unique=True)
    addedBy = db.Column(db.String(1000))
    addTime = db.Column(db.String(100))
    isPassive = db.Column(db.Integer)
    modificationTime = db.Column(db.String(100))
    modifiedBy = db.Column(db.String(100))

class Config(db.Model):
    __bind_key__ = 'config'
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100))
    value = db.Column(db.String(1000))
    addedBy = db.Column(db.String(1000))
    addTime = db.Column(db.String(100))

class Apik(db.Model):
    __bind_key__ = 'apik'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(1000), unique=True)
    addedBy = db.Column(db.String(1000))
    addTime = db.Column(db.String(100))
    isPassive = db.Column(db.Integer)
    modificationTime = db.Column(db.String(100))
    modifiedBy = db.Column(db.String(100))

class Cronlinks(db.Model):
    __bind_key__ = 'cronlinks'
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.String(1000), unique=True)
    addedBy = db.Column(db.String(1000))
    addTime = db.Column(db.String(100))
    isPassive = db.Column(db.Integer)
    modificationTime = db.Column(db.String(100))
    modifiedBy = db.Column(db.String(100))
#######################################################

#API FOR AJAX TABLE
@app.route('/api/data')
def data():
    query = Blacklist.query

    # search filter
    search = request.args.get('search[value]')
    if search:
        query = query.filter(db.or_(
            Blacklist.value.like(f'%{search}%'),
            Blacklist.addedBy.like(f'%{search}%'),
            Blacklist.modifiedBy.like(f'%{search}%'),
        ))
    total_filtered = query.count()
    
    # sorting
    order = []
    i = 0
    while True:
        col_index = request.args.get(f'order[{i}][column]')
        if col_index is None:
            break
        col_name = request.args.get(f'columns[{col_index}][data]')
        if col_name not in ['id', 'type', 'value', 'addedBy', 'addTime', 'isPassive', 'modifiedBy', 'modificationTime']:
            col_name = 'value'
        descending = request.args.get(f'order[{i}][dir]') == 'desc'
        col = getattr(Blacklist, col_name)
        if descending:
            col = col.desc()
        order.append(col)
        i += 1
    if order:
        query = query.order_by(*order)

    # pagination
    start = request.args.get('start', type=int)
    length = request.args.get('length', type=int)
    query = query.offset(start).limit(length)

    # response
    return {
        'data': [blacklist.to_dict() for blacklist in query],
        'recordsFiltered': total_filtered,
        'recordsTotal': Blacklist.query.count(),
        'draw': request.args.get('draw', type=int),
    }
    #return {'data': [blacklist.to_dict() for blacklist in Blacklist.query]}

#AUTOMATION FUNC AND CONFIG
def automation():
        cronjob.runthis()
        #sched.shutdown()

def logcron():
        Cronlog.runthis()

sched = BackgroundScheduler(daemon=True)
sched.add_job(automation,'interval', minutes=automation_interval, id='autoBlackList') #automation
sched.add_job(logcron,'cron', hour=23, minute=59, id='logcron') #log cron, make it 23 59
sched.start()

db.create_all() #CREATE ALL DB

#INDEX PAGE
@app.route('/')
def home():
    
    return render_template("index.html", logged_in=current_user.is_authenticated, username=session.get('username'))

#LDAP LOGIN PAGE
@app.route('/login', methods=["GET", "POST"])
def login():
    global server_url, domain
    if request.method == "POST":
        name = request.form.get('name')
        password = request.form.get('password')
        
        server = ldap.Server(server_url)
        connection = ldap.Connection(server, user='cn={},{}'.format(name, domain), password=password)
        connection.open()
        if connection.bind():
            print('Authenticated!')
            user = User(name)
            login_user(user, duration=timedelta(minutes=session_lifetime))
            #logged_user = user.name
            #print(User.get_id(user))
            session['username'] = name
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" LOGIN,"+" User has been logged in using LDAP : "+name+" user logged in"+"\n")
            return  redirect(url_for('home'))
        else:
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" LOGIN,"+" User tried to log in using LDAP, unsuccessful... : "+name+": tried to log in as"+"\n")
            print('Not Authenticated')
            #print(connection.result)

    return render_template("login.html", logged_in=current_user.is_authenticated)

#LOGOUT
@app.route('/logout')
def logout():
    username=session.get('username')
    logout_user()
    return redirect(url_for('login'))

#CONFIG PAGE
@app.route('/config', methods=["GET", "POST"])
@login_required
def config():   
    global server_url, domain, session_lifetime, automation_interval
    username=session.get('username')
    if request.method == "POST":
        conn = sqlite3.connect('database.db')
        cursor = conn.cursor()
        now = datetime.now() 
        date_time = now.strftime("%m/%d/%Y %H:%M:%S")
        if request.form['submit_button'] == 'serveraddr_submit_button':
            try:
                newaddr = request.form['serveraddr']
                server_addr = newaddr
                cursor.execute(
                            f'UPDATE config SET value="{newaddr}", addTime="{date_time}", addedBy="{username}" WHERE type="address"')
                conn.commit()
                conn.close()
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG,"+" User has changed server address : "+username +" changed the address to "+newaddr+"\n")
                return jsonify({'success': True, 'message': 'Server address has been changed.'})
            except:    
                return jsonify({'success': False, 'message': 'Error'}), 404
        if request.form['submit_button'] == 'ldapurl_submit_button': ## no need to redeploy
            try:
                newurl = request.form['ldapurl']
                server_url = newurl
                #print(server_url)
                cursor.execute(
                            f'UPDATE config SET value="{newurl}", addTime="{date_time}", addedBy="{username}" WHERE type="ldapurl"')
                conn.commit()
                conn.close()
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG,"+" User has changed LDAP login URL : "+username +" changed the URL to "+newurl+"\n")
                return jsonify({'success': True, 'message': 'LDAP URL has been changed.'})
            except:
                return jsonify({'success': False, 'message': 'Error'}), 404
        elif request.form['submit_button'] == 'ldapdomain_submit_button': ## no need to redeploy
            try:
                newdomain = request.form['ldapdomain']
                domain = newdomain
                #print(domain)
                cursor.execute(
                            f'UPDATE config SET value="{newdomain}", addTime="{date_time}", addedBy="{username}" WHERE type="ldapdomain"')
                conn.commit()
                conn.close()
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG,"+" User has changed LDAP domain : "+username +" changed the domain to "+newdomain+"\n")
                return jsonify({'success': True, 'message': 'LDAP Domain has been changed.'})
            except:
                return jsonify({'success': False, 'message': 'Error'}), 404
        elif request.form['submit_button'] == 'session_lifetime_submit_button': ## need to redeploy
            try:
                new_session_lifetime = request.form['session_lifetime']
                session_lifetime = int(new_session_lifetime)
                #print(session_lifetime)
                cursor.execute(
                            f'UPDATE config SET value="{new_session_lifetime}", addTime="{date_time}", addedBy="{username}" WHERE type="sessionlifetime"')
                conn.commit()
                conn.close()
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG,"+" User has changed session lifetime : "+username +" changed the session lifetime to "+new_session_lifetime+"\n")
                return jsonify({'success': True, 'message': 'Session Lifetime has been changed. Server needs to be redeployed to apply the effect.'}), 404
            except:
                return jsonify({'success': False, 'message': 'Error'}), 404
        elif request.form['submit_button'] == 'cron_interval_submit_button': ## no need to redeploy
            try:
                new_automation_interval = request.form['cron_interval']
                automation_interval = int(new_automation_interval)
                #print(automation_interval)
                cursor.execute(
                            f'UPDATE config SET value="{new_automation_interval}", addTime="{date_time}", addedBy="{username}" WHERE type="crontime"')
                sched.reschedule_job('autoBlackList', trigger='interval', minutes=automation_interval)
                conn.commit()
                conn.close()
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG,"+" User has changed automation interval : "+username +" changed the interval to "+new_automation_interval+"\n")
                return jsonify({'success': True, 'message': 'Cronjob interval has been changed.'})
            except:
                return jsonify({'success': False, 'message': 'Error'}), 404
        elif request.form['submit_button'] == 'automation_url_submit_button': ## no need to redeploy
            newlink = request.form['automation_url']
            #print(newlink)
            try:
                cursor.execute("INSERT INTO cronlinks (value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?)",
                            ( newlink, username, date_time, False))
                conn.commit()
                with open('automation-urls.txt', 'a') as f:
                        f.write(newlink + '\n')
                conn.close()
                return jsonify({'success': True, 'message': 'New link has been added.'})
            except:
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG, User tried to add existing cronlink or bad request : "+username +" tried to add "+newlink+"\n")
                return jsonify("'success': False, 'message': 'error writing the value, maybe is already in db? or bad request'")
        elif request.form['submit_button'] == 'api_key_submit_button': ## no need to redeploy
            newkey = request.form['api_key']
            #print(newkey)
            try:
                cursor.execute("INSERT INTO apik (value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?)",
                            ( newkey, username, date_time, False))
                conn.commit()
                with open('IPChecker-apikeys.txt', 'a') as f:
                        f.write(newkey + '\n')
                conn.close()
                return jsonify({'success': True, 'message': 'New apikey has been added.'})
            except:
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                with open(log_path, 'a') as f:
                    f.write(formatted_time+" PORTAL,"+" CONFIG,"+" User tried to add existing api key or bad request : "+username +" tried to add "+newkey+"\n")
                return jsonify("'success': False, 'message': 'error writing the value, maybe is already in db? or bad request'")
    return render_template("config.html", logged_in=current_user.is_authenticated, username=session.get('username'))

#REPUTATION PAGE
@app.route('/reputation_checker', methods=["GET", "POST"])
@login_required
def ipscanner():
    username=session.get('username')
    ext = iptester()
    if request.method == 'POST':
        #username = session.get('username')
        #print(username)
        inp = request.form['scanner']
        ext.runthis(inp, username)
        now = datetime.now()
        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" IPTESTER,"+" User has scanned some adresses : "+username+" scanned IPs"+"\n")
        return send_file("out.txt")
        # return ext.runthis(inp)
    return render_template('reputation-checker.html', logged_in=current_user.is_authenticated,title="Ip scanner", username=session.get('username'))

#IP CHECKER LAST SCAN VIEW PAGE
@app.route('/ip-last-scan')
@login_required
def lastIpScan():   
    return send_file('out.txt')

#BLACKLIST PAGE
@app.route('/blacklist', methods=["GET", "POST"])
@login_required
def blacklist():
    #global logged_user
    username=session.get('username')
    file_formats = {
        "ip": {"txt": "blacklist-ip.txt"},
        "domain": {"txt": "blacklist-domain.txt"},
        "hash": {"txt": "blacklist-hash.txt"},
    }
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT count(value) FROM blacklist WHERE isPassive=0')
    blacklisted = cursor.fetchone()[0]

    conn.close()

    totalblacklisted = blacklisted
    ext = blacklist_add()
    if request.method == 'POST':
        inp = request.form['blacklist']
        option = request.form['input_type']
        ext.runthis(inp, option, username)
        
        if option in file_formats:
            if request.form['submit_button'] == 'save-to-txt':
                #return send_file(file_name)
                return jsonify({'success': True, 'message': 'Entries posted.'})
            else:
                if option == "ip":
                    return redirect(url_for('blacklistIP'))
                elif option == "domain":
                    return redirect(url_for('blacklistDomain'))
                elif option == "hash":
                    return redirect(url_for('blacklistHash'))
                else:
                    return jsonify({'success': False, 'message': 'ERROR Format'})
    
    return render_template('blacklist.html', logged_in=current_user.is_authenticated, title="Black List", username=session.get('username'), totalblacklisted=totalblacklisted)

##DYNAMIC BLACKLIST VALUES## no need to login to see this page bc fw needs to see
@app.route('/blacklist-ip')
def blacklistIP():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM blacklist WHERE type = "ip" AND isPassive=0')
    rows = cursor.fetchall()
    conn.close()

    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        for row in rows:
            f.write(row[0] + '\n')

    # Send temporary text file to user
    return send_file(f.name, attachment_filename='ip_addresses.txt')
    #return render_template('blacklist-ip.html', rows=rows)

@app.route('/blacklist-domain')
def blacklistDomain():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM blacklist WHERE type = "domain" AND isPassive=0')
    rows = cursor.fetchall()
    conn.close()
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        for row in rows:
            f.write(row[0] + '\n')
    return send_file(f.name, attachment_filename='domains.txt')
    #return render_template('blacklist-domain.html', rows=rows)

@app.route('/blacklist-hash')
def blacklistHash():
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    cursor.execute('SELECT value FROM blacklist WHERE type = "hash" AND isPassive=0')
    rows = cursor.fetchall()
    conn.close()
    
    with tempfile.NamedTemporaryFile(mode='w', delete=False) as f:
        for row in rows:
            f.write(row[0] + '\n')
    return send_file(f.name, attachment_filename='hashes.txt')
    
    #return render_template('blacklist-hash.html', rows=rows)
##################################################################################

#BLACKLIST DB AJAX TABLE PAGE
@app.route('/blacklist-db', methods=["GET", "POST"])
@login_required
def blacklistdb():
    blacklist = Blacklist.query
    username=session.get('username')
    
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    cursor.execute('SELECT count(value) FROM blacklist WHERE type="ip" AND isPassive=0')
    blacklistedip = cursor.fetchone()[0]
    cursor.execute('SELECT count(value) FROM blacklist WHERE type="domain" AND isPassive=0')
    blacklisteddomain = cursor.fetchone()[0]
    cursor.execute('SELECT count(value) FROM blacklist WHERE type="hash" AND isPassive=0')
    blacklistedhash = cursor.fetchone()[0]

    cursor.close()

    totalblacklistedip = blacklistedip
    totalblacklisteddomain = blacklisteddomain
    totalblacklistedhash = blacklistedhash

    if request.method == 'POST':
        if 'row_id' in request.form:
            blacklist_id = request.form['row_id']
            blacklist = Blacklist.query.get(blacklist_id)
            if not blacklist:
                return jsonify({'success': False, 'message': 'Blacklist entry not found.'}), 404
            
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" BLACKLISTDB,"+" User has deleted an entry : "+username+" deleted value:"+blacklist.value+"\n")
            db.session.delete(blacklist)
            db.session.commit()
            flash("{'success': True, 'message': 'Blacklist entry deleted.'}")
            
        elif 'toggle-passive' in request.form:
            blacklist_id = request.form['toggle-passive']
            blacklist = Blacklist.query.get(blacklist_id)
            if not blacklist:
                return jsonify({'success': False, 'message': 'Blacklist entry not found.'}), 404
            
            if blacklist.isPassive == 1:
                with open("whitelist.txt", 'r') as f:
                    whitelist_set = set(f.read().splitlines())    
                if blacklist.value in whitelist_set:
                    conn = sqlite3.connect('database.db')
                    cursor = conn.cursor() 
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("INSERT INTO tried_to_add_list (value, addedBy, addTime) VALUES (?, ?, ?)",
                    (blacklist.value, f'{username} tried to make a value active that is in Whitelist', formatted_time))  
                    conn.commit()
                    conn.close()
                    return jsonify({'success': False, 'message': 'Value is in Whitelist'}), 400

            blacklist.isPassive = not blacklist.isPassive
            #blacklist.modificationTime = datetime.now()
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
            blacklist.modificationTime = formatted_time
            blacklist.modifiedBy = username
            db.session.commit()
            flash("{'success': True, 'message': 'Blacklist entry updated.'}")
        
        return redirect(url_for('blacklistdb'))
    
    return render_template('blacklist-db.html', title='Blacklist Database',
                           blacklist=blacklist, logged_in=current_user.is_authenticated, username=session.get('username'),
                           totalblacklistedhash=totalblacklistedhash, totalblacklisteddomain=totalblacklisteddomain, totalblacklistedip=totalblacklistedip)

#WHITELIST PAGE
@app.route('/whitelist', methods=["GET", "POST"])
@login_required
def whitelist():
    #global logged_user
    username=session.get('username')
    ext = whitelist_add()
    if request.method == 'POST':
        if request.form['submit_button'] == 'save-to-txt':
            inp = request.form['whitelist']
            ext.runthis(inp, username)
            #return send_file("whitelist.txt")
            return jsonify({'success': True, 'message': 'Entries added.'})
            # return ext.runthis(inp)
        elif request.form['submit_button'] == 'download-csv': 
            inp = request.form['whitelist']
            ext.runthis(inp, username)
            return send_file("whitelist.txt", as_attachment=True, attachment_filename="whitelist.csv")
    return render_template('whitelist.html', logged_in=current_user.is_authenticated,title="White List", username=session.get('username'))

#WHITELIST TABLE PAGE
@app.route('/whitelist-db', methods=["GET", "POST"])
@login_required
def whitelistdb():
    whitelist = Whitelist.query
    username=session.get('username')
    if request.method == 'POST':
        if 'row_id' in request.form:
            whitelist_id = request.form['row_id']
            whitelist = Whitelist.query.get(whitelist_id)
            if not whitelist:
                return jsonify({'success': False, 'message': 'Whitelist entry not found.'}), 404
            
            # Delete the corresponding row from the whitelist.txt file
            with open('whitelist.txt', 'r') as f:
                lines = f.readlines()
            with open('whitelist.txt', 'w') as f:
                for line in lines:
                    if line.strip() != whitelist.value:
                        f.write(line)
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" WHITELISTDB,"+" User has deleted an entry : "+username+" deleted value:"+whitelist.value+"\n")
            db.session.delete(whitelist)
            db.session.commit()
            return  redirect(url_for('whitelistdb'))
            # return jsonify({'success': True, 'message': 'Whitelist entry deleted.'})
        elif 'toggle-passive' in request.form:
            whitelist_id = request.form['toggle-passive']
            whitelist = Whitelist.query.get(whitelist_id)
            if not whitelist:
                return jsonify({'success': False, 'message': 'Whitelist entry not found.'}), 404
            
            if whitelist.isPassive == 1:
                with open('whitelist.txt', 'a') as f:
                    f.write(whitelist.value + '\n')
                conn = sqlite3.connect('database.db')
                cursor = conn.cursor() 
                now = datetime.now()
                formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                cursor.execute(f'UPDATE blacklist SET isPassive=1, modificationTime="{formatted_time}", modifiedBy="{username} via Whitelist" WHERE value="{whitelist.value}"')  
                conn.commit()
                conn.close()
            else:
                with open('whitelist.txt', 'r') as f:
                    lines = f.readlines()
                with open('whitelist.txt', 'w') as f:
                    for line in lines:
                        if line.strip() != whitelist.value:
                            f.write(line)
            whitelist.isPassive = not whitelist.isPassive
            #print(whitelist.isPassive)
            
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
            whitelist.modificationTime = formatted_time
            whitelist.modifiedBy = username
            db.session.commit()
            flash("{'success': True, 'message': 'Whitelist entry updated.'}")

        return redirect(url_for('whitelistdb'))

    return render_template('whitelist-db.html', title='Whitelist Database',
                           whitelist=whitelist, logged_in=current_user.is_authenticated, username=session.get('username'))

@app.route('/configs-db', methods=["GET", "POST"])
@login_required
def configsdb():
    config = Config.query
    username=session.get('username')
    return render_template('configs-db.html', title='Configurations',
                        config=config, logged_in=current_user.is_authenticated, username=session.get('username'))
#APIKEY DB PAGE
@app.route('/apikey-db', methods=["GET", "POST"])
@login_required
def apikeydb():
    apik = Apik.query
    username=session.get('username')
    if request.method == 'POST':
        if 'row_id' in request.form:
            apik_id = request.form['row_id']
            apik = Apik.query.get(apik_id)
            if not apik:
                return jsonify({'success': False, 'message': 'Api Key entry not found.'}), 404
            
            # Delete the corresponding row from the whitelist.txt file
            with open('IPChecker-apikeys.txt', 'r') as f:
                lines = f.readlines()
            with open('IPChecker-apikeys.txt', 'w') as f:
                for line in lines:
                    if line.strip() != apik.value:
                        f.write(line)
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" APIKEYDB,"+" User has deleted an entry : "+username+" deleted value:"+apik.value+"\n")
            db.session.delete(apik)
            db.session.commit()
            return  redirect(url_for('apikeydb'))
            # return jsonify({'success': True, 'message': 'Whitelist entry deleted.'})
        elif 'toggle-passive' in request.form:
            apik_id = request.form['toggle-passive']
            apik = Apik.query.get(apik_id)
            if not apik:
                return jsonify({'success': False, 'message': 'Api Key entry not found.'}), 404
            
            if apik.isPassive == 1:
                with open('IPChecker-apikeys.txt', 'a') as f:
                    f.write(apik.value + '\n')
            else:
                with open('IPChecker-apikeys.txt', 'r') as f:
                    lines = f.readlines()
                with open('IPChecker-apikeys.txt', 'w') as f:
                    for line in lines:
                        if line.strip() != apik.value:
                            f.write(line)
            apik.isPassive = not apik.isPassive
            #print(apik.isPassive)
            
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
            apik.modificationTime = formatted_time
            apik.modifiedBy = username
            db.session.commit()
            flash("{'success': True, 'message': 'API Key entry updated.'}")

        return redirect(url_for('apikeydb'))

    return render_template('apikey-db.html', title='API Key Database',
                           apik=apik, logged_in=current_user.is_authenticated, username=session.get('username'))

#AUTOMATION LINKS DB PAGE
@app.route('/cronlinks-db', methods=["GET", "POST"])
@login_required
def cronlinksdb():
    cronlinks = Cronlinks.query
    username=session.get('username')
    if request.method == 'POST':
        if 'row_id' in request.form:
            cronlinks_id = request.form['row_id']
            cronlinks = Cronlinks.query.get(cronlinks_id)
            if not cronlinks:
                return jsonify({'success': False, 'message': 'Cronlinks entry not found.'}), 404
            
            # Delete the corresponding row from the whitelist.txt file
            with open('automation-urls.txt', 'r') as f:
                lines = f.readlines()
            with open('automation-urls.txt', 'w') as f:
                for line in lines:
                    if line.strip() != cronlinks.value:
                        f.write(line)
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
            with open(log_path, 'a') as f:
                f.write(formatted_time+" PORTAL,"+" CRONLINKSDB,"+" User has deleted an entry : "+username+" deleted value:"+cronlinks.value+"\n")
            db.session.delete(cronlinks)
            db.session.commit()
            return  redirect(url_for('cronlinksdb'))
            # return jsonify({'success': True, 'message': 'Whitelist entry deleted.'})
        elif 'toggle-passive' in request.form:
            cronlinks_id = request.form['toggle-passive']
            cronlinks = Cronlinks.query.get(cronlinks_id)
            if not cronlinks:
                return jsonify({'success': False, 'message': 'Cronlinks entry not found.'}), 404
            
            if cronlinks.isPassive == 1:
                with open('automation-urls.txt', 'a') as f:
                    f.write(cronlinks.value + '\n')
            else:
                with open('automation-urls.txt', 'r') as f:
                    lines = f.readlines()
                with open('automation-urls.txt', 'w') as f:
                    for line in lines:
                        if line.strip() != cronlinks.value:
                            f.write(line)
            cronlinks.isPassive = not cronlinks.isPassive
            #print(cronlinks.isPassive)
            
            now = datetime.now()
            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
            cronlinks.modificationTime = formatted_time
            cronlinks.modifiedBy = username
            db.session.commit()
            flash("{'success': True, 'message': 'API Key entry updated.'}")

        return redirect(url_for('cronlinksdb'))

    return render_template('cronlinks-db.html', title='Cronlinks Database',
                           cronlinks=cronlinks, logged_in=current_user.is_authenticated, username=session.get('username'))

#serve(app, host='0.0.0.0', port=443, url_scheme='https', threads=1)




if __name__ == '__main__':
    app.run(server_addr, debug=True)
    
  
