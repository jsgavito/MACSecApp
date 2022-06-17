from flask import flash, redirect, render_template, request, url_for
from flask_login import login_user, logout_user, current_user
from flask_package.forms import RegistrationForm, LoginForm
from flask_package import app, db, bcrypt
from flask_package.devmanager import db, CA, User

from ncclient import manager
from ncclient.operations import RPCError
from ncclient.transport import SSHError
from ncclient.transport import AuthenticationError
import xml.dom.minidom
import xmltodict
import lxml.etree as etree
import itertools
import json
import jinja2
import logging
import xml.etree.ElementTree as ET
from flask_package.tenxtemplates import *


values={}
#@app.before_request
#def make_session_permanent():
#    session.permanent = True

kw = {}
kw['device_port']= '830'
kw['username'] = 'user'
kw['password'] = 'ciena123'

def get_connection(**kw):
    try:
        db.session.query(CA).delete()
        db.session.commit()
        m=manager.connect(host=kw['device_ip'], port=int(kw['device_port']), username=kw['username'], password=kw['password'], look_for_keys=False, hostkey_verify=False)
    except:
        db.session.rollback()
    
    return m

@app.route('/login', methods = ['GET','POST'])
def login():
    form=LoginForm()
    if form.validate_on_submit():
        user= User.query.filter_by(email=form.email.data).first()
        print('this is a test')
        print(user)
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            print('success')
            login_user(user)
            return redirect(url_for('form'))
        else:
            flash('Invalid Credentials')
    return render_template('login.html',title="Login", form= form)

@app.route('/')
def homepage():
    return redirect(url_for('login'))

@app.route('/form/')
def form():
    if current_user.is_authenticated:
        kw['device_ip'] = None
        print('autorizado')
        return render_template('main.html')
    else:
        print('no autorizado')
        return redirect(url_for('login'))

@app.route('/logout', methods = ['GET','POST'])
def logout():
    kw['device_ip'] = None
    logout_user()
    print('logout')
    return redirect(url_for('login'))


@app.route('/data', methods=["GET", "POST"])
def data():

    if request.method == 'GET':
        return redirect(url_for('form'))

    if request.method == "POST":
        kw['device_ip'] = request.form['IP']
        return(redirect(url_for('connections')))
        
@app.route('/connections')
def connections():
    if current_user.is_authenticated:
        print(kw['device_ip'])
        try:
            m = get_connection(**kw)
            macsec_xml_filter= """<macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec"/>"""
            netconf_get_reply = m.get(('subtree', macsec_xml_filter))
            print(netconf_get_reply)
 
            print('Configuración MACSEC')
            ns = {'ciena': 'http://www.ciena.com/ns/yang/ciena-macsec'}
            state_data=[]
            root = ET.fromstring(str(netconf_get_reply))
            print(root)
            
            localmac=[]
            for fir in root.findall('.//ciena:local-mac-address', ns):
                y=fir.text
                localmac.append(y)
            chmac=localmac[0]          
   
            macsec_config = [e.text for e in root[0][0][2].iter()]
            macsec_config_cleaned = macsec_config[3:-4] 
            macsec_config_cleaned= [macsec_config_cleaned[i:i + 8] for i in range(0, len(macsec_config_cleaned), 8)]
            ca_data=[]
            print(macsec_config_cleaned)
            configs=CA()            
            for i in macsec_config_cleaned:
                name=i[0]
                new_xml_filter="""<macsec xmlns="http://www.ciena.com/ns/yang/ciena-macsec">
                <state><connection-association><name>"""+name+"""</name>
                </connection-association></state></macsec>"""
                netconf_get_reply = m.get(('subtree', new_xml_filter))
                root = ET.fromstring(str(netconf_get_reply))
                for st in root.findall('.//ciena:macsec-oper-state', ns):
                    y=st.text             
                mac=i[2]
                pf=i[4]
                ky=i[5]
                flp=i[6]
                stat=y
                print("CA:", name, "status:", stat)
                configs=CA(caname=name, remotemac=mac, pr=pf, kyc=ky, fp=flp, status=stat )
                db.session.add(configs)
                db.session.commit()
                #ca_data.append((ind, name, mac, pf, ky, status))

            print(configs)
            
            c_a = CA.query.all()
            print('revisar db', c_a)
            r=m.close_session()

            return render_template("table.html", c_a = c_a, chmac=chmac, ip=kw['device_ip'])

            #return render_template("data.html", form_data = form_data)
        except:
            logging.exception("Failed to create netconf session:")
            return render_template("404.html")
        
    else:
        flash("Please login first")
        return redirect(url_for('login'))

@app.route('/new_ca', methods=["GET", "POST"])
def new_ca():
    if request.method == 'POST':
        form_data = { "VLAN": request.form["VLAN"],"MAC": request.form["MAC"],"KC": request.form["KC"],"CA": request.form["CA"], "interval": request.form["interval"]}

        #####Service Creation from scratch
        port='7'
        New_CA_to_create = {"vid": request.form['VLAN'] }
        NewClassifier = createClassifier.render(New_CA_to_create)
        print(NewClassifier)        
        
        New_CA_to_create = {"vid": request.form['VLAN'] }
        NewFD = createFD.render(New_CA_to_create)
        print(NewFD)
   
        New_CA_to_create = {"vid": request.form['VLAN'], "port": port }
        NewFP = createFP.render(New_CA_to_create)
        print(NewFP)
        #MACSEC Config
        keyname="KC"+request.form['VLAN']
        
        New_CA_to_create = {"keyname": keyname, "newkey": request.form["KC"]}
        NewKC = createKC.render(New_CA_to_create)
        print(NewKC)

        pf="PF"+request.form['VLAN']
        New_CA_to_create = {"pf": pf, "keyinterval": request.form["interval"] }
        NewProfile = createMSprofile.render(New_CA_to_create)
        print(NewProfile)

        New_CA_to_create = {"port": port }
        ConfIntMSec = configIntMACSec.render(New_CA_to_create)
        print(ConfIntMSec)

        fp='FPVLAN'+request.form['VLAN']
        New_CA_to_create = {"CA": request.form['CA'], "pf": pf, "fp": fp, "remotemac": request.form["MAC"], "keyname": keyname }
        NewCA = createCA.render(New_CA_to_create)
        print(NewCA)
        print('done')
        
        try:
            
            c = get_connection(**kw)
            r= c.edit_config (target = "running", config=NewClassifier)
            r= c.edit_config (target = "running", config=NewFD)
            r= c.edit_config (target = "running", config=NewFP)
            r= c.edit_config (target = "running", config=NewKC)
            r= c.edit_config (target = "running", config=NewProfile)
            r= c.edit_config (target = "running", config=ConfIntMSec)         
            r= c.edit_config (target = "running", config=NewCA)
            
            flash("New CA Succesfully Created")

            return redirect(url_for('connections'))
        
        except:

            flash("Failed to establish a netconf session, please try again")
            logging.exception("Failed to create netconf session:")
            return redirect(url_for('form'))

        return "received"

@app.route('/editkey/<id>', methods=["GET", "POST"])
def editkey(id):
    cur = CA.query.filter_by(ca_id=id).first()
  
    values_loc={}
    if cur is None:
        abort(404)
    global values
    values = {
        'CA': cur.caname,
        'remotemac': cur.remotemac,
        'Profile': cur.pr,
        'KY': cur.kyc,
        'FP': cur.fp,  
        }
   
    values_loc=values
    print(values_loc['CA'])
    print(values['Profile'])
    print(values['KY'])
    print(values['remotemac'])
    print(values_loc['FP'])
    
    print('Diccionario global antes de pasar valores a la otra funcion')
    print(values_loc)

    ca_to_delete = { "CA" : values_loc['CA']}
    DeletedCA = deleteCA.render(ca_to_delete)
        #print(DeletedCA)
            
    ca_to_delete = { "pf" : values_loc['Profile']}
    DeletedPF = deletePF.render(ca_to_delete)
        #print(DeletedPF)

    ca_to_delete = { "KC" : values_loc['KY']}
    DeletedKC = deleteKC.render(ca_to_delete)
    #NewKey=request.form("newkey")

    try:
            
        m = get_connection(**kw)
        r= m.edit_config (target = "running", config=DeletedCA)
        r= m.edit_config (target = "running", config=DeletedPF)
        r= m.edit_config (target = "running", config=DeletedKC)
        r=m.close_session()

        flash("Old Key Successfuly Removed")
        return render_template("editkey.html", data=values_loc)
        
    except:

        flash("Failed to establish a netconf session, please try again")
        logging.exception("Failed to create netconf session:")
        return redirect(url_for('form'))

    return redirect(url_for('form'))

@app.route('/updatekey/<id>', methods=["GET", "POST"])
def updatekey(id):
    if request.method == 'POST':
        #newca = request.form["newca"]
        newkey = request.form["newkey"]
        keyinterval=request.form["interval"]
        #print(newca)
        print('Diccionario Global Values')
        print(values)
        
        New_CA_to_create = {"keyname": values['KY'], "newkey": newkey }
        NewKC = createKC.render(New_CA_to_create)
        print(NewKC)

        New_CA_to_create = {"pf": values['Profile'], "keyinterval": keyinterval }
        NewProfile = createMSprofile.render(New_CA_to_create)
        print(NewProfile)

        New_CA_to_create = {"CA": values['CA'], "pf": values['Profile'], "fp": values['FP'], "remotemac": values["remotemac"], "keyname": values['KY'] }
        NewCA = createCA.render(New_CA_to_create)
        print(NewCA)

        #flash("New Key Rendered Succesfully")
        
        try:
            
            m = get_connection(**kw)
            r= m.edit_config (target = "running", config=NewKC)
            r= m.edit_config (target = "running", config=NewProfile)
            r= m.edit_config (target = "running", config=NewCA)
            r=m.close_session()

            flash("New Key Updated Succesfully")
        
        except:

            flash("Failed to establish a netconf session, please try again")
            logging.exception("Failed to create netconf session:")
            return redirect(url_for('form'))
        

        return redirect(url_for('connections'))

@app.route('/delete/<string:id>', methods=["GET", "POST"])
def delete(id):
    print(type(id))
    id=int(id)
    test=CA.query.all()
    old_ca='None'
    old_pf='None'
    old_kc='None'
    for row in test:
        
        if id==row.ca_id:
            old_ca=row.caname
            old_pf=row.pr
            old_kc=row.kyc
            old_fp=row.fp
            break

    print(old_ca)
    print(old_pf)
    print(old_fp)
    print(kw['device_ip'])
    
    try:
        
        m = get_connection(**kw)
        ca_to_delete = { "CA" : old_ca}
        print(type(ca_to_delete), ca_to_delete)
        rendered_config = deleteCA.render(ca_to_delete)
        print(rendered_config)
        r= m.edit_config (target = "running", config=rendered_config)

        ca_to_delete = { "pf" : old_pf}
        print(type(ca_to_delete), ca_to_delete)
        rendered_config = deletePF.render(ca_to_delete)
        print(rendered_config)
        r= m.edit_config (target = "running", config=rendered_config)

        ca_to_delete = { "KC" : old_kc}
        print(type(ca_to_delete), ca_to_delete)
        rendered_config = deleteKC.render(ca_to_delete)
        print(rendered_config)
        r= m.edit_config (target = "running", config=rendered_config)
        
        ca_to_delete = { "FP" : old_fp}
        DeletedFP = deleteFP.render(ca_to_delete)
        r= m.edit_config (target = "running", config=DeletedFP)
        print("1111111111111111111111111111111111111111111111111111111111")
    
        flash("Successful Deletion")
        r=m.close_session()

        return redirect(url_for('connections'))

    except:

        flash("Failed to establish a netconf session, please try again")
        logging.exception("Failed to create netconf session:")
        return redirect(url_for('form'))

    return redirect(url_for('form'))
