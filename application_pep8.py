#!/usr/bin/python3

from flask import Flask, render_template, request, redirect, url_for, jsonify
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Maker, TransportationItem, User

# maintain the same connection per thread
import json
import os
import requests
from flask import flash

# New imports for authenication authorization
from flask import session as login_session
import random
import string
import urllib.request

# IMPORTS FOR THIS STEP oath
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response

from sqlalchemy import func
from sqlalchemy import inspect


app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "UdacityCatalog"

engine = create_engine('sqlite:///catalog.sqlite')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


# Create anti-forgery state token


@app.route('/login')
def showLogin():
    xrange = range
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    # return "The current session state is %s" % login_session['state']
    # render login template
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()

    # result = json.loads(h.request(url, 'GET')[1])
    response = urllib.request.urlopen(url)
    str_response = response.read().decode()
    result = json.loads(str_response)

    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps(
                                    'Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # see if user exists, if it doesn't make a new one
    user_id = getUserID(data["email"])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px; border-radius: 150px;"
    output += "-webkit-border-radius: 150px; -moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print("done!")
    return output

# User Helper Functions


def createUser(login_session):
    session = DBSession()
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    session = DBSession()
    user = session.query(User).filter_by(id=user_id).one()
    return user


def getUserID(email):
    session = DBSession()
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

    # DISCONNECT - Revoke a current user's token and reset their login_session


@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print('Access Token is None')
        response = make_response(json.dumps(
            'Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print('In gdisconnect access token is %s', access_token)
    print('User name is: ')
    print(login_session['username'])
    print('%s', access_token)
    print(login_session['access_token'])
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print('result is ')
    print(result)
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps(
            'Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

#####################


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data.decode()
    print("access token received %s" % access_token)

    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    print(url)
    h = httplib2.Http()
    result_s = h.request(url, 'GET')[1]
    result_b = result_s.decode()
    print("results: %s" % result_s)
    print("resultb: %s" % result_b)
    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange
        we have to split the token first on commas and select the first index
        which gives us the key : value
        for the server access token then we split it on colons to pull out the
        actual token value and replace the remaining quotes with nothing so
        that it can be used directly in the graph api calls
    '''

    token = result_b.split(',')[0].split(':')[1].replace('"', '')

    print(token)

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    print("url sent for API access:%s" % url)
    print("API JSON result: %s" % result)
    response = urllib.request.urlopen(url)
    str_response = response.read().decode()
    data = json.loads(str_response)
    # data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s'
    url += '&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    # result = h.request(url, 'GET')[1]
    # result = json.loads(h.request(url, 'GET')[1])
    response = urllib.request.urlopen(url)
    str_response = response.read().decode()
    data = json.loads(str_response)
    # data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;"'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]

    return "you have been logged out"

# Disconnect based on provider


@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('searchLanding'))
    else:
        flash("You were not logged in")
        return redirect(url_for('searchLanding'))


######################

@app.route('/maker/<int:maker_id>/transportation/JSON')
def makerTransportationJSON(maker_id):
    session = DBSession()
    maker = session.query(Maker).filter_by(id=maker_id).one()
    items = session.query(TransportationItem).filter_by(
        maker_id=maker_id).all()
    return jsonify(TransportationItems=[i.serialize for i in items])


@app.route('/maker/<int:maker_id>/transportation/<int:transportation_id>/JSON')
def transportationItemJSON(maker_id, transportation_id):
    session = DBSession()
    Transportation_Item = session.query(
        TransportationItem).filter_by(id=transportation_id).one()
    return jsonify(Transportation_Item=Transportation_Item.serialize)


@app.route('/maker/JSON')
def makersJSON():
    session = DBSession()
    makers = session.query(Maker).all()
    return jsonify(makers=[r.serialize for r in makers])


@app.route('/transportation/JSON')
def allTransportationItemJSON():
    session = DBSession()
    transportationItems = session.query(TransportationItem).all()
    return jsonify(
        transportationItems=[r.serialize for r in transportationItems])


def object_as_dict(obj):
    return {c.key: getattr(obj, c.key)
            for c in inspect(obj).mapper.column_attrs}


# Search Landing
@app.route('/')
def searchLanding():
    session = DBSession()
    makers = session.query(Maker).all()
    if 'username' in login_session:
        user = session.query(User).filter_by(
            email=login_session['email']).one()

    # for u in session.query(Maker).all():
    #     print (u.__dict__)
    # return "This page will show all my makers"
    SITE_ROOT = os.path.realpath(os.path.dirname(__file__))
    # response = requests.get("https://jsonplaceholder.typicode.com/todos")
    # makes = response.json()
    json_url = os.path.join(SITE_ROOT, "static", "makes.json")
    data = json.load(open(json_url))
    makerDict = json.dumps(data)
    if 'username' not in login_session:
        return render_template(
            'search.html', globalMakers=data, makers=makers,
            makerDict=makerDict, opacity='0.2')
    else:
        return render_template(
            'search.html', globalMakers=data, makers=makers,
            makerDict=makerDict, user=user, opacity='0.2')


# Show all makers
@app.route('/maker/')
def showMakers():
    session = DBSession()
    makers = session.query(Maker).all()
    if 'username' in login_session:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
    count_makers = session.query(func.count(makers))
    # return "This page will show all my makers"
    if 'username' not in login_session:
        return render_template(
            'publicmakers.html', makers=makers, count_makers=count_makers)
    else:
        return render_template(
            'makers.html', makers=makers, count_makers=count_makers, user=user)

# Show all vehicles


@app.route('/vehicles/')
def showVehicles():
    session = DBSession()
    transportationItems = session.query(TransportationItem).join(User)
    itemCount = session.query(TransportationItem).count()
    makers = session.query(Maker).all()
    # return "This page will show all my makers"
    return render_template(
        'showAllVehicles.html', items=transportationItems, itemCount=itemCount)

# Create a new maker


@app.route('/maker/new/', methods=['GET', 'POST'])
def newMaker():
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newMaker = Maker(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newMaker)
        session.commit()
        return redirect(url_for('showMakers'))
    else:
        return render_template('newMaker.html')
    # return "This page will be for making a new maker"

# Edit a maker


@app.route('/maker/<int:maker_id>/edit/', methods=['GET', 'POST'])
def editMaker(maker_id):
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')

    item = session.query(Maker).filter_by(id=maker_id).one()
    if login_session['user_id'] != item.user_id:
        return
        "<script>function myFunction() {alert('You are not authorized to modify this item.');} </script><body onload='myFunction()''>"
    editedMaker = session.query(
        Maker).filter_by(id=maker_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedMaker.name = request.form['name']
            return redirect(url_for('showMakers'))
    else:
        return render_template(
            'editMaker.html', maker=editedMaker)

    # return 'This page will be for editing maker %s' % maker_id

# Delete a maker


@app.route('/maker/<int:maker_id>/delete/', methods=['GET', 'POST'])
def deleteMaker(maker_id):
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(Maker).filter_by(id=maker_id).one()
    if login_session['user_id'] != item.user_id:
        return
        "<script>function myFunction() {alert('You are not authorized to modify this item.');} </script><body onload='myFunction()''>"
    makerToDelete = session.query(
        Maker).filter_by(id=maker_id).one()
    if request.method == 'POST':
        session.delete(makerToDelete)
        session.commit()
        return redirect(
            url_for('showMakers', maker_id=maker_id))
    else:
        return render_template(
            'deleteMaker.html', maker=makerToDelete)
    # return 'This page will be for deleting maker %s' % maker_id
#  join transportation and user for user name id image
# Show a maker transportation items


@app.route('/maker/<int:maker_id>/')
@app.route('/maker/<int:maker_id>/transportation/')
def showTransportation(maker_id):
    session = DBSession()
    if 'username' in login_session:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
    maker = session.query(Maker).filter_by(id=maker_id).one()
    items = session.query(TransportationItem).filter_by(
        maker_id=maker_id).join(User)
    if 'username' not in login_session:
        return render_template(
            'publictransportation.html', items=items, maker=maker)
    else:
        return render_template(
            'transportation.html', items=items, maker=maker, user=user)
    # return 'This page is the transportation for maker %s' % maker_id

# Create a new transportation item

# id = Column(Integer, primary_key = True)
# model = Column(String(80), nullable = False)
# year = Column(String(10), nullable = False)
# mileage = Column(Integer, nullable = False)
# trim = Column(String(80), nullable = True)
# vin =  Column(String(80), nullable = False)
# automatic = Column(Integer, nullable = True)
# description = Column(String(80), nullable = True)
# price = Column(String(8))
# maker_id = Column(Integer,ForeignKey('maker.id'))


@app.route(
    '/maker/<int:maker_id>/transportation/new/', methods=['GET', 'POST'])
def newTransportationItem(maker_id):
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    if 'username' in login_session:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
    maker = session.query(Maker).filter_by(id=maker_id).one()
    user = session.query(User).filter_by(email=login_session['email']).one()
    creator_id = getUserID(login_session['email'])
    if request.method == 'POST':
        newItem = TransportationItem(make=request.form['maker'],
                                     model=request.form['model'],
                                     year=request.form['year'],
                                     mileage=request.form['mileage'],
                                     trim=request.form['trim'],
                                     vin=request.form['vin'],
                                     automatic=request.form['automatic'],
                                     description=request.form['description'],
                                     price=request.form['price'],
                                     maker_id=maker_id, user_id=user.id)
        session.add(newItem)
        session.commit()

        return redirect(url_for(
            'showTransportation', maker_id=maker_id, user=user))
    else:
        return render_template(
            'newtransportationitem.html', maker_id=maker_id,
            maker_name=maker.name, user=user)
    return render_template(
        'newTransportationItem.html', maker=maker, creator=creator_id)
    # return 'This page is for making a new transportation item for maker %s'
    # %maker_id

# Edit a transportation item


@app.route('/maker/<int:maker_id>/transportation/<int:transportation_id>/edit',
           methods=['GET', 'POST'])
def editTransportationItem(maker_id, transportation_id):
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    if 'username' in login_session:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
    # maker = session.query(Maker).filter_by(id=maker_id).one()
    item = session.query(TransportationItem).filter_by(
        id=transportation_id).one()
    if login_session['user_id'] != item.user_id:
        return
        "<script>function myFunction() {alert('You are not authorized to modify this item.');}</script><body onload='myFunction()''>"
    editedItem = session.query(TransportationItem).filter_by(
        id=transportation_id).one()
    if request.method == 'POST':
        if request.form['make']:
            editedItem.make = request.form['make']
        if request.form['model']:
            editedItem.model = request.form['model']
        if request.form['year']:
            editedItem.year = request.form['year']
        if request.form['mileage']:
            editedItem.mileage = request.form['mileage']
        if request.form['trim']:
            editedItem.trim = request.form['trim']
        if request.form['vin']:
            editedItem.vin = request.form['vin']
        if request.form.get("automatic"):
            editedItem.automatic = 'true'
        else:
            editedItem.automatic = 'false'
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        session.add(editedItem)
        session.commit()
        return redirect(url_for('showTransportation', maker_id=maker_id))
    else:
        return render_template(
            'edittransportationitem.html', maker_id=maker_id,
            transportation_id=transportation_id, item=editedItem, user=user)
    # comment


# Delete a transportation item
@app.route(
    '/maker/<int:maker_id>/transportation/<int:transportation_id>/delete',
    methods=['GET', 'POST'])
def deleteTransportationItem(maker_id, transportation_id):
    session = DBSession()
    if 'username' not in login_session:
        return redirect('/login')
    item = session.query(TransportationItem).filter_by(
        id=transportation_id).one()
    if login_session['user_id'] != item.user_id:
        return
        "<script>function myFunction() {alert('You are not authorized to modify this item.');} </script><body onload='myFunction()''>"
    itemToDelete = session.query(TransportationItem).filter_by(
        id=transportation_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        return redirect(url_for(
            'showTransportation', maker_id=maker_id))
    else:
        return render_template(
            'deleteTransportationItem.html', item=itemToDelete)


@app.route('/maker/<int:maker_id>/transportation/<int:transportation_id>/view')
def viewTransportationItem(maker_id, transportation_id):
    session = DBSession()
    item = session.query(TransportationItem).filter_by(
        maker_id=maker_id).join(User).one()
    if 'username' in login_session:
        user = session.query(User).filter_by(
            email=login_session['email']).one()
    if 'username' not in login_session:
        return render_template(
            'publicviewTransportationItem.html',
            maker_id=maker_id, transportation_id=transportation_id, item=item)
    else:
        return render_template(
            'viewTransportationItem.html',
            maker_id=maker_id, transportation_id=transportation_id,
            item=item, user=user)

if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
