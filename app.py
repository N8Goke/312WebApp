from flask import Flask, make_response, render_template, request, redirect, url_for, abort
from pymongo import MongoClient
import json
import bcrypt

mongo_client = MongoClient("mongo")
db = mongo_client["teamInnovation"]
# user_collection = db["userInfo"]
chat_collection = db["projectChat"]

app = Flask(__name__)

@app.route('/')
def index():
    print("INDEX INDEX")
    return render_template("index.html")

@app.route("/cat")
def serve_cat():
    return render_template('image.html')


# Andy - insert username and password into db
@app.route('/registrationServer', methods = ['POST'])
def registrationServer():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    print(username, password)

    salt = bcrypt.gensalt()
    password = bcrypt.hashpw(password.encode(), salt)

    data2 = {}
    data2['username'] = username
    data2['password'] = password

    print(data2)

    query = {"username": username}
    found = chat_collection.find_one(query)

    if found != None:
        return abort(404)
    else:

        chat_collection.insert_one(data2)

        return "success"
        
    return abort(404)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    login_pw = data.get('password')
    details = chat_collection.find_one({'username':username})
    stored_pw = details.get('password')
    is_Valid = bcrypt.checkpw(stored_pw, login_pw)
    if is_Valid:
        

@app.route('/style.css')
def css():
    response = make_response('/static/style.css')
    response.headers['Content-Type'] = 'text/css'
    return response

# Sets nosniff to all requests.
@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

# Nate/Danny - Check if username/pass exist in database collection
def userCheck(jsonString):
    updict = jsonString.loads()
    username = updict["username"]
    plaintextpass = updict["password"]
    dbData = chat_collection.findOne({"username": username})
    if dbData == None:
        return False
    else:
        is_valid = bcrypt.check_password_hash(dbData["password"], plaintextpass)
        return is_valid




if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 8080)


