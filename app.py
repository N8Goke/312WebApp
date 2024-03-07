from flask import Flask, make_response, render_template
from pymongo import MongoClient
from flask_bcrypt import Bcrypt

mongo_client = MongoClient("mongo")
db = mongo_client["teamInnovation"]
chat_collection = db["projectChat"]

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html")

@app.route("/cat")
def serve_cat():
    return render_template('image.html')

@app.route('/registration')
def registration():
    return render_template("registration.html") 

@app.route('/login')
def login():
    return render_template("login.html")

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