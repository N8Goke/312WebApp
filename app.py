from flask import Flask, make_response, render_template, request
from pymongo import MongoClient
import json

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

#both registration and login forms should be on the index.html
# @app.route('/registration')
# def registration():
#     return render_template("registration.html")
#
# @app.route('/login')
# def login():
#     return render_template("login.html")


# Andy - insert username and password into db
@app.route('/registrationServer', methods = ['POST'])
def registrationServer():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    print(username, password)

    data2 = {}
    data2['username'] = username
    data2['password'] = password

    print(data2)
    chat_collection.insert_one(data2)

    return ("HTTP/l.1 200 OK\r\nContent-Length: 5\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n").encode() + ("hello").encode()



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


