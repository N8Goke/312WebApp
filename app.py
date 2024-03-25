from flask import Flask, make_response, render_template, request, redirect, url_for, abort, jsonify, send_file
from pymongo import MongoClient
import json
import bcrypt
import html
import secrets
import hashlib

mongo_client = MongoClient("mongo")
db = mongo_client["teamInnovation"]

user_collection = db["userInfo"]
chat_collection = db["projectChat"]
count_collection = db["chatcounter"]

app = Flask(__name__)

@app.route('/')
def index():
    #print("INDEX INDEX")
    return render_template("index.html")

# @app.route("/cat")
# def serve_cat():
#     return render_template('image.html')

@app.route("/cat.jpg", endpoint="image_route")
def image_route():
    return send_file('static/image/cat.jpg', mimetype="image/jpeg")


# Andy - insert username and password into db
@app.route('/registrationServer', methods = ['POST'])
def registrationServer():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    password2 = data.get('password2')

    #check if the two pw are the same
    if password != password2:
        return abort(404)

    #since its the same, we salt and hash the pw
    #then attempt to put it in db
    salt = bcrypt.gensalt()
    password = bcrypt.hashpw(password.encode(), salt)

    data2 = {}
    data2['username'] = username
    data2['password'] = password

    #check if username already exists. If it exists we exist, otherwise we insert
    query = {"username": username}
    found = user_collection.find_one(query)

    if found != None:
        return abort(404)
    else:
        user_collection.insert_one(data2)

        return "success"
        
    return abort(404)

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()

    username = data.get('username')
    login_pw = data.get('password')
    details = user_collection.find_one({'username':username})

    if details == None:
        print("db lookup invalid")
        return abort(404)

    stored_pw = details.get('password')
    is_Valid = bcrypt.checkpw(login_pw.encode(), stored_pw)

    if is_Valid:
        #atoken = secrets.token_bytes()
        atoken = bcrypt.gensalt()
        
        # Fix checking for the auth token cookie
        # if 'atoken' not in request.cookies:
        #     request.cookies['atoken'] = secrets.token_hex(20)

        # token = request.cookies.get('atoken')
        # temp_hash = hashlib.new('sha256')
        # temp_hash.update(token.encode())
        # hashed_token = temp_hash.hexdigest()

        user_collection.update_one({"username": username}, {"$set": {"atoken": atoken}})
        print("atoken updated")
        response = make_response()
        response.set_cookie("atoken", atoken, httponly = True)

        return response
    else:
        return abort(404)


@app.route('/logout', methods=['POST'])
def logout():
    print("temporary")
    if 'atoken' in request.cookies:
        token = request.cookies.get('atoken')
    
        temp_hash = hashlib.new('sha256')
        temp_hash.update(token.encode())
        hashed_token = temp_hash.hexdigest()

        if user_collection.find_one({'atoken': hashed_token}):
            user_collection.update_one({'atoken':hashed_token}, {"$set":{'atoken':""}})
            return redirect("/", code=302)


@app.route('/sendpost', methods=['POST'])
def sendpost():

    jsondata = request.get_json()
    
    count = list(count_collection.find())
    if len(count) == 0:
        count_collection.insert_one({"id" : 1})
        count = list(count_collection.find())

    #print(count)
    count = count[0]['id']
    count_collection.update_one({'id' : count}, {'$inc': {'id': 1}})

    username = "guest"
    if request.cookies.get("atoken") != None:
        details = user_collection.find_one({"atoken": request.cookies.get("atoken").encode()})
        #print(details)
        if details != None:
            username = details["username"]

    data = {}
    data["id"] = count
    data["username"] = username
    data["message"] = html.escape(jsondata.get("message"))
    data["likes"] = 0
    data["likedBy"] = []

    chat_collection.insert_one(data)

    data2 = {}
    data2["id"] = data["id"]
    data2["username"] = data["username"]
    data2["message"] = data["message"]
    data2["likes"] = data["likes"]
    
    return data2


@app.route('/allposts', methods = ['GET'])
def allposts():
    dbdata = chat_collection.find()

    allposts = []

    for post in dbdata:
        post2 = {}
        post2['id'] = post['id']
        post2['username'] = post['username']
        post2['message'] = post['message']
        post2['likes'] = post['likes']

        allposts.append(post2)

    #print(allposts)
    return jsonify(allposts)


@app.route('/like', methods = ['POST'])
def like():
    data = request.get_json()
    id = data.get("id")

    post_info = chat_collection.find_one({'id': id})
    print(post_info)
    likedBy = post_info["likedBy"]


    atoken = request.cookies.get("atoken")
    user_info = user_collection.find_one({"atoken": atoken.encode()})
    print(user_info)
    username = user_info["username"]

    if username in likedBy:
        return abort(404)
    else:
        likedBy = likedBy.append(username)
        chat_collection.update_one({'id' : id}, {'$inc': {'likes': 1}})
        chat_collection.update_one({'id' : id}, {'$push': {"likedBy" : username}})

    return "successfully liked"


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
# obsolete -- ignore
# def userCheck(jsonString):
#     updict = jsonString.loads()
#     username = updict["username"]
#     plaintextpass = updict["password"]
#     dbData = user_collection.findOne({"username": username})
#     if dbData == None:
#         return False
#     else:
#         is_valid = bcrypt.check_password_hash(dbData["password"], plaintextpass)
#         return is_valid




if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 8080)


