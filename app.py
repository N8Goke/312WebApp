from flask import Flask, make_response, render_template, request, redirect, url_for, abort, jsonify, send_file, send_from_directory
from pymongo import MongoClient
from werkzeug.utils import secure_filename
import json
import bcrypt
import html
import secrets
import hashlib
import uuid
import os
import random

mongo_client = MongoClient("mongo")
db = mongo_client["teamInnovation"]

user_collection = db["userInfo"]
chat_collection = db["projectChat"]
count_collection = db["chatcounter"]
profile_collection = db["pfpics"]



upload_path = "static/image/"
allowed_extensions = {'jpg','jpeg'}

app = Flask(__name__)
app.config['UPLOAD_PATH'] = upload_path


upload_path = "static/image/"
app.config['UPLOAD_PATH'] = upload_path

@app.route('/')
def index():
    #print("INDEX INDEX")
    return render_template("index.html")

@app.route("/cat.jpg", endpoint="image_route")
def image_route():
    return send_file('static/image/cat.jpg', mimetype="image/jpeg")



# @app.route('/profile-pic', methods=['GET','POST'])
# def proflie_pic():
#     print(request)
#     print(request.files['file'])
#     if 'atoken' in request.cookies:
#         print("atoken pass")
#         atoken = request.cookies.get('atoken')
#         print(atoken)
#         temp_hash = hashlib.new('sha256')
#         print(temp_hash)
#         temp_hash.update(atoken.encode())
#         dbData = user_collection.find_one({'atoken': temp_hash.hexdigest()})
#         print(dbData)
#         if dbData == None:
#             print("dbdata none")
#             return abort(404)
#         else:
#             print("dbData found")
#             if request.method == 'POST':
#                 print("correct request")
#                 new_file = request.files['file']
#                 print(new_file)
#                 if new_file.filename == "":
#                     print("filename none")
#                     return redirect(request.url)
#                 if 'file' in request.files and new_file:
#                     print("processing file")
#                     secured_filename = secure_filename(new_file.filename)
#                     new_file.save(os.path.join(app.config['UPLOAD_PATH'], secured_filename))
#                     source = '<img src="' + secured_filename +'"width="100" height="100">'
#                     user= {"username": dbData["username"]}
#                     profLookup = profile_collection.find({"username": dbData["username"]})
#                     if profLookup != None:
#                         profile_collection.update_one(user,{"$set":{"profile":source}})
#                         return redirect("/", code=302)
#                     else:
#                         profile_collection.insert_one({"username": dbData["username"],"profile":source})
#                         return  redirect("/", code=302)
#     else:
#         print("guest upload")
#         return abort(404)


@app.route('/getprofpic', methods =['GET'])
def sendProfilePic():
    if 'atoken' in request.cookies:
        print("atoken found")
        usertoken_check= ""
        token = request.cookies.get('atoken')
        temp_hash = hashlib.new('sha256')
        temp_hash.update(token.encode())
        usertoken_check = user_collection.find_one({'atoken': temp_hash.hexdigest()})
        if usertoken_check == "":
            print("should be a guest")
            guestImage = '<img src="../static/image/Guestprofile.jpg" alt="buttonpng" width="100" height="100"/><br/>'
            testImage ="Guestprofile.png"
            response = make_response(json.dumps(testImage))
            response.status_code = 200
            return response
        username = usertoken_check["username"]
        print(profile_collection)
        print(username)
        profile = profile_collection.find_one({"username":username})
        print(profile["profile"])
        response = make_response(json.dumps(profile["profile"]))
        response.status_code = 200
        return response



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
    data2['username'] = html.escape(username)
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
        
        hash1 = hashlib.new('sha256')
        hash1.update(atoken)

        # Fix checking for the auth token cookie
        # if 'atoken' not in request.cookies:
        #     request.cookies['atoken'] = secrets.token_hex(20)

        # token = request.cookies.get('atoken')
        # temp_hash = hashlib.new('sha256')
        # temp_hash.update(token.encode())
        # hashed_token = temp_hash.hexdigest()

        user_collection.update_one({"username": username}, {"$set": {"atoken": hash1.hexdigest()}})
        print("atoken updated")
        response = make_response()
        response.set_cookie("atoken", atoken.decode(), max_age=3600, httponly = True)

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
            response = redirect("/", code=302)
            response.set_cookie("atoken", "deleted", max_age=3600, httponly = True)
            return response


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


        atoken = request.cookies.get("atoken")
        hash1 = hashlib.new('sha256')
        hash1.update(atoken.encode())

        details = user_collection.find_one({"atoken": hash1.hexdigest()})
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
    hash1 = hashlib.new('sha256')
    hash1.update(atoken.encode())


    user_info = user_collection.find_one({"atoken": hash1.hexdigest()})
    print(user_info)
    username = user_info["username"]

    if username in likedBy:
        return abort(404)
    else:
        likedBy = likedBy.append(username)
        chat_collection.update_one({'id' : id}, {'$inc': {'likes': 1}})
        chat_collection.update_one({'id' : id}, {'$push': {"likedBy" : username}})

    return "successfully liked"

@app.route('/username', methods = ["GET"])
def username():
    atoken = request.cookies.get("atoken")
    if atoken == None:
        return "Guest"
    
    hash1 = hashlib.new('sha256')
    hash1.update(atoken.encode())

    user_info = user_collection.find_one({"atoken": hash1.hexdigest()})

    if user_info == None:
        return "Guest"
    else:
        return user_info["username"]

@app.route('/style.css')
def css():
    response = make_response('/static/style.css')
    response.headers['Content-Type'] = 'text/css'
    return response

# Grabs the file extension from input and checks if it is in the allowed extensions (declared above)
# def allowed_file(filename):
#     return '.' in filename and \
#            filename.rsplit('.', 1)[1].lower() in allowed_extensions


@app.route('/profile-pic', methods=['GET','POST'])
def proflie_pic():
    print("here")
    if request.method == 'POST':
        print("post")
        new_file = request.files['file']
        # file_name = img_uuid+".jpg"
        if new_file.filename == "":
            print("empty filename")
            return redirect(request.url)
        if 'file' in request.files and new_file:
            print("good file is here")
            secured_filename = secure_filename(new_file.filename)
            new_file.save(os.path.join(app.config['UPLOAD_PATH'], secured_filename))

            # file_path = upload_path + secured_filename
            print(secured_filename)
            print(new_file)
            # check if user is authenticated or not
            usertoken_check = ""
            if 'atoken' in request.cookies:
                    print("atoken")
                    token = request.cookies.get('atoken')
                    temp_hash = hashlib.new('sha256')
                    temp_hash.update(token.encode())
                    usertoken_check = user_collection.find_one({'atoken': temp_hash.hexdigest()})
            source = '<img src="../static/image/' + secured_filename +'"width="100" height="100">'
            if usertoken_check != "": # If user is authenticated
                profLookup = profile_collection.find({"username": usertoken_check["username"]})

                if profLookup != None: #If user already has profile pic
                    profile_collection.update_one({"username": usertoken_check["username"]},{"$set":{"profile":secured_filename}})
                    profLookup = profile_collection.find({"username": usertoken_check["username"]})
                    print("Prof",profLookup)
                else:
                    profile_collection.insert_one({"username": usertoken_check["username"],"profile":secured_filename})
                    profLookup = profile_collection.find({"username": usertoken_check["username"]})
                    print("Prof", profLookup)

    return redirect("/")




@app.route('/upload-image', methods=['GET','POST'])
def upload_files():
    random_id = random.randint(1,999999999)
    # generated_uuid = uuid.uuid4()
    # img_uuid = str(generated_uuid)

    if request.method == 'POST':
        new_file = request.files['file']
        # file_name = img_uuid+".jpg"
        if new_file.filename == "":
            return redirect(request.url)
        if 'file' in request.files and new_file:
            secured_filename = secure_filename(new_file.filename)
            new_file.save(os.path.join(app.config['UPLOAD_PATH'], secured_filename))

            # file_path = upload_path + secured_filename
            print(secured_filename)
            print(new_file)
        # check if user is authenticated or not
            usertoken_check = ""
            if 'atoken' in request.cookies:
                if 'auth_token' in request.cookies:
                    token = request.cookies.get('atoken')
                    temp_hash = hashlib.new('sha256')
                    temp_hash.update(token.encode())
                    usertoken_check = user_collection.find_one({'atoken': temp_hash.hexdigest()})

            if usertoken_check != "": # If user is authenticated
                chat_collection.insert_one({"id":random_id,"username":usertoken_check.get('username'), "message":'<img src="' + secured_filename + '" alt="Image">',"likes":0})
            else: # User is guest
                chat_collection.insert_one({"id":random_id,"username":"Guest", "message":'<img src="' + secured_filename + '" alt="Image">',"likes":0})

    return redirect("/")


# Sets nosniff to all requests.
@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 8080)


