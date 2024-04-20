function sendpost()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
        }
    }
    var message = document.getElementById("message").value
    data = {"message": message}

    document.getElementById("message").value = ""

    request.open("POST", "/sendpost")
    request.setRequestHeader('Content-Type', 'application/json')
    request.send(JSON.stringify(data))

}
function profilepic(){
    console.log("prof pic called")
    request = request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            profilePic = document.getElementById("ProfilePic");
            profilePic.innerHTML = '<img src="../static/image/'+JSON.parse(this.response)+'" alt="buttonpng" width="100" height="100"/><br/>'
            profilePic.innerHTML += '<form action="logout" method="post" enctype="applications/x-www-form-urlencoded">'
             + '<button className="top-right-btn" onclick="logout()">Logout</button> </form>'
        }
    }
    request.open("GET", "/getprofpic")
    request.send()
}

function username()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            username = document.getElementById("your_username");
            username.append(this.response)
        }
    }
    request.open("GET", "/username")
    request.send()
}
function allposts()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            
            chatMessages = document.getElementById("chat-messages");
            
            response = JSON.parse(this.response)

            length = response.length
            chatMessages.innerHTML = ""

            for (let i = 0; i < length; i++) {
                post = document.createElement("div");
                post.className = "post";
                post.innerHTML = "<div class = 'box'/>"+ response[i]["username"] + ": " + response[i]["message"] + " - likes: " + response[i]["likes"] + "<button onclick='like(" + response[i]["id"] + ")'>Like</button></div/><br>";

                chatMessages.append(post)
            }


        }
    }
    request.open("GET", "/allposts")
    request.send()
}

function like(id)
{
    request = new XMLHttpRequest(); 

    data = {"id": id}

    request.open("POST", "/like")
    request.setRequestHeader('Content-Type', 'application/json')
    request.send(JSON.stringify(data))
}
function allusers()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);

            allusers = document.getElementById("allusers");

            response = JSON.parse(this.response)

            length = response.length
            
            for (let i = 0; i < length; i++) {
                post = document.createElement("div");
                post.className = "user";
                post.innerHTML = "<div class = 'box'/>" + response[i]["username"] + "<button onclick='dm()'>DM</button>" + "</div/><br>";

                allusers.append(post)
            }

        }
    }
    request.open("GET", "/allusers")
    request.send()

}

function dm()
{
    request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            window.location.replace("http://localhost:8080/dmpage");
        }
    }
    request.open("POST", "/dm")
    request.send()
}

function welcome(){
    allposts()
    username();
    allusers();
    profilepic()
    setInterval(allposts,5000)
}