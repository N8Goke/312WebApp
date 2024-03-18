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

function allposts()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            
            chatMessages = document.getElementById("chat-messages");
            chatMessages.innerHTML += this.response;
        }
    }
    request.open("GET", "/allposts")
    request.send()
}