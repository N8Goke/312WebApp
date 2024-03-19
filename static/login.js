function login()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            window.location.replace("")
            document.cookie = "auth=" + this.response;
        }
    }
    var username = document.getElementById("usernameL").value
    var password = document.getElementById("passwordL").value

    data = {"username": username, "password": password}
    request.open("POST", "/login")
    request.setRequestHeader('Content-Type', 'application/json')
    request.send(JSON.stringify(data))

}