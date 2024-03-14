function register()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            window.location.replace("http://localhost:8080/");
        }
    }
    var username = document.getElementById("username").value
    var password = document.getElementById("password").value

    data = {"username": username, "password": password}
    request.open("POST", "/registrationServer")
    request.setRequestHeader('Content-Type', 'application/json')
    request.send(JSON.stringify(data))

}