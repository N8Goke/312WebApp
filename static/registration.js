function register()
{
    request = new XMLHttpRequest();   
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            window.location.replace("http://localhost:8080/");
        } 
        if (this.readyState == 4 && this.status != 200) {
            alert("username or password invalid")
        }
    }
    var username = document.getElementById("username").value
    var password = document.getElementById("password").value
    var password2 = document.getElementById("password2").value

    data = {"username": username, "password": password, "password2": password2}
    request.open("POST", "/registrationServer")
    request.setRequestHeader('Content-Type', 'application/json')
    request.send(JSON.stringify(data))

}