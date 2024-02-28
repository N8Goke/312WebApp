function register()
{
    const request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
        }
    }
    var username = document.getElementById("username").value
    var password = document.getAnimations("password").value

    data = {"username": username, "password": password}
    request.open("POST", "../app.py")
    request.send(JSON.stringify(data))

}