function dm_usernames()
{
    request = new XMLHttpRequest();
    request.onreadystatechange = function () {
        if (this.readyState === 4 && this.status === 200) {
            console.log(this.response);
            users = document.getElementById("users")

            obj1 = JSON.parse(this.response)

            users.innerHTML += ("<h2>DM between " + obj1[0] + " and " + obj1[1] + "</h2><br>")
        }
    }
    request.open("GET", "/dm_usernames")
    request.send()
}
