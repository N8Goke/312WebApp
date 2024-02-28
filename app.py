from flask import Flask, make_response, render_template

app = Flask(__name__)

@app.route('/')
def index():
    return render_template("index.html") 

@app.route('/style.css')
def css():
    response = make_response('/static/style.css')
    response.headers['Content-Type'] = 'text/css'
    return response

@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == '__main__':
    app.run(host = '0.0.0.0', port = 8080)