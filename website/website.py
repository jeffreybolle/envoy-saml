from flask import Flask, request

app = Flask(__name__)


@app.route('/')
def index():
    user = request.headers.get('x-auth-user')
    return f'Welcome {user}'


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
