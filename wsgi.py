import logging
import os
from flask import Flask, render_template, request, url_for, send_from_directory, Response, session, redirect
from flask.typing import TemplateGlobalCallable
from flask_login import (current_user, LoginManager,
                            login_user, logout_user,
                            login_required)
from werkzeug.utils import secure_filename

from utils import AESCipher

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)

UPLOAD_FOLDER: str = './uploads'
ALLOWED_EXTENSIONS: set = {'txt', 'json', 'docx', 'doc'}

app.logger.setLevel(logging.DEBUG)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'super secret key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(id):
    return User.query.filter_by(id=int(id)).first()

"""Database
"""
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    authenticated = db.Column(db.Boolean, default=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return '<User %r>' % self.username

    def is_authenticated(self):
        return True

    def is_active(self):   
        return True           

    def is_anonymous(self):
        return False
    def get_id(self):
        return str(self.id)

class Events(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.String(80), nullable=False)
    key = db.Column(db.String(120), nullable=False, default="hello")
    action = db.Column(db.String(120), nullable=False)
    created = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return str(id)

def getToken(token: str):
    """
    Get token function retieves user token and verifies if the user is allowed to use the service.
    """
    tokens = open('useraccess.txt', 'r').read().split('\n')

    if token in tokens:
        return True
    return False


def allowed_file(filename: str) -> bool:
    """Checks if file is of an allowed extension.
    """

    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=["GET"])
@login_required
def index() -> TemplateGlobalCallable:
    """Index Page (Function), renders the index.html template.
    1. User can upload file, usually raw text(txt).
    2. Can Input a Raw text in text area.
    3. Make A request to the Encrypt endpoint.
    4. Makes Request to the Decrypt endpoint.
    """

    app.logger.info("Index Page")

    author_name: str | None = None

    return render_template("index.html", name = author_name)


@app.route('/encrypt', methods=["GET", "POST"])
@login_required
def encryption() -> TemplateGlobalCallable:
    """Encrypted Page (Function), renders the encrypt.html template.
    1. Has an alert that the encryption was successfull or not.
    2. Encrypt the file or Text.
    3. Use a default Encryption Key if none was provided.
    """

    app.logger.info("Encrypt Page, With Encryption")

    message: dict = {
        "type": str,
        "body": str
    }

    if request.method == "POST":
        data = request.form
        
        text_plain: str = data['plain_text']

        if data['key']:
            encryption_key: str = data['key']
        else:
            encryption_key: str = "hello"

        encryption = AESCipher(encryption_key)
        encrypted_text: str = encryption.encrypt(text_plain)
        event = Events(content=encrypted_text, key=encryption_key, action="Encryption")
        db.session.add(event)
        db.session.commit()
        message["type"] = "success"
        message["body"] = "Encrypted Successfully!"
        session['encrypted'] = encrypted_text

    return render_template("encrypt.html", message = message, encrypted_text = encrypted_text)


@app.route('/decrypt', methods=["GET", "POST"])
@login_required
def decryption() -> TemplateGlobalCallable:
    """Decrypted Page (Function), renders the decrypt.html template.
    1. Has an alert that the decryption was successfull or not.
    2. Decrypt the file or Text.
    3. Use a default Decryption Key if none was provided.
    """

    app.logger.info("Deccrypt Page, With Decryption")

    message: dict = {
        "type": str,
        "body": str
    }

    if request.method == "POST":
        data = request.form
        text_plain: str = data['plain_text']

        if data['key']:
            decryption_key: str = data['key']
        else:
            decryption_key: str = "hello"
        try:
            decryption = AESCipher(decryption_key)
            decrypted_text: str | None = decryption.decrypt(text_plain)
            event = Events(content=decrypted_text, key=decryption_key, action="Decryption")
            db.session.add(event)
            db.session.commit()
            message["type"] = "success"
            message["body"] = "Decrypted Successfully!"
        except Exception:
            message["type"] = "danger"
            message["body"] = "Please Enter a valid decryption key!"
            decrypted_text = None
    return render_template("decrypt.html", message = message, decrypted_text = decrypted_text)

@app.route('/download_txt/<name>')
def download_txt(name: str):
    return Response(
        session['encrypted'],
        mimetype='text/plain',
        headers={'Content-disposition': f'attachment; filename={name}.txt'})

@app.route('/api/v1/encrypt/<text>/<key>/<token>', methods=["GET"])
def encrypt_api(text: str, key: str, token: str):
    
    if getToken(token):
        if request.method == "GET":
        
            text_plain: str = text

            if key:
                encryption_key: str = key
            else:
                encryption_key: str = "hello"

            encryption = AESCipher(encryption_key)
            encrypted_text: str = encryption.encrypt(text_plain)
            session['encrypted'] = encrypted_text

        return {"Encrypted text": encrypted_text}
    else:
        return {"Error": "Please provide a valid access token"}

@app.route('/api/v1/decrypt/<text>/<key>/<token>', methods=["GET"])
def decrypt_api(text: str, key: str, token: str):
    
    message: dict = {
        "type": str,
        "body": str
    }

    if getToken(token):
        if request.method == "GET":
            text_plain: str = text

            if key:
                decryption_key: str = key
            else:
                decryption_key: str = "hello"
            try:
                decryption = AESCipher(decryption_key)
                decrypted_text: str | None = decryption.decrypt(text_plain)
                message["type"] = "success"
                message["body"] = "Decrypted Successfully!"
            except Exception:
                message["type"] = "danger"
                message["body"] = "Please Enter a valid decryption key!"
                decrypted_text = None
        return {"decrypted text": decrypted_text, "message": message}

    else:
        return {"Error": "Please provide a valid access token"}

@app.route('/register', methods=["GET", "POST"])
def sign_up():
    
    app.logger.info("Encrypt Page, With Encryption")

    message: dict = {}

    if request.method == "POST":
        data = request.form

        if (User.query.filter_by(username=data['username']).first()):
            message['type'] = "danger"
            message['body'] = "Username choosen!"
        else:
            if data['token']:
                if getToken(data['token']):
                    me = User(username=data['username'], password=data['password'], is_admin=True)
                    db.session.add(me)
                    db.session.commit()
                    message['type'] = "success"
                    message['body'] = "User created"
                else:
                    message['type'] = "danger"
                    message['body'] = "Invalid Token"
            else:    
                me = User(username=data['username'], password=data['password'], is_admin=False)
                db.session.add(me)
                db.session.commit()
                message['type'] = "success"
                message['body'] = "User created"

    return render_template("register.html", message=message)

@app.route('/login', methods=["GET", "POST"])
def login():
    
    app.logger.info("Encrypt Page, With Encryption")

    message: dict = {}

    if request.method == "POST":
        data = request.form

        user = User.query.filter_by(username=data['username'], password=data['password']).first()

        if (user):
            login_user(user)
            return redirect(url_for('index'))
        else:
            message['type'] = "danger"
            message['body'] = "Invalid Username or Password"

    return render_template("login.html", message=message)

@app.route('/logout', methods=['GET'])
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/activities', methods=["GET", "POST"])
@login_required
def activity() -> TemplateGlobalCallable:

    app.logger.info("Admin Page")

    users = User.query.all()
    events = Events.query.all()

    return render_template("activity.html", users=users, events=events)

if __name__ == '__main__':
    db.create_all()
    app.run(host='0.0.0.0', port=8080)