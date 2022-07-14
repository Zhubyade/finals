import logging
import os
from flask import Flask, render_template, request, url_for, send_from_directory, Response, session
from flask.typing import TemplateGlobalCallable
from werkzeug.utils import secure_filename

from utils import AESCipher

app = Flask(__name__)

UPLOAD_FOLDER: str = './uploads'
ALLOWED_EXTENSIONS: set = {'txt', 'json', 'docx', 'doc'}

app.logger.setLevel(logging.DEBUG)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = 'super secret key'

def allowed_file(filename: str) -> bool:
    """Checks if file is of an allowed extension.
    """

    return '.' in filename and \
        filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=["GET"])
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
        message["type"] = "success"
        message["body"] = "Encrypted Successfully!"
        session['encrypted'] = encrypted_text

    return render_template("encrypt.html", message = message, encrypted_text = encrypted_text)


@app.route('/decrypt', methods=["GET", "POST"])
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)