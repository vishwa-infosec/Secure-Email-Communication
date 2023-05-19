#importing necessary packages
import io
from flask import Flask, request, render_template, make_response, send_file
from flask_mail import Mail, Message
from crypto import generate_key_pair, encrypt_message, decrypt_message, serialize_private_key, serialize_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key, load_pem_public_key
from mail import decodeMail
import base64

app = Flask(__name__)

#configuration of flask app
app.secret_key = 'ar#WxWc2AxRT6ulH9n3S7&gXjPj2XE!k0c6Iz&5A57d5I%NAlq'
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['USE_TLS'] = True
app.config['MAIL_USE_SSL'] = True
app.config['MAIL_USERNAME'] = 'vishwacybersec@gmail.com'
app.config['MAIL_PASSWORD'] = 'pymmaplqssnoldxc'
app.config['MAIL_DEFAULT_SENDER'] = 'vishwacybersec@gmail.com'

#initializing mail in flask app
mail = Mail(app)

#route for the homepage
@app.route('/')
def index():
    return render_template('form.html')

#route for send page
@app.route('/send', methods=['POST', 'GET'])
def send(): 
    public_key = request.files['publickey']
    public_key.save('public_key.pem')
    recipient = request.form['recipient']
    message = request.form['message']
    subject = request.form['subject']
    
    message = bytes(message, 'utf-8')
    subject = bytes(subject, 'utf-8')
    # Load the public key from file
    with open("public_key.pem", "rb") as key_file:
        key_bytes = key_file.read()
    public_key = load_pem_public_key(key_bytes)
    cipherMsg = encrypt_message(message, public_key)
    encodedCipherMsg = base64.b64encode(cipherMsg)
    cipherSub = encrypt_message(subject, public_key)
    encodedCipherSub = base64.b64encode(cipherSub)
    
    
    attachment = request.files['attachment']
    filename = ''
    if attachment:
        filename = attachment.filename
        attachment.save(filename)
    
    # Create the message object with the encrypted subject and message
    msg = Message(subject=encodedCipherSub.decode(), sender='vishwacybersec@gmail.com', recipients=[recipient])
    msg.body = encodedCipherMsg.decode()
    # Attach the file if provided
    if attachment:
        with app.open_resource(filename) as f:
            msg.attach(filename, 'application/octet-stream', f.read())
    try:
        mail.send(msg)
        success = True
    except Exception as e:
        print(str(e))
        success = False

    return render_template('result.html', success=success)



@app.route('/generate-keys', methods=['GET','POST'])
def generate_keys():
    # Serialize private and public keys
    private_key, public_key = generate_key_pair()
    with open("private_key.pem", "wb") as f:
        f.write(serialize_private_key(private_key))
    with open("public_key.pem", "wb") as f:
        f.write(serialize_public_key(public_key))
    # Create responses for downloading the keys
    public_key_response = make_response(send_file(io.BytesIO(serialize_public_key(public_key)), as_attachment=True, download_name='public_key.pem'))
    private_key_response = make_response(send_file(io.BytesIO(serialize_private_key(private_key)), as_attachment=True, download_name='private_key.pem'))
    # Render the template with the generated keys
    return render_template('generate-keys.html',public_key=serialize_public_key(public_key).decode(), private_key=serialize_private_key(private_key).decode(), public_key_response=public_key_response, private_key_response=private_key_response)

@app.route('/download-public-key', methods=['GET'])
def download_public_key():
    return send_file('public_key.pem', download_name='public_key.pem', as_attachment=True)

@app.route('/download-private-key', methods=['GET'])
def download_private_key():
    return send_file('private_key.pem' , download_name='private_key.pem', as_attachment=True)

@app.route('/decryptForm', methods=['GET', 'POST'])
def decryptForm():
    return render_template('decryptForm.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    email = request.files['email']
    private_key = request.files['privatekey']
    private_key.save('private_key.pem')
    filename = ''
    if email:
        filename = email.filename
        email.save(filename)
        subject, body = decodeMail(filename)
        decodedSub = base64.b64decode(subject)
        decodedBody = base64.b64decode(body)
        with open("private_key.pem", "rb") as key_file:
            key_bytes = key_file.read()
        print(len(key_bytes))
        deserialized_private_key = load_pem_private_key(key_bytes, password=None)
        print(deserialized_private_key)
        print(len(subject))
        print(type(body))
        subject = decrypt_message(decodedSub , deserialized_private_key)
        body = decrypt_message(decodedBody, deserialized_private_key)
        decrypted = True
    return render_template('decryptResult.html', subject=subject.decode(), body=body.decode(), decrypted=decrypted)


if __name__ == '__main__':
    app.run(debug=True)
