from flask import Flask, request, jsonify, render_template, redirect, url_for
from werkzeug.utils import secure_filename
import os
import json
from flask_jwt_extended import JWTManager, jwt_required, create_access_token
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_oauthlib.client import OAuth

app = Flask(__name__, template_folder='template')

# Configure JWT setting
app.config['JWT_SECRET_KEY'] = 'raju123'  # Replace with your secret key
jwt = JWTManager(app)

# Configure rate limiting 5 per minute
limiter = Limiter(app, default_limits=["5 per minute"])

# Set the upload folder and allowed file extensions
app.config['UPLOAD_FOLDER'] = 'uploads'  # Replace with your upload folder
app.config['ALLOWED_EXTENSIONS'] = set(['txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'])

# Function to check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

database = {}

# Initialize Flask-OAuthlib
oauth = OAuth(app)

# Configure Google OAuth
google = oauth.remote_app(
    'google',
    consumer_key='697757396448-psugu8aap27k1kv2rm3n1vblrsjj9vuf.apps.googleusercontent.com',
    consumer_secret='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',
    request_token_params={
        'scope': 'email',
    },
    base_url='https://www.googleapis.com/oauth2/v1/',
    request_token_url=None,
    access_token_method='POST',
    access_token_url='https://accounts.google.com/o/oauth2/token',
    authorize_url='https://accounts.google.com/o/oauth2/auth',
)

@app.route('/')
def hello():
    return render_template('login.html')

@app.route('/loginForm', methods=['POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        if email in database and database[email] == password:
            # Generate a JWT token
            access_token = create_access_token(identity=email)
            # Include the token in the response
            return jsonify(access_token=access_token, info='Log in successfully')
        else:
            return render_template('login.html', info='Invalid email or password')

    return render_template('RegistrationForm.html')

@app.route('/signup')
def signup():
    return render_template('RegistrationForm.html')

@app.route('/RegistrationForm', methods=['POST'])
def RegistrationForm():
    name = request.form['fullname']
    email = request.form['email']
    password = request.form['password']
    cpassword = request.form['cpassword']

    if password != cpassword:
        return render_template('RegistrationForm.html', info='Your Password is not matching')

    database[email] = password
    return redirect(url_for('hello'))

@app.route('/uploader', methods=['POST'])
@jwt_required()
def uploader():
    if 'file1' not in request.files:
        return jsonify({'error': 'No file part'})

    file = request.files['file1']

    if file.filename == '':
        return jsonify({'error': 'No selected file'})

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
        image_url = url_for('view_image', image_filename=filename)
        return render_template('imageViewer.html', image_url=image_url)
    else:
        return jsonify({'error': 'Invalid file'})

# Add a new route for image viewing
@app.route('/view_image/<image_filename>')
def view_image(image_filename):
    # Assuming images are stored in the UPLOAD_FOLDER
    image_url = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
    return render_template('imageViewer.html', image_url=image_url)

# Redirect to Google login
@app.route('/google_login')
def google_login():
    return google.authorize(callback=url_for('google_authorized', _external=True))

# Handle the Google OAuth callback
@app.route('/google_authorized')
@google.authorized_handler
def google_authorized(resp):
    if resp is None or resp.get('access_token') is None:
        return 'Access denied: reason={} error={}'.format(
            request.args['error_reason'],
            request.args['error_description']
        )
    # Store user information as needed and log the user in
    # You can use resp['access_token'] to make API requests on behalf of the user

if __name__ == '__main__':
    app.run()