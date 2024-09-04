import bcrypt
import os
import requests
import tweepy

from flask import Flask, flash, redirect, render_template, request, session, jsonify, make_response, url_for
from flask_session import Session
from cs50 import SQL
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity, create_refresh_token, verify_jwt_in_request
from datetime import timedelta
from cryptography.fernet import Fernet
from werkzeug.serving import make_ssl_devcert
from dotenv import load_dotenv

app = Flask(__name__)

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

jwt = JWTManager(app)

app.config["JWT_SECRET_KEY"] = "ad4c3c55884f75c874f07dc6c32c3976"
app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_COOKIE_SECURE'] = False
app.config['JWT_ACCESS_COOKIE_NAME'] = 'access_token_cookie'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(minutes=15)
app.config['JWT_REFRESH_COOKIE_NAME'] = 'refresh_token_cookie'
app.config['JWT_REFRESH_TOKEN_EXPIRES'] = timedelta(days=30)

db = SQL("sqlite:///SocialPulse.db")

key = Fernet.generate_key()
cipher_suite = Fernet(key)

load_dotenv('config.env')

api_key = os.getenv("API_KEY")
api_key_secret = os.getenv("API_KEY_SECRET")
access_token = os.getenv("ACCESS_TOKEN")
access_token_secret = os.getenv("ACCESS_TOKEN_SECRET")

secret_key = os.getenv("SECRET_KEY")

auth = tweepy.OAuth1UserHandler(api_key, api_key_secret, callback='https://b43a-155-93-238-211.ngrok-free.app/callback')

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/logout")
def logout():

    response = make_response(redirect(url_for('login')))
    response.delete_cookie('access_token_cookie')
    response.delete_cookie('refresh_token_cookie')

    session.clear()

    return response


@app.route("/", methods=["GET", "POST"])
@jwt_required(optional=True)
def index():

    if not get_jwt_identity():
        return redirect(url_for("login"))

    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "GET":
        return render_template("register.html")

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        email_address = request.form.get("email_address")
        confirm_password = request.form.get("confirm_password")

        verify_input = input_validation(username, password, confirm_password, email_address)

        if verify_input:
            return verify_input

        try:
            password_salt = bcrypt.gensalt()

            hashed_password = bcrypt.hashpw(password.encode('utf-8'), password_salt)

            db.execute("INSERT INTO users (username, email_address, hash) VALUES(?, ?, ?)",
                       username, email_address, hashed_password)

            user_id_check = db.execute("SELECT last_insert_rowid()")

            user_id = user_id_check[0]["last_insert_rowid()"]

            session["user_id"] = user_id

            return redirect('/login')

        except Exception as e:
            print(f"Error occurred: {e}")
            return "Error occurred while processing"


@app.route("/login", methods=["GET", "POST"])
def login():

    print("login")
    session.clear()

    if request.method == "POST":

        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            flash("Must provide username")
            return redirect(url_for('login'))

        elif not password:
            flash("Must provide password")
            return redirect(url_for('login'))

        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        if len(rows) != 1 or not bcrypt.checkpw(password.encode(), rows[0]["hash"]):
            flash("Invalid username and/or password")
            return redirect(url_for('login'))

        session["user_id"] = rows[0]["id"]

        access_token = create_access_token(identity=session["user_id"], fresh=True)
        refresh_token = create_refresh_token(identity=session["user_id"])

        access_token_encrypted = cipher_suite.encrypt(access_token.encode())
        refresh_token_encrypted = cipher_suite.encrypt(refresh_token.encode())

        response = make_response(redirect(url_for('index')))

        response.set_cookie('access_token_cookie', access_token, httponly=True)
        response.set_cookie('refresh_token_cookie', refresh_token, httponly=True)

        db.execute(
            "UPDATE users SET access_token = ?, refresh_token = ? WHERE id = ?", access_token_encrypted, refresh_token_encrypted, session[
                'user_id']
        )

        return response

    else:
        return render_template("login.html")


@app.route('/errorpage', methods=['GET'])
def errorpage():

    return render_template("errorpage.html")


def get_auth_url(client_id, redirect_uri, scope):

    base_url = "https://api.instagram.com/oauth/authorize"
    return f"{base_url}?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&response_type=code"


@app.route('/auth/instagram')
def auth_instagram():

    client_id = "469586486062131"
    redirect_uri = "https://3e3f-155-93-238-211.ngrok-free.app/auth"
    scope = "user_profile,user_media"
    auth_url = get_auth_url(client_id, redirect_uri, scope)

    return redirect(auth_url)

@app.route('/continue_with_x')
def continue_with_x():
    try:
        redirect_url = auth.get_authorization_url()
        session['request_token'] = auth.request_token
        return redirect(redirect_url)
    except tweepy.TweepyException as e:
        return f'Error! Failed to get request token. {e}'

'''@app.route('/callback')
def callback():
    request_token = session.pop('request_token')
    auth.request_token = request_token
    verifier = request.args.get('oauth_verifier')
    try:
        auth.get_access_token(verifier)
        api = tweepy.API(auth)
        user = api.me()
        return f'Logged in as {user.name} with {user.followers_count} followers and {user.statuses_count} tweets.'
    except tweepy.TweepyException as e:
        return f'Error! Failed to get access token. {e}'''

@app.route('/deauth', methods=['POST'])
def deauth():

    user_id = request.form.get('user_id')

    deauth_id_search = db.execute("SELECT id FROM users WHERE id = ?", user_id)

    if deauth_id_search == []:
        return "User not found", 404

    if deauth_id_search:

        deauth_id = deauth_id_search[0]["id"]

        db.execute(
            "UPDATE users SET access_token = '', refresh_token = '' WHERE id = ?", deauth_id
        )

        return "Deauthorized", 200
    
    else:
        return "User not found", 404

@app.route('/privacypolicy')
def display_policy():

    return render_template("privacypolicy.html")


@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):

    return jsonify({
        'message': 'The token has expired',
        'error': 'token_expired'
    }), 401


@app.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
def refresh():

    current_user = get_jwt_identity()

    new_access_token = create_access_token(identity=current_user, fresh=False)

    response = jsonify({'access_token': new_access_token})
    response.set_cookie('access_token_cookie', new_access_token, httponly=True)

    return response


@app.route('/data_deletion', methods=['POST'])
def data_deletion():

    signed_request = request.form.get('signed_request')
    data = parse_signed_request(signed_request)
    user_id = data['user_id']

    confirmation_code = str(uuid.uuid4())
    status_url = f'http://127.0.0.1:5000/data_deletion?id={confirmation_code}'

    response_data = {
        'url': status_url,
        'confirmation_code': confirmation_code
    }
    return jsonify(response_data)


@app.route('/twitter/<username>', methods=['GET'])
def tweet_count(username):

    try:
        user_id = get_user_id(username)
        url = create_url(username)
        params = get_params()
        json_response = connect_to_endpoint(url, params)
        return jsonify(json_response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def input_validation(username, password, confirm_password, email_address):

    special_characters = ['!', '"', '#', '$', '%', '&', '\\', "'",
                          '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~']

    if not username:
        return "Username cannot be blank"

    if not password:
        return "Password cannot be blank"

    if not email_address:
        return "Email address cannot be blank"

    if password != confirm_password:
        return "Passwords do not match"

    try:
        username_check = db.execute("SELECT username FROM users WHERE username = ?", username)

        if username_check:
            current_username = username_check[0]['username']
            if username == current_username:
                return "Username already exists"

    except Exception as e:
        return f"Error occurred while checking username: {e}"

    try:
        email_address_check = db.execute(
            "SELECT email_address FROM users WHERE email_address = ?", email_address)

        if email_address_check:
            current_email_address = email_address_check[0]['email_address']
            if email_address == current_email_address:
                return "Email address already exists"

    except Exception as e:
        return f"Error occurred while checking email address: {e}"

    if len(password) < 8:
        return "Password should have at least 8 characters"

    if not any(char in special_characters for char in password):
        return "Password must have at least 1 special character"

    return None


if __name__ == "__main__":
    app.run(ssl_context=('cert.pem', 'key.pem'))
