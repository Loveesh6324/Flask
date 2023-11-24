import os
import pathlib
import requests
# import tensorflow as tf
# import numpy as np
# import cv2
from flask import Flask, jsonify, render_template, session, abort, redirect, request, url_for
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests
from authlib.integrations.flask_client import OAuth


app = Flask("Login App")

oauth = OAuth(app)
# model = tf.keras.models.load_model('dog_cat_model.h5')  
app.secret_key = "Loveesh"
app.config['GITHUB_CLIENT_ID'] = "8d22f2cf6b287a96fd08"
app.config['GITHUB_CLIENT_SECRET'] = "5ed13b1c12192352f887b114abac846164d687cf"

os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "74671101782-3vnjmv7874h848hnrehc9bta0jr7v6qg.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email",
            "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)


github = oauth.register (
  name = 'github',
    client_id = app.config["GITHUB_CLIENT_ID"],
    client_secret = app.config["GITHUB_CLIENT_SECRET"],
    access_token_url = 'https://github.com/login/oauth/access_token',
    access_token_params = None,
    authorize_url = 'https://github.com/login/oauth/authorize',
    authorize_params = None,
    api_base_url = 'https://api.github.com/',
    client_kwargs = {'scope': 'user:email'},
)

# def preprocess_image(image):
#     img = cv2.resize(image,(256, 256))
#     img = img.reshape(1, 256, 256, 3)
#     return img



@app.route('/')
def index():
    return render_template('login.html')



#Google API Calls
@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID,
        clock_skew_in_seconds=50
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    
    response={
        "status":"success",
        "message":"Callback successful"
        
    }
    # return redirect("/protected_area")
    return jsonify(response), 200


#Github API Calls
@app.route('/login/github')
def github_login():
    github = oauth.create_client('github')
    redirect_uri = url_for('github_authorize', _external=True)
    return github.authorize_redirect(redirect_uri)


@app.route('/login/github/authorize')
def github_authorize():
    github = oauth.create_client('github')
    token = github.authorize_access_token()
    resp = github.get('user').json()
    # print(f"\n{resp}\n")
    
    response={
        "status":"success",
        "message":"Callback successful"
        
    }
    # return redirect("/protected_area")
    return jsonify(response), 200



@app.route("/protected_area")
def protected_area():
    return render_template("index.html")


# @app.route('/predict', methods=['POST'])
# def predict():
#     file = request.files['image']
#     image = cv2.imdecode(np.fromstring(file.read(), np.uint8), cv2.IMREAD_UNCHANGED)
#     image = preprocess_image(image)
#     prediction = model.predict(image)
#     if prediction == 0:
#         result = 'Cat'
#     else:
#         result = 'Dog'
        
#     return render_template('prediction.html', result=result, file=file)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


if __name__ == "__main__":
    app.run(debug=True)
