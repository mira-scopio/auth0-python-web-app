"""Python Flask WebApp Auth0 integration example
"""
import json
from functools import wraps
from os import environ as env
from six.moves.urllib.request import urlopen
from flask_cors import cross_origin
import constants
import flask
import requests
from dotenv import load_dotenv, find_dotenv
from flask import Flask
from flask import jsonify
from flask import redirect
from flask import render_template
from flask import request
from flask import session
from flask import url_for
from flask import _request_ctx_stack
from jose import jwt

from flask_oauthlib.client import OAuth
from six.moves.urllib.parse import urlencode

ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

AUTH0_CALLBACK_URL = env.get(constants.AUTH0_CALLBACK_URL)
AUTH0_CLIENT_ID = env.get(constants.AUTH0_CLIENT_ID)
AUTH0_CLIENT_SECRET = env.get(constants.AUTH0_CLIENT_SECRET)
AUTH0_DOMAIN = env.get(constants.AUTH0_DOMAIN)
AUTH0_AUDIENCE = env.get(constants.AUTH0_AUDIENCE)
API_AUDIENCE = 'https://scopiolabs.com/api'
ALGORITHMS = ["RS256"]
if AUTH0_AUDIENCE is '':
    AUTH0_AUDIENCE = 'https://' + AUTH0_DOMAIN + '/userinfo'
APP = Flask(__name__, static_url_path='/public', static_folder='./public')
APP.secret_key = constants.SECRET_KEY
APP.debug = True


# Format error response and append status code
def get_token_auth_header():
    """Obtains the Access Token from the Authorization Header
    """
    # auth = request.headers.get("Authorization", None)
    auth = request.cookies.get('authorization')

    if not auth:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                             "Authorization header is expected"}, 401)

    parts = auth.split()

    if parts[0].lower() != "bearer":
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must start with"
                             " Bearer"}, 401)
    elif len(parts) == 1:
        raise AuthError({"code": "invalid_header",
                         "description": "Token not found"}, 401)
    elif len(parts) > 2:
        raise AuthError({"code": "invalid_header",
                         "description":
                             "Authorization header must be"
                             " Bearer token"}, 401)

    token = parts[1]
    return token


def requires_auth(f):
    """Determines if the Access Token is valid
    """

    @wraps(f)
    def decorated(*args, **kwargs):
        token = get_token_auth_header()
        response = requests.get("https://" + AUTH0_DOMAIN + "/.well-known/jwks.json")
        jwks = response.json()
        # jwks = json.loads(jsonurl.read())
        unverified_header = jwt.get_unverified_header(token)
        rsa_key = {}
        for key in jwks["keys"]:
            if key["kid"] == unverified_header["kid"]:
                rsa_key = {
                    "kty": key["kty"],
                    "kid": key["kid"],
                    "use": key["use"],
                    "n": key["n"],
                    "e": key["e"]
                }
        if rsa_key:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=API_AUDIENCE,
                    issuer="https://" + AUTH0_DOMAIN + "/"
                )
            except jwt.ExpiredSignatureError:
                raise AuthError({"code": "token_expired",
                                 "description": "token is expired"}, 401)
            except jwt.JWTClaimsError:
                raise AuthError({"code": "invalid_claims",
                                 "description":
                                     "incorrect claims,"
                                     "please check the audience and issuer"}, 401)
            except Exception:
                raise AuthError({"code": "invalid_header",
                                 "description":
                                     "Unable to parse authentication"
                                     " token."}, 400)

            _request_ctx_stack.top.current_user = payload
            return f(*args, **kwargs)
        raise AuthError({"code": "invalid_header",
                         "description": "Unable to find appropriate key"}, 400)

    return decorated


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@APP.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


@APP.errorhandler(Exception)
def handle_auth_error(ex):
    response = jsonify(ex)
    return response


oauth = OAuth(APP)

auth0 = oauth.remote_app(
    'auth0',
    consumer_key=AUTH0_CLIENT_ID,
    consumer_secret=AUTH0_CLIENT_SECRET,
    request_token_params={
        'scope': 'openid profile',
        'audience': API_AUDIENCE
    },
    base_url='https://%s' % AUTH0_DOMAIN,
    access_token_method='POST',
    access_token_url='/oauth/token',
    authorize_url='/authorize',
)


# def requires_auth(f):
#     @wraps(f)
#     def decorated(*args, **kwargs):
#         if constants.PROFILE_KEY not in session:
#             return redirect('/login')
#         return f(*args, **kwargs)
#     return decorated


# Controllers API
@APP.route('/')
def home():
    return render_template('home.html')


@APP.route('/callback')
def callback_handling():
    resp = auth0.authorized_response()
    if resp is None:
        raise AuthError({'code': request.args['error'],
                         'description': request.args['error_description']}, 401)

    access_token = resp['access_token']
    # url = 'https://' + AUTH0_DOMAIN + '/userinfo'
    # headers = {'authorization': 'Bearer ' + access_token}
    # resp = requests.get(url, headers=headers)
    # userinfo = resp.json()
    #
    # session[constants.JWT_PAYLOAD] = userinfo
    #
    # session[constants.PROFILE_KEY] = {
    #     'user_id': userinfo['sub'],
    #     'name': userinfo['name'],
    #     'picture': userinfo['picture']
    # }

    response = flask.make_response(redirect('/api/public'))
    response.set_cookie('authorization', 'Bearer ' + access_token)
    return response


@APP.route('/login')
def login():
    return auth0.authorize(callback=AUTH0_CALLBACK_URL)


@APP.route('/logout')
def logout():
    # session.clear()
    params = {'returnTo': url_for('home', _external=True), 'client_id': AUTH0_CLIENT_ID}
    return redirect(auth0.base_url + '/v2/logout?' + urlencode(params))


# This doesn't need authentication
@APP.route("/api/public")
@cross_origin(headers=['Content-Type', 'Authorization'])
def public():
    response = "All good. You don't need to be authenticated to call this"
    return jsonify(message=response)


# This does need authentication
@APP.route("/api/private")
@cross_origin(headers=['Content-Type', 'Authorization'])
@requires_auth
def private():
    response = "All good. You only get this message if you're authenticated"
    return jsonify(message=response)


@APP.route('/dashboard')
@requires_auth
def dashboard():
    token = get_token_auth_header()
    url = 'https://' + AUTH0_DOMAIN + '/userinfo'
    headers = {'authorization': 'Bearer ' + token}
    resp = requests.get(url, headers=headers)
    userinfo = resp.json()

    JWT_PAYLOAD = userinfo

    PROFILE_KEY = {
        'user_id': userinfo['sub'],
        'name': userinfo['name'],
        'picture': userinfo['picture']
    }

    return render_template('dashboard.html',
                           userinfo=PROFILE_KEY,
                           userinfo_pretty=json.dumps(JWT_PAYLOAD, indent=4))


if __name__ == "__main__":
    APP.run(host='0.0.0.0', port=env.get('PORT', 4000))
