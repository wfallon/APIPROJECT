import random
import time
from urllib import quote, urlencode
import urllib2
import binascii
import hashlib
import hmac

from flask import Flask, render_template, request
import requests

app = Flask(__name__)

# Constants given by service provider
CONSUMER_KEY = '54fae896b065003ecf321fa9cbc90624059c127dc'
CONSUMER_SECRET = 'ac1e375ea2b80491d218cb4a8014c3c3'



# Values that choose client application

API_RESOURCE_URL = 'https://api.schoology.com/v1/courses/'

q = lambda x: quote(x, safe="~")
get_timestamp = lambda: int(time.time())
get_nonce = lambda: str(str(random.getrandbits(64)) + str(get_timestamp()))

def get_sign(params, url, http_method, oauth_token_secret=""):
    """returns HMAC-SHA1 sign"""
    params.sort()
    normalized_params = urlencode(params)
    base_string = "&".join((http_method, q(url), q(normalized_params)))
    sig = hmac.new("&".join([CONSUMER_SECRET, oauth_token_secret]), base_string, hashlib.sha1)
    return binascii.b2a_base64(sig.digest())[:-1]

# Start oauth 1.0 2-legged process
params_confirmed_access_token = [
                                 ('oauth_consumer_key', CONSUMER_KEY),
                                 ('oauth_nonce', get_nonce()),
                                 ('oauth_signature_method', "HMAC-SHA1"),
                                 ('oauth_timestamp', get_timestamp()),
                                 ('oauth_version', '1.0'),
                                 ]

# signature
signature = get_sign(params_confirmed_access_token, API_RESOURCE_URL, "GET")
params_confirmed_access_token.append(('oauth_signature', signature))

url = "?".join((API_RESOURCE_URL, urlencode(params_confirmed_access_token)))
resp = urllib2.urlopen(url)
assert resp.code == 200

@app.route('/redirect', methods=['POST'])
def redirect():
    return resp.read()

@app.route('/')
def index():
    return render_template('index.html')

if __name__ == '__main__':
    app.run(debug=True)


#print resp.read()
