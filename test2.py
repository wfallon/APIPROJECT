import random
import time
from urllib import quote, urlencode
import urllib2
import binascii
import hashlib
import hmac

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
# Or maybe it is called 0-legged process, or 1-legged...
# oauth 1.0a standard explains only 3-legged process, less-legged process
# is not an oauth 1.0a in fact.

####################################
# STEP 1: request to server resource
####################################

# Note, no auth token is present
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
print resp.read()