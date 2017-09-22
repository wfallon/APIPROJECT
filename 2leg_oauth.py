import oauth2
from urllib import quote, urlencode #for url-encode
import urllib2 #for getting and receiving data from server
import time #Unix timestamp import oauth2
import random

import binascii
import hashlib
import hmac


CONSUMER_KEY = '54fae896b065003ecf321fa9cbc90624059c127dc'
CONSUMER_SECRET = 'ac1e375ea2b80491d218cb4a8014c3c3'

get_timestamp = lambda: int(time.time())
get_nonce = lambda: str(str(random.getrandbits(64)) + str(get_timestamp()))
q = lambda x: quote(x, safe="~")

def get_sign(params, url, http_method, oauth_token_secret=""):
    """returns HMAC-SHA1 sign"""
    params.sort()
    normalized_params = urlencode(params)
    base_string = "&".join((http_method, q(url), q(normalized_params)))
    sig = hmac.new("&".join([CONSUMER_SECRET, oauth_token_secret]), base_string, hashlib.sha1)
    return binascii.b2a_base64(sig.digest())[:-1]



def build_request(url, method):
    params_confirmed_access_token = {
        'oauth_version': "1.0",
        'oauth_nonce': get_nonce(),
        'oauth_timestamp': int(time.time()),
        'oauth_token': "",
        'oauth_consumer_key': CONSUMER_KEY,
        'oauth_signature_method': "PLAINTEXT"
    }
    signature = get_sign(params_confirmed_access_token, url, method)
    params_confirmed_access_token.append(('oauth_signature', signature))
    

    req = oauth2.Request(method=method, url=url, parameters=params)
    signature_method = oauth2.SignatureMethod_HMAC_SHA1()
    req.sign_request(signature_method, consumer, None)
    return req
#end build_request



resourceUrl = 'https://api.schoology.com/v1/courses/'
request = build_request(resourceUrl,'GET')
u = urllib2.urlopen(request.to_url())
data = u.read()
print data



