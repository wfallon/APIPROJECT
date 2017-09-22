import oauth2
import urllib #for url-encode
import urllib2 #for getting and receiving data from server
import time #Unix timestamp import oauth2



def build_request(url, method):
    params = {
        'oauth_version': "1.0",
        'oauth_nonce': oauth2.generate_nonce(),
        'oauth_timestamp': int(time.time()),
        'oauth_token': "",
        'oauth_signature_method': "PLAINTEXT"
    }
    consumer = oauth2.Consumer(key='54fae896b065003ecf321fa9cbc90624059c127dc',secret='ac1e375ea2b80491d218cb4a8014c3c3')
    params['oauth_consumer_key'] = consumer.key
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



