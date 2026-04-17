# -*- coding: utf-8 -*-
#
#   Copyright 2014 Forest Crossman
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.


from __future__ import print_function

import base64
import binascii
import hashlib
import hmac
import re
import string
import sys
import time
import xml.etree.ElementTree as etree
# Python 2/3 compatibility
try:
    import urllib.parse as urllib
except ImportError:
    import urllib

import requests
from Crypto.Cipher import AES
from Crypto.Random import random
import xml.etree.ElementTree as etree
from oath import totp, hotp
from vipaccess.version import __version__

PROVISIONING_URL = 'https://services.vip.symantec.com/prov'
TEST_URL = 'https://vip.symantec.com/otpCheck'
SYNC_URL = 'https://vip.symantec.com/otpSync'
DEFAULT_REQUEST_TIMEOUT = 20
STATUS_MESSAGE_PATTERN = re.compile(
    r'<span[^>]*class="[^"]*\bsixcode\b[^"]*"[^>]*>(.*?)</span>',
    re.IGNORECASE | re.DOTALL,
)

HMAC_KEY = b'\xdd\x0b\xa6\x92\xc3\x8a\xa3\xa9\x93\xa3\xaa\x26\x96\x8c\xd9\xc2\xaa\x2a\xa2\xcb\x23\xb7\xc2\xd2\xaa\xaf\x8f\x8f\xc9\xa0\xa9\xa1'

TOKEN_ENCRYPTION_KEY = b'\x01\xad\x9b\xc6\x82\xa3\xaa\x93\xa9\xa3\x23\x9a\x86\xd6\xcc\xd9'

REQUEST_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" ?>
<GetSharedSecret Id="%(timestamp)d" Version="2.0"
    xmlns="http://www.verisign.com/2006/08/vipservice"
    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
    <TokenModel>%(token_model)s</TokenModel>
    <ActivationCode></ActivationCode>
    <OtpAlgorithm type="%(otp_algorithm)s"/>
    <SharedSecretDeliveryMethod>%(shared_secret_delivery_method)s</SharedSecretDeliveryMethod>
    <Extension extVersion="auth" xsi:type="vip:ProvisionInfoType"
        xmlns:vip="http://www.verisign.com/2006/08/vipservice">
        <AppHandle>%(app_handle)s</AppHandle>
        <ClientIDType>%(client_id_type)s</ClientIDType>
        <ClientID>%(client_id)s</ClientID>
        <DistChannel>%(dist_channel)s</DistChannel>
        <ClientTimestamp>%(timestamp)d</ClientTimestamp>
        <Data>%(data)s</Data>
    </Extension>
</GetSharedSecret>'''


def generate_request(**request_parameters):
    '''Generate a token provisioning request.'''
    default_request_parameters = {
        'timestamp':int(time.time()),
        'token_model':'SYMC',
        'otp_algorithm':'HMAC-SHA1-TRUNC-6DIGITS',
        'shared_secret_delivery_method':'HTTPS',
        'app_handle':'iMac010200',
        'client_id_type':'BOARDID',
        'client_id':'python-vipaccess-' + __version__,
        'dist_channel':'Symantec',
    }

    default_request_parameters.update(request_parameters)
    request_parameters = default_request_parameters

    data_before_hmac = u'%(timestamp)d%(timestamp)d%(client_id_type)s%(client_id)s%(dist_channel)s' % request_parameters
    request_parameters['data'] = base64.b64encode(
        hmac.new(
            HMAC_KEY,
            data_before_hmac.encode('utf-8'),
            hashlib.sha256
            ).digest()
        ).decode('utf-8')

    return REQUEST_TEMPLATE % request_parameters

def _post(session, url, timeout=DEFAULT_REQUEST_TIMEOUT, **kwargs):
    response = session.post(url, timeout=timeout, **kwargs)
    response.raise_for_status()
    return response


def _get_vip_credential_status(response_text):
    match = STATUS_MESSAGE_PATTERN.search(response_text)
    if match is not None:
        response_text = match.group(1)
    return ' '.join(response_text.split()).lower()


def _get_hash_fn(algorithm):
    algorithm = (algorithm or 'sha1').lower()
    hash_fn = getattr(hashlib, algorithm, None)
    if hash_fn is None:
        raise ValueError('unsupported hash algorithm %r' % algorithm)
    return hash_fn


def _normalize_otp(raw_otp, digits):
    digits = int(digits)
    if digits <= 0:
        raise ValueError('digits must be positive')
    return str(raw_otp).zfill(digits)[-digits:]


def get_provisioning_response(request, session=requests, timeout=DEFAULT_REQUEST_TIMEOUT):
    return _post(session, PROVISIONING_URL, data=request, timeout=timeout)

def get_token_from_response(response_xml):
    '''Retrieve relevant token details from Symantec's provisioning
    response.'''
    # Define an arbitrary namespace "v" because etree doesn't like it
    # when it's "None"
    ns = {'v':'http://www.verisign.com/2006/08/vipservice'}

    tree = etree.fromstring(response_xml)
    result = tree.find('v:Status/v:StatusMessage', ns).text
    reasoncode = tree.find('v:Status/v:ReasonCode', ns).text

    if result != 'Success':
        raise RuntimeError(result, reasoncode)
    else:
        token = {}
        token['timeskew'] = time.time() - int(tree.find('v:UTCTimestamp', ns).text)
        container = tree.find('v:SecretContainer', ns)
        encryption_method = container.find('v:EncryptionMethod', ns)
        token['salt'] = base64.b64decode(encryption_method.find('v:PBESalt', ns).text)
        token['iteration_count'] = int(encryption_method.find('v:PBEIterationCount', ns).text)
        token['iv'] = base64.b64decode(encryption_method.find('v:IV', ns).text)

        device = container.find('v:Device', ns)
        secret = device.find('v:Secret', ns)
        data = secret.find('v:Data', ns)
        expiry = secret.find('v:Expiry', ns)
        usage = secret.find('v:Usage', ns)

        token['id'] = secret.attrib['Id']
        token['cipher'] = base64.b64decode(data.find('v:Cipher', ns).text)
        token['digest'] = base64.b64decode(data.find('v:Digest', ns).text)
        token['expiry'] = expiry.text
        ts = usage.find('v:TimeStep', ns) # TOTP only
        token['period'] = int(ts.text) if ts is not None else None
        ct = usage.find('v:Counter', ns) # HOTP only
        token['counter'] = int(ct.text) if ct is not None else None

        # Apparently, secret.attrib['type'] == 'HOTP' in all cases, so the presence or absence of
        # the counter or period fields is the only sane way to distinguish TOTP from HOTP tokens.
        if (token['counter'] is not None) == (token['period'] is not None):
            raise RuntimeError('invalid token metadata: expected exactly one of counter or period')

        algorithm = usage.find('v:AI', ns).attrib['type'].split('-')
        if len(algorithm)==4 and algorithm[0]=='HMAC' and algorithm[2]=='TRUNC' and algorithm[3].endswith('DIGITS'):
            token['algorithm'] = algorithm[1].lower()
            token['digits'] = int(algorithm[3][:-6])
        else:
            raise RuntimeError('unknown algorithm %r' % '-'.join(algorithm))

        return token

def decrypt_key(token_iv, token_cipher):
    '''Decrypt the OTP key using the hardcoded AES key.'''
    decryptor = AES.new(TOKEN_ENCRYPTION_KEY, AES.MODE_CBC, token_iv)
    decrypted = decryptor.decrypt(token_cipher)

    # "decrypted" has PKCS#7 padding on it, so we need to remove that
    if type(decrypted[-1]) != int:
        num_bytes = ord(decrypted[-1])
    else:
        num_bytes = decrypted[-1]
    otp_key = decrypted[:-num_bytes]

    return otp_key

def generate_otp_uri(token, secret, issuer='VIP Access', image=None):
    '''Generate the OTP URI.'''
    token_parameters = {}
    token_parameters['issuer'] = urllib.quote(issuer)
    token_parameters['account_name'] = urllib.quote(token.get('id', 'Unknown'))
    secret = base64.b32encode(secret).upper()
    data = dict(
        secret=secret,
        # Per Google's otpauth:// URI spec (https://github.com/google/google-authenticator/wiki/Key-Uri-Format#issuer),
        # the issuer in the URI path and the issuer parameter are equivalent.
        # Per #53, Authy does not correctly parse the latter.
        # Therefore, we include only the former (issuer in the URI path) for maximum compatibility.
        # issuer=issuer,
    )
    if image:
        data['image'] = image
    if token.get('digits', 6) != 6:  # 6 digits is the default
        data['digits'] = token['digits']
    if token.get('algorithm', 'SHA1').upper() != 'SHA1':  # SHA1 is the default
        data['algorithm'] = token['algorithm'].upper()
    if token.get('counter') is not None: # HOTP
        data['counter'] = token['counter']
        token_parameters['otp_type'] = 'hotp'
    elif token.get('period'): # TOTP
        if token['period'] != 30:  # 30 seconds is the default
            data['period'] = token['period']
        token_parameters['otp_type'] = 'totp'
    else: # Assume TOTP with default period 30 (FIXME)
        token_parameters['otp_type'] = 'totp'
    token_parameters['parameters'] = urllib.urlencode(data, safe=':/')
    return 'otpauth://%(otp_type)s/%(issuer)s:%(account_name)s?%(parameters)s' % token_parameters


def generate_otp(token, secret, timestamp=None, counter=None):
    secret_hex = binascii.b2a_hex(secret).decode('ascii')
    digits = token.get('digits', 6)
    hash_fn = _get_hash_fn(token.get('algorithm', 'sha1'))
    if counter is None:
        counter = token.get('counter')

    if counter is not None:
        raw_otp = hotp(secret_hex, counter=counter, format='dec', hash=hash_fn)
    else:
        period = int(token.get('period', 30) or 30)
        raw_otp = totp(secret_hex, period=period, t=timestamp, format='dec', hash=hash_fn)
    return _normalize_otp(raw_otp, digits)

def check_token(token, secret, session=requests, timestamp=None, timeout=DEFAULT_REQUEST_TIMEOUT):
    '''Check the validity of the generated token.'''
    otp = generate_otp(token, secret, timestamp=timestamp)
    data = {'cr%s'%d:c for d,c in enumerate(otp, 1)}
    data['cred'] = token['id']
    data['continue'] = 'otp_check'
    token_check = _post(session, TEST_URL, data=data, timeout=timeout)
    status = _get_vip_credential_status(token_check.text)
    if 'working correctly' in status:
        if token.get('counter') is not None:
            token['counter'] += 1
        return True
    elif 'need' in status and 'sync' in status:
        return False
    else:
        return None

def sync_token(token, secret, session=requests, timestamp=None, timeout=DEFAULT_REQUEST_TIMEOUT):
    '''Sync the generated token. This will fail for a TOTP token if performed less than 2 periods after the last sync or check.'''
    if timestamp is None:
        timestamp = int(time.time())
    if token.get('counter') is not None: # HOTP
        # This reliably fails with -1, 0
        otp1 = generate_otp(token, secret, counter=token['counter'])
        otp2 = generate_otp(token, secret, counter=token['counter'] + 1)
    else: # Assume TOTP with default period 30 (FIXME)
        period = int(token.get('period', 30) or 30)
        otp1 = generate_otp(token, secret, timestamp=timestamp - period)
        otp2 = generate_otp(token, secret, timestamp=timestamp)

    data = {'cr%s'%d:c for d,c in enumerate(otp1, 1)}
    data.update({'ncr%s'%d:c for d,c in enumerate(otp2, 1)})
    data['cred'] = token['id']
    data['continue'] = 'otp_sync'
    token_check = _post(session, SYNC_URL, data=data, timeout=timeout)
    status = _get_vip_credential_status(token_check.text)
    if 'successfully synced' in status:
        if token.get('counter') is not None:
            token['counter'] += 2
        return True
    elif 'need' in status and 'sync' in status:
        return False
    else:
        return None
