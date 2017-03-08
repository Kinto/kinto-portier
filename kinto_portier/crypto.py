import base64
import codecs
from cryptography.fernet import Fernet


def encrypt(message, key):
    key = base64.urlsafe_b64encode(codecs.decode(key, 'hex'))
    f = Fernet(key)
    return f.encrypt(message.encode('utf-8')).decode('utf-8')


def decrypt(encrypted_message, key):
    key = base64.urlsafe_b64encode(codecs.decode(key, 'hex'))
    f = Fernet(key)
    return f.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
