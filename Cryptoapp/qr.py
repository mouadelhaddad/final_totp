import pyotp
import qrcode
from Cryptoapp.models import *
import pathlib
import re

def qr(user):
    instance = otpuser.objects.get(username=user)
    link=pyotp.totp.TOTP(instance.token).provisioning_uri(name=user, issuer_name='CipherSpace')
    img=qrcode.make(link)
    img.save(pathlib.Path().resolve().as_posix()+"/static/Cryptoapp"+user+".png")

regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
def isValid(email):
    if re.fullmatch(regex, email):
      return True
    else:
      return False
