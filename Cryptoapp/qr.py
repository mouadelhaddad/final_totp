import pyotp
import qrcode
from Cryptoapp.models import *
import pathlib

def qr(user):
    instance = otpuser.objects.get(username=user)
    link=pyotp.totp.TOTP(instance.token).provisioning_uri(name=user, issuer_name='CipherSpace')
    img=qrcode.make(link)
    print(link)
    print(pathlib.Path().resolve().as_posix())
    img.save(pathlib.Path().resolve().as_posix()+"/Cryptoapp/static/qr/qr"+user+".png")
