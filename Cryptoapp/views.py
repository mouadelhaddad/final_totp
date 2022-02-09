from Cryptoapp.challs.scripts import *
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth.models import User
from django.db import IntegrityError
from django.http import Http404
from django.contrib.auth import login, logout, authenticate
from django.utils import timezone
from django.contrib.auth.decorators import login_required
from Cryptoapp.forms import CustomUserCreationForm
from Cryptoapp.email import *
from django.contrib import messages
import pyotp
from Cryptoapp.models import *
from Cryptoapp.qr import *
import pathlib
import os
# Create your views here.

def loginuser(request):
    global user
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == 'GET':
            return render(request, 'Cryptoapp/login.html', {'form': AuthenticationForm()})
        else:
            user = authenticate(request, username=request.POST['username'], password=request.POST['password'])
            if user is None:
                return render(request, 'Cryptoapp/login.html', {'form': AuthenticationForm(),'error': 'Le nom d\'utilisateur ou le mot de passe est incorrect'})
            else:
                token=request.POST['Token']
                instance = otpuser.objects.get(username=user)
                TK=instance.token
                totp = pyotp.TOTP(TK)
                print(totp.now())
                if token == totp.now() :
                    login(request, user)
                    user=None
                    return redirect('home')
                else:
                    return render(request, 'Cryptoapp/login.html', {'form': AuthenticationForm(),'error': 'Le nom d\'utilisateur ou le mot de passe est incorrect'})

def signup(request):
    if request.user.is_authenticated:
        return redirect('home')
    else:
        if request.method == 'GET':
            return render(request, 'Cryptoapp/signup.html')
        else:
            Username = request.POST.get('Username', False)
            first_name = request.POST.get('first_name', False)
            last_name = request.POST.get('last_name', False)
            email = request.POST.get('email', False)
            password = request.POST.get('password', False)
            password1 = request.POST.get('password1', False)
            if User.objects.filter(username=Username).exists():
                return render(request, 'Cryptoapp/signup.html', {'form': AuthenticationForm(),'error': 'Username already taken choose an other one'})
            if password!=password1:
                return render(request, 'Cryptoapp/signup.html', {'form': AuthenticationForm(),'error': 'incorrect password confirmation'})
            if not (isValid(email)):
                return render(request, 'Cryptoapp/signup.html', {'form': AuthenticationForm(),'error': 'incorrect email'})
            else:
                instance = otpuser(username=Username,password=password,email=email,token=pyotp.random_base32())
                instance.save()
                qr(Username)
                sendemail(email,Username)
                user = User.objects.create_user(Username, email, password)
                user.last_name = last_name
                user.first_name = first_name
                user.save()
                login(request, user)
                os.remove(pathlib.Path().resolve().as_posix()+"/static/Cryptoapp"+Username+".png")
                return redirect('home')



@login_required(login_url='/')
def home(request):
    return render(request, 'Cryptoapp/home.html')

@login_required
def logoutuser(request):
    if request.method == 'POST':
        logout(request)
        return redirect('login')
@login_required(login_url='/')
def choix(request):
    choice = str(request.GET.get('Choix d\'algorithme',"cesar"))
    if choice == "cesar":
        return redirect('Ceasar')
    elif choice == "Homophonic":
        return redirect('Homophonic')
    elif choice == "CBC":
        return redirect('CBC')
    elif choice == "Hill":
        return redirect('Hill')
    elif choice == "Vigenere":
        return redirect('Vigenere')
    elif choice == "Vernam":
        return redirect('Vernam')
    elif choice == "Permutation":
        return redirect('Permutation')
    elif choice== "ECB":
        return redirect('ECB')
    elif choice=="CTR":
        return redirect('CTR')
    elif choice=="RC4":
        return redirect('RC4')
@login_required(login_url='/')
def Ceasar(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/Ceasar.html')
    else:
        but1 = request.POST.get('exampleRadios')
        if but1 == 'encrypte':
            cpt=1
            try:
                text = request.POST['Plaintext']
                shift = int(request.POST['Shift'])
                Ciphertext=encryptcesar(shift,text)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/Ceasar.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/Ceasar.html',{'error': 'Une erreur s\'est produite'})
        else:
            cpt=2
            try:
                text = request.POST['Plaintext']
                shift = int(request.POST['Shift'])
                Ciphertext=decryptcesar(shift,text)
                info1=(Ciphertext!='' and cpt==2)
                return render(request, 'Cryptoapp/Ceasar.html', {'Ciphertext':Ciphertext,'info1':info1})
            except:
                return render(request, 'Cryptoapp/Ceasar.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def Homophonic(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/Homophonic.html')
    but1 = request.POST.get('exampleRadios')
    if but1 == 'encrypte':
        cpt=1
        try:
            text = request.POST['Plaintext']
            Ciphertext=encrypthomo(text)
            info=(Ciphertext!='' and cpt==1)
            return render(request, 'Cryptoapp/Homophonic.html', {'Ciphertext':Ciphertext,'info':info})
        except:
            return render(request, 'Cryptoapp/Homophonic.html',{'error': 'Une erreur s\'est produite'})
    else:
        cpt=2
        try:
            text = request.POST['Plaintext']
            Ciphertext=decrypthomo(text)
            info1=(Ciphertext!='' and cpt==2)
            return render(request, 'Cryptoapp/Homophonic.html', {'Ciphertext':Ciphertext,'info1':info1})
        except:
            return render(request, 'Cryptoapp/Homophonic.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def CBC(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/CBC.html')
    else:
        but1 = request.POST.get('exampleRadios')
        if but1 == 'encrypte':
            cpt=1
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                Ciphertext=CBCencryption( text,key)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/CBC.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/CBC.html',{'error': 'Une erreur s\'est produite'})
        else:
            cpt=1
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                Ciphertext=CBCdecryption(text,key)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/CBC.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/CBC.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def Hill(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/Hill.html')
    but1 = request.POST.get('exampleRadios')
    if but1 == 'encrypte':
        cpt=1
        try:
            text = request.POST['Plaintext']
            key= request.POST['key']
            print("hey")
            Ciphertext=hillencrypte(text,key)
            print(Ciphertext)
            info=(Ciphertext!='' and cpt==1)
            return render(request, 'Cryptoapp/Hill.html', {'Ciphertext':Ciphertext,'info':info})
        except:
            return render(request, 'Cryptoapp/Hill.html',{'error': 'Une erreur s\'est produite'})
    else:
        cpt=2
        try:
            text = request.POST['Plaintext']
            key= request.POST['key']
            Ciphertext=hilldecrypte(text,key)
            info1=(Ciphertext!='' and cpt==2)
            return render(request, 'Cryptoapp/Hill.html', {'Ciphertext':Ciphertext,'info1':info1})
        except:
            return render(request, 'Cryptoapp/Hill.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def Vigenere(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/Vigenere.html')
    but1 = request.POST.get('exampleRadios')
    if but1 == 'encrypte':
        cpt=1
        try:
            text = request.POST['Plaintext']
            key= request.POST['Key']
            Ciphertext=vignere(text, key, typ='e')
            info=(Ciphertext!='' and cpt==1)
            return render(request, 'Cryptoapp/Vigenere.html', {'Ciphertext':Ciphertext,'info':info})
        except:
            return render(request, 'Cryptoapp/Vigenere.html',{'error': 'Une erreur s\'est produite'})
    else:
        cpt=2
        try:
            text = request.POST['Plaintext']
            key= request.POST['Key']
            Ciphertext=vignere(text, key, typ='d')
            info1=(Ciphertext!='' and cpt==2)
            return render(request, 'Cryptoapp/Vigenere.html', {'Ciphertext':Ciphertext,'info1':info1})
        except:
            return render(request, 'Cryptoapp/Vigenere.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def Vernam(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/Vernam.html')
    but1 = request.POST.get('exampleRadios')
    if but1 == 'encrypte':
        cpt=1
        try:
            text = request.POST['Plaintext']
            key= request.POST['Key']
            Ciphertext=vernamencrypt(key,text)
            info=(Ciphertext!='' and cpt==1)
            return render(request, 'Cryptoapp/Vernam.html', {'Ciphertext':Ciphertext,'info':info})
        except:
            return render(request, 'Cryptoapp/Vernam.html',{'error': 'Une erreur s\'est produite'})
    else:
        cpt=2
        try:
            text = request.POST['Plaintext']
            key= request.POST['Key']
            Ciphertext=vernamdecrypt(key,text)
            info1=(Ciphertext!='' and cpt==2)
            return render(request, 'Cryptoapp/Vernam.html', {'Ciphertext':Ciphertext,'info1':info1})
        except:
            return render(request, 'Cryptoapp/Vernam.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def Permutation(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/Permutation.html')
    but1 = request.POST.get('exampleRadios')
    if but1 == 'encrypte':
        cpt=1
        try:
            text = request.POST['Plaintext']
            key= request.POST['Key']
            Ciphertext=encryptSub(key,text)
            infoV=(Ciphertext!='' and cpt==1 and Ciphertext!="")
            return render(request, 'Cryptoapp/Permutation.html', {'Ciphertext':Ciphertext,'info':infoV})
        except:
            return render(request, 'Cryptoapp/Permutation.html',{'error': 'Une erreur s\'est produite'})
    else:
        cpt=2
        try:
            text = request.POST['Plaintext']
            key= request.POST['Key']
            Ciphertext=decryptSub(key,text)
            info1=(Ciphertext!='' and cpt==2)
            return render(request, 'Cryptoapp/Permutation.html', {'Ciphertext':Ciphertext,'info1':info1})
        except:
            return render(request, 'Cryptoapp/Permutation.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def ECB(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/ECB.html')
    else:
        but1 = request.POST.get('exampleRadios')
        if but1 == 'encrypte':
            cpt=1
            try:
                text = request.POST['Plaintext']
                shift = int(request.POST['Shift'])
                key= request.POST['Key']
                Ciphertext=ECBencypt(key,shift,text)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/ECB.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/ECB.html',{'error': 'Une erreur s\'est produite'})
        else:
            cpt=2
            try:
                text = request.POST['Plaintext']
                shift = int(request.POST['Shift'])
                key= request.POST['Key']
                Ciphertext=ECBdecypt(key,shift,text)
                info1=(Ciphertext!='' and cpt==2)
                return render(request, 'Cryptoapp/ECB.html', {'Ciphertext':Ciphertext,'info1':info1})
            except:
                return render(request, 'Cryptoapp/ECB.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def CTR(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/CTR.html')
    else:
        but1 = request.POST.get('exampleRadios')
        if but1 == 'encrypte':
            cpt=1
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                counter = int(request.POST['Counter'])
                Ciphertext=en_dec_CTR(text, key, counter)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/CTR.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/CTR.html',{'error': 'Une erreur s\'est produite'})
        else:
            cpt=2
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                counter = int(request.POST['Counter'])
                Ciphertext=en_dec_CTR(text, key, counter)
                info1=(Ciphertext!='' and cpt==2)
                return render(request, 'Cryptoapp/CTR.html', {'Ciphertext':Ciphertext,'info1':info1})
            except:
                return render(request, 'Cryptoapp/CTR.html',{'error': 'Une erreur s\'est produite'})
@login_required(login_url='/')
def RC4(request):
    if request.method == 'GET':
        return render(request, 'Cryptoapp/RC4.html')
    else:
        but1 = request.POST.get('exampleRadios')
        if but1 == 'encrypte1':
            cpt=1
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                Ciphertext=encrypt_Hex(key, text)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/RC4.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/RC4.html',{'error': 'Une erreur s\'est produite'})
        elif but1 == 'encrypte2':
            cpt=1
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                Ciphertext=encrypt_bin(key, text)
                info=(Ciphertext!='' and cpt==1)
                return render(request, 'Cryptoapp/RC4.html', {'Ciphertext':Ciphertext,'info':info})
            except:
                return render(request, 'Cryptoapp/RC4.html',{'error': 'Une erreur s\'est produite'})
        elif but1 == 'decrypte1':
            cpt=2
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                Ciphertext= decrypt_Hex(key, text)
                info1=(Ciphertext!='' and cpt==2)
                return render(request, 'Cryptoapp/RC4.html', {'Ciphertext':Ciphertext,'info1':info1})
            except:
                return render(request, 'Cryptoapp/RC4.html',{'error': 'Une erreur s\'est produite'})
        else:
            cpt=2
            try:
                text = request.POST['Plaintext']
                key=request.POST['Key']
                Ciphertext= decrypt_bin(key, text)
                info1=(Ciphertext!='' and cpt==2)
                return render(request, 'Cryptoapp/RC4.html', {'Ciphertext':Ciphertext,'info1':info1})
            except:
                return render(request, 'Cryptoapp/RC4.html',{'error': 'Une erreur s\'est produite'})
