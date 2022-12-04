from django.shortcuts import render
from django.http import HttpResponse
from .aes import AES

# Create your views here.
def encryption(response):
    clicked=''
    if response.method=="POST":
        a=AES(response.POST.get("key"), True, False)
        cipher=a.encryption(response.POST.get("text"))

        if response.POST.get("show"):
            clicked='checked'
            a=AES(response.POST.get("key"), True, True)
        else: 
            clicked=''
            a=AES(response.POST.get("key"), True, False)

        if response.POST.get("encrypt"):
            print('encrypt')
            cipher=a.encryption(response.POST.get("text"))
        else:
            print(response.POST.get("decrypt"))
            cipher=a.decryption(response.POST.get("text"))

        return render(response, 'index.html', {"ans":cipher, "clicked":clicked, "previouskey":response.POST.get("key"), "previoustext":response.POST.get("text")})
    return render(response, 'index.html', {"ans":" ", "clicked":clicked, "previouskey":'', "previoustext":''})