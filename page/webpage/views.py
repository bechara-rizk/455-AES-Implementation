from django.shortcuts import render
from django.http import HttpResponse
from .aes import AES

# Create your views here.
def encryption(response):
    clicked=''
    if response.method=="POST":
        if response.POST.get("show"):
            clicked='checked'
            a=AES(response.POST.get("key"), True, True)
            if response.POST.get("encrypt"):
                text,key=a.encryption(response.POST.get("text"))
            else:
                print(response.POST.get("decrypt"))
                text,key=a.decryption(response.POST.get("text"))
        else: 
            clicked=''
            a=AES(response.POST.get("key"), True, False)
            if response.POST.get("encrypt"):
                text,key=a.encryption(response.POST.get("text")),''
            else:
                print(response.POST.get("decrypt"))
                text,key=a.decryption(response.POST.get("text")),''

        return render(response, 'index.html', {"text":text, 'key':key, "clicked":clicked, "previouskey":response.POST.get("key"), "previoustext":response.POST.get("text")})
    return render(response, 'index.html', {"text":"", 'key':'', "clicked":clicked, "previouskey":'0f1571c947d9e8590cb7add6af7f6798', "previoustext":'ff0b844a0853bf7c6934ab4364148fb9'})