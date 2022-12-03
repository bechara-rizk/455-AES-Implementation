from aes import AES

a=AES("0f1571c947d9e8590cb7add6af7f6798")
cipher=a.encryption("0123456789abcdeffedcba9876543210")
print("Ciphertext:\n"+ cipher)
plain=a.decryption("ff0b844a0853bf7c6934ab4364148fb9")
print("Plaintext:\n"+ plain)