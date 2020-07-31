from Crypto.Cipher import AES
import base64
import datetime

class aescrypt():
    def __init__(self,key,model,iv,encode_):
        self.encode_ = encode_
        self.model =  {'ECB':AES.MODE_ECB,'CBC':AES.MODE_CBC}[model]
        self.key = self.add_16(key)
        self.iv = iv.encode()
        if model == 'ECB':
            self.aes = AES.new(self.key,self.model) 
        elif model == 'CBC':
            self.aes = AES.new(self.key,self.model,self.iv) 

    def add_16(self,par):
        par = par.encode(self.encode_)
        while len(par) % 16 != 0:
            par += b'\x00'
        return par

    def aesencrypt(self,text):
        text = self.add_16(text)
        self.encrypt_text = self.aes.encrypt(text)
        return base64.encodebytes(self.encrypt_text).decode().strip()

    def aesdecrypt(self,text):
        if self.model == AES.MODE_ECB:
            text = base64.decodebytes(text.encode(self.encode_))
            self.decrypt_text = self.aes.decrypt(text)
            return self.decrypt_text.decode(self.encode_).strip('\0')
        elif self.model == AES.MODE_CBC:
            self.aes = AES.new(self.key,self.model,self.iv)
            text = base64.decodebytes(text.encode(self.encode_))
            self.decrypt_text = self.aes.decrypt(text)
            return self.decrypt_text.decode(self.encode_).strip('\0')


if __name__ == '__main__':
    pattern_ecb = aescrypt('841155412','ECB','','utf8')
    en_text = pattern_ecb.aesencrypt('My hero')
    print('ECB加密模式密文:',en_text)
    data = pattern_ecb.aesdecrypt('t7Amf9fH6H+0YOAsNLOKeA==')
    print('ECB加密模式明文：',data)

    pattern_cbc = aescrypt('859685','CBC','1252635241524152','utf8')
    cbc_text = pattern_cbc.aesencrypt('My hero')
    print('CBC加密模式密文：',cbc_text)
    cbc_data = pattern_cbc.aesdecrypt(cbc_text)
    print('CBC加密模式密文：',cbc_data)
