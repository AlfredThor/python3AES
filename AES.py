from Crypto.Cipher import AES
import base64

class aescrypt():
    def __init__(self,key,model,iv,encode_):
        self.encode_ = encode_
        self.model =  {'ECB':AES.MODE_ECB,'CBC':AES.MODE_CBC}[model]
        self.key = self.add_16(key)
        self.iv = iv.encode()
        if model == 'ECB':
            self.aes = AES.new(self.key,self.model) #创建一个aes对象
        elif model == 'CBC':
            self.aes = AES.new(self.key,self.model,self.iv) #创建一个aes对象

    #这里的密钥长度必须是16、24或32，目前16位的就够用了
    def add_16(self,par):
        par = par.encode(self.encode_)
        while len(par) % 16 != 0:
            par += b'\x00'
        return par

    # 加密
    def aesencrypt(self,text):
        text = self.add_16(text)
        self.encrypt_text = self.aes.encrypt(text)
        return base64.encodebytes(self.encrypt_text).decode().strip()

    # 解密
    def aesdecrypt(self,text):
        if self.model == AES.MODE_ECB:
            text = base64.decodebytes(text.encode(self.encode_))
            self.decrypt_text = self.aes.decrypt(text)
            return self.decrypt_text.decode(self.encode_).rstrip('\0')
        elif self.model == AES.MODE_CBC:
            self.aes = AES.new(self.key,self.model,self.iv)
            text = base64.decodebytes(text.encode(self.encode_))
            self.decrypt_text = self.aes.decrypt(text)
            return self.decrypt_text.decode(self.encode_).rstrip('\0')


if __name__ == '__main__':
    pattern_ecb = aescrypt('85748593541','ECB','','utf8')
    en_text = pattern_ecb.aesencrypt('张文超傻逼')
    print('ECB加密模式密文:',en_text)
    data = pattern_ecb.aesdecrypt(en_text)
    print('ECB加密模式明文：',data)

    # pattern_cbc = aescrypt('17610855585','CBC','1761085558512138','utf8')
    # cbc_text = pattern_cbc.aesencrypt('admin911')
    # print('CBC加密模式密文：',cbc_text)
    # a = '4p2RPQqkQyyBRyTNbqO2Xw=='
    # cbc_data = pattern_cbc.aesdecrypt(a)
    # print('CBC加密模式明文：',cbc_data)
