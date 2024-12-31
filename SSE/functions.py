import hashlib
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256

def pad_to_48_bytes(data: bytes) -> bytes:
    """ 将数据填充到48个字节的长度，中文字符占3个字节，英文占1个字节 """
    # 如果长度不足48字节，则用零填充
    return data.ljust(48, b'\x00')

# 计算X_i
def encrypt_to_X_i(W_i: str, hashkey: bytes, iv:bytes) -> bytes:
    """ 使用AES CBC模式加密数据 """

    # 步骤1: 标准化为48字节
    W_i_bytes = W_i.encode('utf-8')  # 将字符串转换为bytes
    # 将数据填充到48字节
    padded_data = pad_to_48_bytes(W_i_bytes)
    # print(padded_data)

    cipher = AES.new(hashkey, AES.MODE_CBC, iv)
    X_i = cipher.encrypt(padded_data)
    return X_i

def hmac_sha256(data: bytes, key: bytes) -> bytes:
    """ 使用HMAC SHA256对数据进行加密 """
    hmac = HMAC.new(key, data, SHA256)
    return hmac.digest()
def encrypt_key(W_i, password):

    X_i, k_i = x_k(W_i, password)
    # 步骤5: 使用伪随机函数生成S_i
    S_i = get_random_bytes(16)  # 伪随机种子

    # 步骤6: 使用HMAC SHA256对S_i进行加密，得到Fk_i
    Fk_i = hmac_sha256(S_i, k_i)

    # 步骤7: 将S_i和Fk_i拼接得到T_i
    T_i = S_i + Fk_i

    # 步骤8: 将T_i与X_i进行异或，得到C_i
    C_i = bytes(a ^ b for a, b in zip(T_i, X_i))

    return C_i

# 计算X_i和k_i
def x_k(W_i, password):

    password_bytes = password.encode('utf-8')
    hashkey = hashlib.sha256(password_bytes).digest()[16:]  # Use SHA-256 of password as the AES key(16)
    iv = hashlib.sha256(password_bytes).digest()[:16]

    # 步骤2: 使用AES CBC模式加密
    X_i = encrypt_to_X_i(W_i, hashkey, iv)

    # 步骤3: 划分X_i为L_i和R_i
    L_i = X_i[:16]  # 取中间16字节

    # 步骤4: 对L_i使用HMAC SHA256加密，得到k_i
    k_i = hmac_sha256(L_i, hashkey)

    return X_i, k_i

# 匹配检索
def find(X_i, k_i, C_i):
    # 步骤1: 将C_i与X_i进行异或，得到T_i
    T_i = bytes(a ^ b for a, b in zip(C_i, X_i))
    tl = T_i[:16]
    tr = T_i[16:]
    tl_h = hmac_sha256(tl, k_i)
    if tl_h == tr:
        return True
    else:
        return  False

def encrypt_file(file, password):
    """
    Encrypt the uploaded file using the given password.
    This is a placeholder encryption function.
    """
    # Derive AES key and IV
    password_bytes = password.encode('utf-8')
    key = hashlib.sha256(password_bytes).digest()  # Use SHA-256 of password as the key
    iv = hashlib.sha256(password_bytes + b'123ad56f').digest()[:15]  # Use first 16 bytes of SHA-256 hash as the IV

    # Encrypt file content
    cipher = AES.new(key, AES.MODE_OCB, iv)
    padded_content = pad(file, AES.block_size)  # Ensure content is block-aligned
    encrypted_content = cipher.encrypt(padded_content)

    return encrypted_content

def decrypt_file(file, password):
    """
    Encrypt the uploaded file using the given password.
    This is a placeholder encryption function.
    """
    # Derive AES key and IV
    password_bytes = password.encode('utf-8')
    key = hashlib.sha256(password_bytes).digest()  # Use SHA-256 of password as the key
    iv = hashlib.sha256(password_bytes + b'123ad56f').digest()[:15]  # Use first 16 bytes of SHA-256 hash as the IV

    # Encrypt file content
    cipher = AES.new(key, AES.MODE_OCB, iv)
    decrypted_content = cipher.decrypt(file)
    content = unpad(decrypted_content, AES.block_size)  # Ensure content is block-aligned

    return content

if __name__ == '__main__':

    a = encrypt_file('nihao.txt'.encode('utf-8'), 'sadfs')
    decrypt_file(a, 'sadfs')
