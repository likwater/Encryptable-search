import json
from flask import Flask, request, render_template, redirect, url_for, flash, jsonify
from functions import *
import os
from functools import reduce

# Create the Flask app
app = Flask(__name__)

# Configure upload folder and allowed extensions
UPLOAD_FOLDER = 'uploads/'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.secret_key = os.urandom(24)

# Ensure the upload folder exists
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload')
def upload():
    return render_template('upload.html')

@app.route('/search')
def search():
    return render_template('search.html')

@app.route('/upload_file', methods=['POST'])
def upload_file():
    file_name = request.form.get('file_name')
    file_content_hex = request.form.get('file_content')
    password = request.form.get('password')
    keywords = request.form.get('keywords')
    keywords = keywords.split(' ')

    # 读取现有的索引
    with open('dicts', 'r') as f:
        loaded_json = f.read()
        if not loaded_json:
            dicts = {}
        else:
            dicts = json.loads(loaded_json)

    # 加密文件名，建立新的索引
    encrypted_file_name = encrypt_file(file_name.encode('utf-8'), password).hex()
    for i in keywords:
        # 计算需上传的加密后的关键词C_i
        C_i = encrypt_key(i, password)
        dicts[C_i.hex()] = encrypted_file_name

    file_content = bytes.fromhex(file_content_hex)
    # 加密文件
    encrypted_content = encrypt_file(file_content, password)

    # IPsec模式，添加hmac确保信息的完整性
    hashkey1 = hashlib.sha256(password.encode('utf-8')).digest()[8:24]
    file_hmac = hmac_sha256(encrypted_content, hashkey1)
    encrypted_content = encrypted_content + '----hmac:'.encode('utf-8') + file_hmac

    # 上传存储加密后的文件
    filepath = os.path.join(UPLOAD_FOLDER, encrypted_file_name)
    with open(filepath, 'wb') as f:
        f.write(encrypted_content)

    # 上传索引，即加密后的关键词C_i和其对应的加密后的文件名
    dict_json = json.dumps(dicts)
    with open('dicts', 'w') as f:
        f.write(dict_json)

    # 返回成功响应
    return jsonify({'success': True,'message': f'文件 {file_name} 上传并加密成功！'}), 200



@app.route('/search_file', methods=['POST'])
def search_keyword():
    keywords = request.form['keywords']
    password = request.form['password']  # Assume password is provided for decryption
    keywords = keywords.split(' ')

    # 读取现有索引
    with open('dicts', 'r') as f:
        loaded_json = f.read()
        if not loaded_json:
            return render_template('search.html', results={})
        else:
            dicts = json.loads(loaded_json)

    results = []
    # 检索每个关键词对应的所有文件
    for keyword in keywords:
        # 生成搜索参数X_i, k_i
        x, k = x_k(keyword, password)

        # 搜索索引，检索文件
        file_names_1 = []
        # i:C_i，j:加密后的文件名
        for i, j in dicts.items():
            if find(x, k, bytes.fromhex(i)):
                # 存储检索到的对应的加密后的文件名
                file_names_1.append(j)
        # 存储该关键词对应的所有文件名列表
        results.append(file_names_1)

    changed_files = []
    file_contents = []
    # 得到满足所有关键词的文件（计算所有关键词对应文件的交集）
    file_names_2 = reduce(lambda x, y: list(set(x) & set(y)), results)
    file_names = []
    for i in file_names_2:
        # 读取检索目标的加密后的文件
        filepath = os.path.join(UPLOAD_FOLDER, i)
        with open(filepath, 'rb') as f:
            file_content = f.read()
        # 解密文件名
        file_name = decrypt_file(bytes.fromhex(i), password).decode('utf-8')

        # 如果篡改过上传的加密后的文件，可能无法分离出hmac
        try:
            # 获得上传的加密文件内容和对应的hmac
            file_content, file_hmac_1 = file_content.split(b'----hmac:')
        except ValueError: #如果无法分离出hmac，则说明文件被篡改过
            changed_files.append(file_name)

        # 如果文件没被篡改过，则解密恢复文件
        if file_name not in changed_files:
            # 计算检索到的加密文件的hmac
            hashkey1 = hashlib.sha256(password.encode('utf-8')).digest()[8:24]
            file_hmac = hmac_sha256(file_content, hashkey1)

            # 验证hmac，保障数据的完整性
            if file_hmac == file_hmac_1:
                file_names.append(file_name)
                # 解密文件
                file_content = decrypt_file(file_content, password)
                file_contents.append(file_content.hex())
            else:
                changed_files.append(file_name)


    # 如果有结果，传递结果到模板
    if file_names_2:
        return render_template('search.html', results=zip(file_names, file_contents), no_results=False
                               , changed_files=changed_files)
    else:
        return render_template('search.html', results=[], no_results=True, changed_files=changed_files)  # 如果没有结果，传递空列表



if __name__ == '__main__':
    app.run(debug=True)

