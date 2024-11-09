from pwn import *
import logging
import hashlib
import hmac
import os
from crypto import *

# 配置日志
logging.basicConfig(filename='client_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# 生成客户端的私钥和公钥
client_private_key,client_public_key = get_key()

# 连接服务器
client = remote('localhost', 12345)
logging.info('Connected to server')

# 接收服务器公钥
server_public_key = client.recv(32)
logging.info(f'Received server public key: {server_public_key.hex()}')

# 发送客户端公钥
client.send(client_public_key)
logging.info(f'Sent client public key: {client_public_key.hex()}')

#接收DH参数
p, g = client.recv()
logging.info(f'Received p,g is: {p.hex()}{g.hex()}')

#生成客户端协商私钥公钥
client_dh_key = generate_private_key()
client_exchange_key =  exchange_key()

#发送客户端协商公钥
client.send(client_exchange_key)
logging.info((f'Sent client_exchange_key{client_exchange_key}'))

#接受服务端协商公钥
server_exchange_key = client.recv()

# 生成共享密钥
shared_secret = shared_key(client_dh_key,server_exchange_key)
logging.info(f'Generated shared secret: {shared_secret.hex()}')

# 发送消息
message = b'Hello from client'
encrypted_message = hmac.new(shared_secret, message, hashlib.sha256).digest()
client.send(encrypted_message)
logging.info(f'Sent encrypted message: {encrypted_message.hex()}')

# 接收响应
encrypted_response = client.recv(1024)
logging.info(f'Received encrypted response: {encrypted_response.hex()}')

# 解密响应
decrypted_response = hmac.new(shared_secret, encrypted_response, hashlib.sha256).digest()
logging.info(f'Decrypted response: {decrypted_response}' )

client.close()
logging.info('Connection closed')