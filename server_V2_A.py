from pwn import *
import logging
import hashlib
import hmac
import os
from crypto import *
# 配置日志
logging.basicConfig(filename='server_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# 生成服务器的私钥和公钥
server_private_key,server_public_key = get_key()

# 创建监听器
server = listen(12345)
logging.info('Server started and listening on port 12345')

# 接受客户端连接
client = server.wait_for_connection()
logging.info(f'Connection from {client.rhost}:{client.rport}')

# 发送服务器公钥
client.send(server_public_key)
logging.info(f'Sent server public key: {server_public_key.hex()}')

# 接收客户端公钥
client_public_key = client.recv(32)
logging.info(f'Received client public key: {client_public_key.hex()}')

#生成DH参数
p = generate_prime()
g = generate_primitive_root(p)

#发送DH参数
client.send(p,g)
logging.info(f'Sent p,g: {p.hex()}{g.hex()}')

#生成服务端协商私钥公钥
server_dh_key = generate_private_key()
server_exchange_key = exchange_key()

#发送服务端协商公钥
client.send(server_exchange_key)
logging.info((f'Sent server_exchange_key{server_exchange_key.hex()}'))

#接受客户端协商公钥
client_exchange_key = client.recv()

# 生成共享密钥
shared_secret = shared_key(server_dh_key,client_exchange_key)
logging.info(f'Generated shared secret: {shared_secret.hex()}')

# 接收客户端消息
encrypted_message = client.recv(1024)
logging.info(f'Received encrypted message: {encrypted_message.hex()}')

# 解密消息
decrypted_message = hmac.new(shared_secret, encrypted_message, hashlib.sha256).digest()
logging.info(f'Decrypted message: {decrypted_message}')

# 发送响应
response = b'Hello from server'
encrypted_response = hmac.new(shared_secret, response, hashlib.sha256).digest()
client.send(encrypted_response)
logging.info(f'Sent encrypted response: {encrypted_response.hex()}')

client.close()
logging.info('Connection closed')