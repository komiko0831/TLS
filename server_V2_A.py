from pwn import *
import logging
from crypto import *
import json
from hashlib import sha256
# 配置日志
logging.basicConfig(filename='server_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')

# 创建监听器
server = listen(12345)
logging.info('Server started and listening on port 12345')

# 接受客户端连接
client = server.wait_for_connection()
logging.info(f'Connection from {client.rhost}:{client.rport}')

"""
Digital Signature
"""

# 生成服务器的私钥和公钥
server_private_key,server_public_key = get_key()

# 发送服务器公钥
client.send(server_public_key)
logging.info(f'Sent server public key: {server_public_key.hex()}')

# 接收客户端公钥
client_public_key = client.recv(32)
logging.info(f'Received client public key: {client_public_key.hex()}')

#server hello
server_hello = b'hello client'
client.send(server_hello)
signature = sign_message(server_hello,server_private_key)
client.send(signature)
logging.info(f'Sent sever hello')

#验签
rcv = client.recv(1024).decode()
is_valid =VerifySignature(rcv, signature, server_public_key)
if is_valid:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
logging.info(f'Signature ')


#生成DH参数
p = generate_prime()
g = generate_primitive_root(p)
logging.info(f"The server has generated DH parameters:{p},{g}")

#发送DH参数
client.send(str(p).encode())  # 单独发送 p
logging.info(f"The server has sent DH parameter p: {p}")
client.send(str(g).encode())  # 单独发送 g
logging.info(f"The server has sent DH parameter g: {g}")


#生成服务端协商私钥公钥
server_dh_key = generate_private_key()
server_exchange_key = exchange_key(server_dh_key)

#发送服务端协商公钥
client.send(str(server_exchange_key).encode())
logging.info(f"Send the server shared public key{server_exchange_key}")

#接受客户端协商公钥
client_exchange_key = int(client.recv(1024).decode())
logging.info(f"Receive the client's shared public key: {client_exchange_key}")

# 生成共享密钥
shared_secret = shared_key(server_dh_key,client_exchange_key)
print(shared_secret)
logging.info(f"The DH shared key is:: {shared_secret}")

# 接收客户端消息
encrypted_message = json.loads(client.recv(4096).decode())
logging.info(f"Receiving encrypted client messages: {encrypted_message}")

# 解密消息
decrypted_message = process_message(shared_secret,encrypted_message)[1]
print(decrypted_message)
logging.info(f"ecrypted_messag: {decrypted_message}")

#验证消息完整性
#接收原消息hash值
m_hash_2 = json.loads(client.recv(4096).decode())
m_hash_1 =  sha256(decrypted_message)
if m_hash_1 == m_hash_2:
    print("Success!")
else:
    print("Error!")

#发送消息
message = b'server has received'
encrypted_message = process_message(shared_secret,message.decode())[0]
client.send(json.dumps(encrypted_message).encode())
logging.info(f"send message: {encrypted_message}")

#发送原消息hash值
m_hash = sha256(message)
client.send(json.dumps(m_hash).encode())
logging.info(f'Send the hash value of the original message:{m_hash}')

client.close()
logging.info('Connection closed')
