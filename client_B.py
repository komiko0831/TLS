from pwn import *
import logging
from crypto import *
import json 

# 配置日志
logging.basicConfig(filename='client_log.txt', level=logging.INFO, format='%(asctime)s - %(message)s')


# 连接服务器
client = remote('localhost', 12345)
logging.info('Connected to server')

# 接收服务器问候
server_hello = client.recv(1024)
logging.info(f'Received server hello: {server_hello}')

# 签名并发送
signature = sign(server_hello)
client.send(signature)
logging.info(f'Sent client hello and signature')

# 验证签名
rcv = client.recv(1024)
is_valid = verify(rcv)
if is_valid:
    print("Signature is valid.")
else:
    print("Signature is invalid.")
logging.info(f'Signature verification result: {is_valid}')

#接收DH参数
p = int(client.recv(1024).decode())  # 接收并转换 p
logging.info(f"The server has sent DH parameter p: {p}")
g = int(client.recv(1024).decode())  # 接收并转换 g
logging.info(f"The server has sent DH parameter g: {g}")

#生成客户端协商私钥公钥
client_dh_key = generate_private_key()
client_exchange_key =  exchange_key(client_dh_key)

#发送客户端协商公钥
client.send(str(client_exchange_key).encode())
logging.info((f'Sent client_exchange_key{client_exchange_key}'))

#接受服务端协商公钥
server_exchange_key = int(client.recv(1024).decode())
logging.info(f"Receive the shared public key from the server: {server_exchange_key}")

# 生成共享密钥
shared_secret = shared_key(client_dh_key,server_exchange_key)
print(shared_secret)
logging.info(f'Generated shared secret: {shared_secret}')

# 发送消息
message = b'Dday landing month 6 month 6 year 1944'
encrypted_message = process_message(shared_secret,message.decode())[0]
client.send(json.dumps(encrypted_message).encode())
logging.info(f"send encrypted_message: {encrypted_message}")

#发送原消息hash值
m_hash = sha256(message)
client.send(json.dumps(m_hash).encode())
logging.info(f'Send the hash value of the original message:{m_hash}')

# 接收响应
encrypted_message = json.loads(client.recv(4096).decode())
logging.info(f"Receive encrypted messages: {encrypted_message}")

# 解密响应
decrypted_message = process_message(shared_secret,encrypted_message)[1]
print(decrypted_message)
logging.info(f"The decrypted message is: {decrypted_message}")

#验证消息完整性
#接收原消息hash值
m_hash_1 = json.loads(client.recv(4096).decode())
m_hash_2 =  sha256(decrypted_message)
if m_hash_1 == m_hash_2:
    print("Success: SHA-256 hash values match!")
else:
    print("Error: SHA-256 hash values do not match!")

client.close()
logging.info('Connection closed')
