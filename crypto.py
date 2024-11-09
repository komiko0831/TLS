
from Crypto.Util.number import *
import math
import random
from Crypto.Cipher import AES



def get_key():
    p = getPrime(1024)
    q = getPrime(1024)
    n = p * q
    e = 65537
    phi  = (p-1)*(q-1)
    d = pow(e,-1,phi)
    return d,e

pub_key,pri_key = get_key()

print (f'{pub_key}')
print(f'{pri_key}')

def generate_prime():
    """
    生成一个大素数p
    """
    prime = 0
    while not is_prime(prime):
        prime = random.randint(2**20, 2**21)
    return prime

def is_prime(n):
    """
    判断一个数是否为素数
    """
    if n <= 1:
        return False
    for i in range(2, int(math.sqrt(n)) + 1):
        if n % i == 0:
            return False
    return True

def generate_primitive_root(p):
    """
    生成一个原根g
    """
    for g in range(2, p):
        if is_primitive_root(g, p):
            return g
    return None

def is_primitive_root(g, p):
    """
    判断一个数是否为原根
    """
    if not is_prime(p):
        return False
    phi = p - 1
    factors = prime_factors(phi)
    for factor in factors:
        if g**(phi // factor) % p == 1:
            return False
    return True
def prime_factors(n):
    """
    计算一个数的素因子
    """
    factors = []
    while n % 2 == 0:
        factors.append(2)
        n //= 2
    i = 3
    while i <= math.sqrt(n):
        if n % i == 0:
            factors.append(i)
            n //= i
        else:
            i += 2
    if n > 1:
        factors.append(n)
    return factors

p = generate_prime()
g = generate_primitive_root(p)

def generate_private_key():
    x = random.randint(1000000,10000000000)
    return x

def exchange_key():
    y = pow(g,generate_private_key(),p)
    return y

def shared_key(x,y):
    return pow(y,x,p)

def aes_encrypt(key,msg):
    aes = AES.new(key,AES.MODE_ECB)
    en_msg = aes.encrypt(msg)
    return en_msg



























