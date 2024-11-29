from hashlib import sha1

# DSA parameters
p = 103687
q = 1571
g = 21947
A = 31377
k = 1305
D = 610  

#Brute-force function to solve g^x ≡ A (mod p)
def find_private_key_brute_force(p, g, A):
    for x in range(1, p):  
        if pow(g, x, p) == A: 
            return x


def dsa_sign( p, q, g, k, x, D):
    #Compute r
    r = pow(g, k, p) % q

    #Compute H(D)
    h_d = int.from_bytes(sha1(D).digest())

    #Compute k^-1 mod q
    k_inv = pow(k, -1, q)

    #Compute s
    s = (k_inv * (h_d + x * r)) % q

    return r, s

#brute force private key
x = find_private_key_brute_force(p, g, A)
print("Private key x:", x)

#sign D 
r, s = dsa_sign(p, q, g, k, x, int.to_bytes(D, 2))
print("Signature (r, s):", (r, s))
