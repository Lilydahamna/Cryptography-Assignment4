import hashlib
import random
#Precomputed DSA parameters 
p = int(
    "86F5CA03DCFEB225063FF830A0C769B9DD9D6153AD91D7CE27F787C43278B447"
    "E6533B86B18BED6E8A48B784A14C252C5BE0DBF60B86D6385BD2F12FB763ED88"
    "73ABFD3F5BA2E0A8C0A59082EAC056935E529DAF7C610467899C77ADEDFC846C"
    "881870B7B19B2B58F9BE0521A17002E3BDD6B86685EE90B3D9A1B02B782B1779",
    16,
)
q = int("996F967F6C8E388D9E28D01E205FBA957A5698B1", 16)
g = int(
    "07B0F92546150B62514BB771E2A0C0CE387F03BDA6C56B505209FF25FD3C133D"
    "89BBCD97E904E09114D9A7DEFDEADFC9078EA544D2E401AEECC40BB9FBBF78FD"
    "87995A10A1C27CB7789B594BA7EFB5C4326A9FE59A070E136DB77175464ADCA4"
    "17BE5DCE2F40D10A46A3A3943F26AB7FD9C0398FF8C76EE0A56826A8A88F1DBD",
    16,
)

#generate key pair 
x = random.randint(1, q - 1)
y = pow(g, x, p)

#generate k 
k = random.randint(1, q - 1)

def dsa_sign(message, p, q, g, x, k):
    #Calculate r = (g^k mod p) mod q
    r = pow(g, k, p) % q

    #Use SHA-1 to hash the message
    h_m = int.from_bytes(hashlib.sha1(message).digest())

    #Compute inverse of k modulo q
    k_inv = pow(k, -1, q) 

    #Calculate s = [k^-1 * (H(M) + x * r)] mod q
    s = (k_inv * (h_m + x * r)) % q

    return r, s

def dsa_verify(p, q, g, y, r, s, message):
    #Calculate inverse of s modulo q
    w = pow(s, -1, q) 

    #Calculate sha-1 of message
    h_m = int.from_bytes(hashlib.sha1(message).digest())

    #Calculate u1 = [H(message) * w] mod q 
    u1 = (h_m * w) % q

    #Calculate u2 = (r * w) mod q 
    u2 = (r * w) % q

    #Compute v = [(g^u1 * y^u2) mod p] mod q
    v = ((pow(g, u1, p) * pow(y, u2, p)) % p) % q

    return v == r

m1 = int.to_bytes(582346829057612, 8)

#Generate signature for m1
r1, s1 = dsa_sign(m1, p, q, g, x, k)

#Verify signature for m1 
is_valid = dsa_verify(p, q, g, y, r1, s1, m1)
print("Valid:", is_valid)

#section for q3
m2 = int.to_bytes(8061474912583, 8)

#Generate signature for m2
r2, s2 = dsa_sign(m2, p, q, g, x, k)