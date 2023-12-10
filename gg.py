from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from math import log2
import portion


def ceil(a, b):
   return -(-a // b)


def floor(a, b):
   return a // b


def M_range(M):
   range = 0
   for interval in M:
      range += interval.upper - interval.lower + 1
   bit_count = log2(range)
   if bit_count > 32:
      return "~ 2^{}".format(bit_count)
   else:
      return "= {}".format(range)


calls_to_oracle = -1


def Oracle(ciphertext, protocol):
   global calls_to_oracle
   calls_to_oracle += 1
   decryption = protocol.decrypt(int.to_bytes(ciphertext, 128, 'big'), b'Error')
   if decryption != b'Error':
      return True
   return False


print("Initialling RSA key")
key = RSA.generate(1024)
public_key = key.publickey()
n = public_key.n
e = public_key.e
protocol = PKCS1_v1_5.new(key)
print("RSA key initialised with")
print("n =", public_key.n, "({} bits)".format(int.bit_length(public_key.n)))
print("e =", public_key.e)
print()
print("----------------------------------------")
message_s = input("Type your message: ")
# message_s = "This is not a quote from the movie 'The Matrix'"
message = bytes(message_s, 'utf-8')
ciphertext = protocol.encrypt(message)
padded_message = protocol._key._decrypt(int.from_bytes(ciphertext, 'big'))
print("Encrypted message:", ciphertext)
print("Oracle check:", Oracle(int.from_bytes(ciphertext, 'big'), protocol))
print()
input("Press Enter to start the attack...")
print("----------------------------------------")
print("Bleichenbacher's attack")
print()

# Step 1
B = pow(2, 8 * (1024 // 8 - 2))
s = ceil(n, 3 * B)
a = 2 * B
b = 3 * B - 1
M0 = portion.closed(a, b)
print("Initial range size", M_range(M0))
print("Message m0 inside search range:", padded_message in M0)
print()
print("----------------------------------------")
print("Step 1: Find smallest s such that c*(s^e) is conforming")
print("Staring search from s =", s)
for s1 in range(s, n):
   if s1 % 10000 == 0:
      print("Searching s =", s1, "...")
   ciphertext3 = int.from_bytes(ciphertext, 'big') * pow(s1, e, n) % n
   if Oracle(ciphertext3, protocol):
      break
print("Found s =", s1)

low_r = ceil((a * s1 - 3 * B + 1), n)
high_r = floor((b * s1 - 2 * B), n)
M_temp = portion.empty()
for r in range(low_r, high_r + 1):
   a1 = ceil((2 * B + r * n), s1)
   b1 = floor((3 * B - 1 + r * n), s1)
   M_temp |= portion.closed(a1, b1)
M0 = M0 & M_temp
print("Current search range size", M_range(M0))
print("Message m0 inside search range:", padded_message in M0)
print()
print("----------------------------------------")

print("Step 2: Find more s until there is only one interval")
input("Press Enter to continue...")

while not M0.atomic:
   s = s1 + 1
   print("Current search range consists of more than 1 closed intervals.")
   print("Staring search from s =", s)
   for s1 in range(s, n):
      if s1 % 10000 == 0:
         print("Searching s =", s1, "...")
      ciphertext3 = int.from_bytes(ciphertext, 'big') * pow(s1, e, n) % n
      if Oracle(ciphertext3, protocol):
         break
   print("Found s =", s1)

   a = M0.lower
   b = M0.upper
   low_r = ceil((a * s1 - 3 * B + 1), n)
   high_r = floor((b * s1 - 2 * B), n)
   M_temp = portion.empty()
   for r in range(low_r, high_r + 1):
      a1 = ceil((2 * B + r * n), s1)
      b1 = floor((3 * B - 1 + r * n), s1)
      M_temp |= portion.closed(a1, b1)
   M0 = M0 & M_temp
   print("Current search range", M_range(M0))
   print("Message m0 inside search range:", padded_message in M0)

print("Current search range has only 1 interval left. Continue to step 3.")
print()
print("----------------------------------------")
print("Step 3: Binary search on one single interval")
input("Press Enter to continue...")

# s = s1
a = M0.lower
b = M0.upper
r = ceil(2 * (b * s - 2 * B), n)
while True:
   for r1 in range(r, n):
      found = False
      low_s = ceil((2 * B + r1 * n), b)
      high_s = floor((3 * B + r1 * n), a)
      for s1 in range(low_s, high_s + 1):
         if s1 % 10000 == 0:
            print("Searching s =", s1, "...")
         ciphertext3 = int.from_bytes(ciphertext, 'big') * pow(s1, e, n) % n
         if Oracle(ciphertext3, protocol):
            found = True
            break
      if found:
         break

   a = M0.lower
   b = M0.upper
   low_r = ceil((a * s1 - 3 * B + 1), n)
   high_r = floor((b * s1 - 2 * B), n)
   M_temp = portion.empty()
   for r in range(low_r, high_r + 1):
      a1 = ceil((2 * B + r * n), s1)
      b1 = floor((3 * B - 1 + r * n), s1)
      M_temp |= portion.closed(a1, b1)
   M0 = M0 & M_temp
   if M_range(M0) > 2**19:
      print("Current search range size", M_range(M0), end="\r")
   else:
      print("Current search range size", M_range(M0))
   if M0.upper == M0.lower:
      break
   else:
      r = ceil(2 * (b * s1 - 2 * B), n)

print()
print("Found plaintext m0 =", int.to_bytes(M0.lower, 128, 'big'))
print("Number of calls to the oracle:", calls_to_oracle)
print("Attack finished")
