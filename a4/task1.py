import hashlib

input_string1 = "string1"
input_string2 = "string2"

# change one bit in input_string1
input_string1 = input_string1[:3] + "0" + input_string1[4:]

# hash the input strings using SHA256 and get the digests in hexadecimal format
hex_digest1 = hashlib.sha256(input_string1.encode()).hexdigest()
hex_digest2 = hashlib.sha256(input_string2.encode()).hexdigest()

# print the hexadecimal digests to the screen
print("Hash of input_string1:", hex_digest1)
print("Hash of input_string2:", hex_digest2)
