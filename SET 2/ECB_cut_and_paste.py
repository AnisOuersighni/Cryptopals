from ecb_encrypt_decrypt import ecb_decrypt_aes_128_block,ecb_encrypt_aes_128_block
from os import urandom


class Profile_Manager:
    def __init__(self):
        self.key = urandom(16)

    '''
    Best Practices
        Use @staticmethod for methods that logically belong to the class but do not need access to instance or class data.
        If a method needs access to class-level variables or behavior, use @classmethod instead.
        Avoid using @staticmethod for methods that require instance-specific data or functionality. ( variable d'instances et fonctions d'instance)
    '''
    @staticmethod
    def parse(message):
        parsed = {}
        if not isinstance(message,str):
            message=message.decode()

        pairs = message.split("&")
        for pair in pairs:
            key, value = pair.split("=")  # tuple unpacking ( # This splits into ['foo', 'bar'] and assigns key='foo', value='bar' )
            parsed[key] = value
        return parsed
        #message = "foo=bar&baz=qux&zap=zazzle"
        # parsed = {'foo': 'bar', 'baz': 'qux', 'zap': 'zazzle'}


    @staticmethod
    def profile_for(email):
        if b"&" in email or b"=" in email:
            raise ValueError("Invalid email address")
        return b"email=" + email + b'&uid=10&role=user'

    def get_encrypted_profile(self, email):
        profile = self.profile_for(email)
        return ecb_encrypt_aes_128_block(profile, self.key)

    def decrypt_and_parse_profile(self, ctxt):
        profile = ecb_decrypt_aes_128_block(ctxt, self.key)
        return self.parse(profile)

manager = Profile_Manager()

encrypted_profile = manager.get_encrypted_profile(b"email@example.com")


print(f'profile_for function for "email@example.com" => {manager.profile_for(b"email@example.com")}')
print("-"*120)
print(f'parse function for "email=email@example.com&uid=10&role=user" => {manager.parse(b"email=email@example.com&uid=10&role=user")}')
print("-"*120)
print(f'encryption for profile with email "email@example.com" => {encrypted_profile}')
print("-"*120)
print(f'decryption for profile with email "email@example.com" => {manager.decrypt_and_parse_profile(encrypted_profile)}')








# Challenge Directions

'''

ECB cut-and-paste

Write a k=v parsing routine, as if for a structured cookie. The routine should take:

foo=bar&baz=qux&zap=zazzle
... and produce:

{
  foo: 'bar',
  baz: 'qux',
  zap: 'zazzle'
}
(you know, the object; I don't care if you convert it to JSON).

Now write a function that encodes a user profile in that format, given an email address. You should have something like:

profile_for("foo@bar.com")
... and it should produce:

{
  email: 'foo@bar.com',
  uid: 10,
  role: 'user'
}
... encoded as:

email=foo@bar.com&uid=10&role=user
Your "profile_for" function should not allow encoding metacharacters (& and =). Eat them, quote them, whatever you want to do, but don't let people set their email address to "foo@bar.com&role=admin".

Now, two more easy functions. Generate a random AES key, then:

Encrypt the encoded user profile under the key; "provide" that to the "attacker".
Decrypt the encoded user profile and parse it.
Using only the user input to profile_for() (as an oracle to generate "valid" ciphertexts) and the ciphertexts themselves, make a role=admin profile.

'''







###################################################################
# Parser  1 
'''
message = "foo=bar&baz=qux&zap=zazzle"
dict= dict()
i = 0 
message = message +"&"
while i < len(message):
    if message[i] == '&':
        slice = message[:i]
        dict[slice.split('=')[0]] = slice.split('=')[1]
        message = message[i+1:]
    else:
        i += 1

print(dict)

'''
###################################################################
# Parser  2
'''
message = "foo=bar&baz=qux&zap=zazzle"
parsed_dict = {}

# Split the string into key-value pairs
pairs = message.split("&")

# Iterate over each pair and split into key and value
for pair in pairs:
    key, value = pair.split("=")  # tuple unpacking ( # This splits into ['foo', 'bar'] and assigns key='foo', value='bar' )
    parsed_dict[key] = value

print(parsed_dict)
'''
###################################################################
