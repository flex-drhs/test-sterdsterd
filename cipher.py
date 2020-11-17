from Crypto.Cipher import AES
import base64, os

def generate_secret_key_for_AES_cipher():
	AES_key_length = 16
	secret_key = os.urandom(AES_key_length)
	encoded_secret_key = base64.b64encode(secret_key)
	return encoded_secret_key

def encrypt_message(private_msg, encoded_secret_key, padding_character):
	secret_key = base64.b64decode(encoded_secret_key)
	cipher = AES.new(secret_key)
	padded_private_msg = private_msg + (padding_character * ((16 - len(private_msg)) % 16))
	encrypted_msg = cipher.encrypt(padded_private_msg)
	encoded_encrypted_msg = base64.b64encode(encrypted_msg)
	return encoded_encrypted_msg

def decrypt_message(encoded_encrypted_msg, encoded_secret_key, padding_character):
	secret_key = base64.b64decode(encoded_secret_key)
	encrypted_msg = base64.b64decode(encoded_encrypted_msg)
	cipher = AES.new(secret_key)
	decrypted_msg = cipher.decrypt(encrypted_msg)
	unpadded_private_msg = decrypted_msg.rstrip(padding_character.encode())
	return unpadded_private_msg

padding_character = "{"

encrypted_msg = "KK3rlcXTEEShIMMpJ/CUZzPSrjAqXEbvgm/5IiVY8IjAu7ESm7SlPcWPaKdIL362"
decrypted_msg1 = decrypt_message(encrypted_msg, "NLys21Ue3ukP7oq8THRiSw==", padding_character)
decrypted_msg2 = decrypt_message(encrypted_msg, "m74p1eilAaMWpAxaxGw1Tw==", padding_character)

print(f"Decrypted Msg w/ right key: {decrypted_msg1} - ({len(decrypted_msg1)})")
print(f"Decrypted Msg w/ wrong key: {decrypted_msg1} - ({len(decrypted_msg1)})")

