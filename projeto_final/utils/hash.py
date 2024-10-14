import hashlib
from dotenv import load_dotenv
import os
import uuid

load_dotenv()

def hashing_input(input):
    h = hashlib.new(os.getenv("HASH_KEY"))
    h.update(input.encode())
    return h.hexdigest()

def hashing_input_with_salt(input, salt):
    h = hashlib.new(os.getenv("HASH_KEY"))
    salted_input = input + salt
    h.update(salted_input.encode())
    return h.hexdigest()

def generate_salt():
    return uuid.uuid4().hex