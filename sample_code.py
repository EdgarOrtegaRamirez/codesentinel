"""Sample file with intentional issues for testing CodeSentinel."""

import os
import pickle
import subprocess
import tempfile

# AI-003: Global variable
total = 0


def process_data(data, items=[], config={}):
    # AI-017: Reassigning parameter
    data = data.strip()
    # AI-024: Mutable default arguments
    global total  # AI-003
    total += len(data)
    return data


def load_config(path):
    # SEC-001: Unsafe pickle
    with open(path, 'rb') as f:
        return pickle.load(f)


def run_command(cmd):
    # SEC-002: os.system
    os.system(cmd)


def run_safe(cmd):
    # SEC-003: subprocess shell=True
    subprocess.run(cmd, shell=True)


def create_temp():
    # SEC-003: mktemp
    return tempfile.mktemp()


def hash_data(data):
    # SEC-004: Weak hash
    import hashlib
    return hashlib.md5(data).hexdigest()


# AI-004: eval usage
def safe_eval():
    result = eval("1 + 2 + 3")
    return result


# AI-005: Hardcoded password
password = "super_secret_password_123"
api_key = "sk-1234567890abcdef"


# AI-014: File operations without error handling
def read_file(path):
    f = open(path)
    return f.read()


# AI-019: Print statements
def greet(name):
    print("Hello, " + name)
    return name


# AI-011: Commented code
# TODO: implement this properly
# FIXME: this is broken
# HACK: temporary workaround
# DEBUG: print("here")
# TEMP: remove later


# AI-010: Inefficient list comprehension
def process_items():
    for i in range(100):
        results = [i * 2 for _ in range(i)]


# AI-012: Long line
def calculate():
    result = some_function_that_takes_a_very_long_argument_list_that_should_be_split_across_multiple_lines_for_readability_purposes(first_arg=1, second_arg=2, third_arg=3)
    return result


if __name__ == "__main__":
    process_data("  hello  ")
    load_config("config.pkl")
