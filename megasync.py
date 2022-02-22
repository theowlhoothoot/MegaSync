from mega import Mega
from mega.crypto import base64_to_a32, base64_url_decode, decrypt_attr, decrypt_key
from typing import Tuple
import queue
import threading
import math
import re
import json
import logging
import secrets
from pathlib import Path
import hashlib
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Util import Counter
import os
import random
import binascii
import tempfile
import shutil
import re, requests, json
import os
from os.path import exists
import threading
import queue
import requests
from tenacity import retry, wait_exponential, retry_if_exception_type
import configparser
from crypto import (a32_to_base64, encrypt_key, base64_url_encode,
                    encrypt_attr, base64_to_a32, base64_url_decode,
                    decrypt_attr, a32_to_str, get_chunks, str_to_a32,
                    decrypt_key, mpi_to_int, stringhash, prepare_key, make_id,
                    makebyte, modular_inverse)

config = configparser.ConfigParser()

try:
    config.read('config.ini')
    base_name = config['DEFAULT']['localSyncBaseFolder']
    base_url = config['DEFAULT']['megaURL']
    threadingEnabled = config['DEFAULT']['betaThreading']
    folderToIgnore = config['DEFAULT']['folderToIgnore']
    folderToIgnore = json.loads(folderToIgnore)
except:
    print ("Error reading your config files. Be sure you have the correct variables and file location.")
    exit(0)


mega = Mega()
email = ""
password = ""
m = mega.login(email, password)


def get_nodes_in_shared_folder(root_folder: str) -> dict:
    data = [{"a": "f", "c": 1, "ca": 1, "r": 1}]
    response = requests.post(
        "https://g.api.mega.co.nz/cs",
        params={'id': 0,  # self.sequence_num
                'n': root_folder},
        data=json.dumps(data)
    )
    json_resp = response.json()
    return json_resp[0]["f"]

def parse_folder_url(url: str) -> Tuple[str, str]:
    "Returns (public_handle, key) if valid. If not returns None."
    REGEXP1 = re.compile(r"mega.[^/]+/folder/([0-z-_]+)#([0-z-_]+)(?:/folder/([0-z-_]+))*")
    REGEXP2 = re.compile(r"mega.[^/]+/#F!([0-z-_]+)[!#]([0-z-_]+)(?:/folder/([0-z-_]+))*")
    m = re.search(REGEXP1, url)
    if not m:
        m = re.search(REGEXP2, url)
    if not m:
        print("Not a valid URL")
        return None
    root_folder = m.group(1)
    key = m.group(2)
    # You may want to use m.group(-1)
    # to get the id of the subfolder
    return (root_folder, key)

def decrypt_node_key(key_str: str, shared_key: str) -> Tuple[int, ...]:
    encrypted_key = base64_to_a32(key_str.split(":")[1])
    return decrypt_key(encrypted_key, shared_key)

def _download_file(file_data, file_key, file_name):
    print(file_name)
    file_url = file_data['g']
    file_size = file_data['s']
    k = (file_key[0] ^ file_key[4], file_key[1] ^ file_key[5],
         file_key[2] ^ file_key[6], file_key[3] ^ file_key[7])
    iv = file_key[4:6] + (0, 0)
    meta_mac = file_key[6:8]

    attribs = base64_url_decode(file_data['at'])
    attribs = decrypt_attr(attribs, file_key)

    input_file = requests.get(file_url, stream=True).raw

    with tempfile.NamedTemporaryFile(mode='w+b', prefix='megapy_', delete=False) as temp_output_file:
        k_str = a32_to_str(k)
        counter = Counter.new(128, initial_value=((iv[0] << 32) + iv[1]) << 64)
        aes = AES.new(k_str, AES.MODE_CTR, counter=counter)

        mac_str = '\0' * 16
        mac_encryptor = AES.new(k_str, AES.MODE_CBC, mac_str.encode("utf8"))
        iv_str = a32_to_str([iv[0], iv[1], iv[0], iv[1]])

        for chunk_start, chunk_size in get_chunks(file_size):
            chunk = input_file.read(chunk_size)
            chunk = aes.decrypt(chunk)
            temp_output_file.write(chunk)

            encryptor = AES.new(k_str, AES.MODE_CBC, iv_str)
            for i in range(0, len(chunk) - 16, 16):
                block = chunk[i:i + 16]
                encryptor.encrypt(block)

                # fix for files under 16 bytes failing
            if file_size > 16:
                i += 16
            else:
                i = 0

            block = chunk[i:i + 16]
            if len(block) % 16:
                block += b'\0' * (16 - (len(block) % 16))

            # mac_str = mac_encryptor.encrypt(encryptor.encrypt(block))

            # file_info = os.stat(temp_output_file.name)
            # file_mac = str_to_a32(mac_str)
            # check mac integrity
            # if (file_mac[0] ^ file_mac[1],file_mac[2] ^ file_mac[3]) != meta_mac:
            #    raise ValueError('Mismatched mac')

    output_path = Path(file_name)
    shutil.move(temp_output_file.name, output_path)

# This starts the process of getting the encryption key for downloading.
def downloadSomething(root_folder: str, file_data) -> dict:
    response = requests.post(
        "https://g.api.mega.co.nz/cs",
        params={'id': 0,  # self.sequence_num
                'n': root_folder},
        data=json.dumps(file_data)
    )
    json_resp = response.json()
    return json_resp[0]

# This proccesses a mega node that we have.
def process_node(node):
    global downloaded_count
    global base_id
    key = decrypt_node_key(node["k"], shared_key)

    isFile = None

    if node["t"] == 0:  # Is a file
        isFile = True
        k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
    elif node["t"] == 1:  # Is a folder
        isFile = False
        k = key

    attrs = decrypt_attr(base64_url_decode(node["a"]), k)

    file_name = attrs["n"]
    file_id = node["h"]

    if (file_id != base_id):
        file_data = [{'a': 'g', 'g': 1, 'n': node['h']}]

        if (node["p"] == base_id):
            if (isFile):
                filePath = "{0}/{1}".format(base_name, file_name)

                if not (exists(filePath)):
                    something = downloadSomething(root_folder, file_data)

                    try:
                        if isAllowed(filePath):
                            _download_file(something, key, filePath)
                    except Exception as e:
                        print("Error on " + file_name, e)

            else:
                folder_path = "{0}/{1}".format(base_name, file_name)
                files[file_id] = folder_path

                if not (exists(folder_path)):
                    if isAllowed(folder_path):
                        path = os.path.join(base_name, file_name)
                        os.mkdir(path)
        else:
            if (isFile):
                filePath = "{0}/{1}".format(files[node["p"]], file_name)
                if not (exists(filePath)):
                    something = downloadSomething(root_folder, file_data)
                    try:
                        if isAllowed(filePath):
                            _download_file(something, key, filePath)
                    except Exception as e:
                        print("Error on " + file_name, e)
                else:
                    pass

            else:
                folder_path = "{0}/{1}".format(files[node["p"]], file_name)
                files[file_id] = folder_path

                if not (exists(folder_path)):
                    if isAllowed(folder_path):
                        path = os.path.join(files[node["p"]], file_name)
                        os.mkdir(path)

    downloaded_count += 1

    print(downloaded_count, "/", total_file_count, " files have been checked")

# This will process one file at a time.
def main():
    for node in nodes:
        process_node(node)

def do_work(item):
    process_node(item)

def worker():
    while True:
        item = q.get()
        if item is None:
            break
        do_work(item)
        q.task_done()

def mainThreading():
    for i in range(num_worker_threads):
        t = threading.Thread(target=worker)
        t.start()
        threads.append(t)

    for item in nodes:
        q.put(item)

    # block until all tasks are done
    q.join()

    print('stopping workers!')

    # stop workers
    for i in range(num_worker_threads):
        q.put(None)

    for t in threads:
        t.join()
# This basically just gets the base folder id so we can get the relative location of every file from mega.
def getBaseFolderID():
    global downloaded_count
    node = nodes[0]

    key = decrypt_node_key(node["k"], shared_key)

    isFile = None

    if node["t"] == 0:  # Is a file
        isFile = True
        k = (key[0] ^ key[4], key[1] ^ key[5], key[2] ^ key[6], key[3] ^ key[7])
    elif node["t"] == 1:  # Is a folder
        isFile = False
        k = key

    attrs = decrypt_attr(base64_url_decode(node["a"]), k)

    file_name = attrs["n"]
    file_id = node["h"]

    downloaded_count += 1

    return file_id

def isAllowed(fileName):
    isAllowed = True
    for folder in folderToIgnore:
        folder = base_name + "/" + folder
        if folder in fileName:
            isAllowed = False

    return isAllowed

(root_folder, shared_enc_key) = parse_folder_url(base_url)

shared_key = base64_to_a32(shared_enc_key)
nodes = get_nodes_in_shared_folder(root_folder)

folder_structure = {}
files = {}
total_file_count = len(nodes)

file_count = 0
downloaded_count = 0

num_worker_threads = 10
q = queue.Queue()
threads = []

if base_name and base_url:
    print ("Syncing {0} to {1}".format(base_url, base_name))

    print ("Skipping {0}".format(",".join(folderToIgnore)))

    base_id = getBaseFolderID()

    if threadingEnabled == 'True':
        mainThreading()
    else:
        main()
else:
    print ("Error getting sync folder / mega. Please check your config settings.")
