from flask import Flask, request, jsonify
import asyncio
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from google.protobuf.json_format import MessageToJson
import binascii
import aiohttp
import requests
import json
import like_pb2
import like_count_pb2
import uid_generator_pb2
from google.protobuf.message import DecodeError
import os

app = Flask(__name__)

# Load tokens from JSON file
def load_tokens(server_name):
    try:
        token_files = {
            "IND": "token_ind.json",
            "BR": "token_br.json",
            "US": "token_br.json",
            "SAC": "token_br.json",
            "NA": "token_br.json",
        }
        token_file = token_files.get(server_name, "token_bd.json")

        if not os.path.exists(token_file):
            app.logger.error(f"Token file not found: {token_file}")
            return None

        with open(token_file, "r") as f:
            tokens = json.load(f)
        
        if not tokens or not isinstance(tokens, list):
            app.logger.error(f"Invalid token format in {token_file}")
            return None
        
        return tokens
    except Exception as e:
        app.logger.error(f"Error loading tokens for {server_name}: {e}")
        return None

# Encrypt data using AES
def encrypt_message(plaintext):
    try:
        key = b'Yg&tc%DEuh6%Zc^8'
        iv = b'6oyZDr22E3ychjM%'
        cipher = AES.new(key, AES.MODE_CBC, iv)
        padded_message = pad(plaintext, AES.block_size)
        encrypted_message = cipher.encrypt(padded_message)
        return binascii.hexlify(encrypted_message).decode('utf-8')
    except Exception as e:
        app.logger.error(f"Error encrypting message: {e}")
        return None

# Create Protobuf message for UID
def create_protobuf_message(user_id, region):
    try:
        message = like_pb2.like()
        message.uid = int(user_id)
        message.region = region
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating protobuf message: {e}")
        return None

# Send request to game server
async def send_request(encrypted_uid, token, url):
    try:
        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
        }
        async with aiohttp.ClientSession() as session:
            async with session.post(url, data=bytes.fromhex(encrypted_uid), headers=headers) as response:
                app.logger.info(f"Request to {url} returned {response.status}")
                if response.status != 200:
                    return None
                return await response.text()
    except Exception as e:
        app.logger.error(f"Exception in send_request: {e}")
        return None

# Send multiple like requests
async def send_multiple_requests(uid, server_name, url, total_requests=100):
    try:
        protobuf_message = create_protobuf_message(uid, server_name)
        if not protobuf_message:
            return None
        encrypted_uid = encrypt_message(protobuf_message)
        if not encrypted_uid:
            return None
        tokens = load_tokens(server_name)
        if not tokens:
            return None

        tasks = [send_request(encrypted_uid, tokens[i % len(tokens)]["token"], url) for i in range(total_requests)]
        return await asyncio.gather(*tasks, return_exceptions=True)
    except Exception as e:
        app.logger.error(f"Exception in send_multiple_requests: {e}")
        return None

# Create Protobuf for UID encryption
def create_protobuf(uid):
    try:
        message = uid_generator_pb2.uid_generator()
        message.saturn_ = int(uid)
        message.garena = 1
        return message.SerializeToString()
    except Exception as e:
        app.logger.error(f"Error creating UID protobuf: {e}")
        return None

# Encrypt UID
def enc(uid):
    protobuf_data = create_protobuf(uid)
    return encrypt_message(protobuf_data) if protobuf_data else None

# Make request to get player info
def make_request(encrypt, server_name, token):
    try:
        url_map = {
            "IND": "https://client.ind.freefiremobile.com/GetPlayerPersonalShow",
            "BR": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "US": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "SAC": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
            "NA": "https://client.us.freefiremobile.com/GetPlayerPersonalShow",
        }
        url = url_map.get(server_name, "https://clientbp.ggblueshark.com/GetPlayerPersonalShow")

        headers = {
            'User-Agent': "Dalvik/2.1.0 (Linux; U; Android 10; ASUS_Z01QD Build/Release)",
            'Authorization': f"Bearer {token}",
            'Content-Type': "application/x-www-form-urlencoded",
        }

        app.logger.info(f"Making request to {url} with token {token[:6]}... and UID {encrypt}")

        response = requests.post(url, data=bytes.fromhex(encrypt), headers=headers, verify=False)
        
        # Log response details
        app.logger.info(f"Response Code: {response.status_code}, Response Text: {response.text[:100]}")

        if response.status_code != 200:
            return None

        return decode_protobuf(response.content.hex())
    except Exception as e:
        app.logger.error(f"Error in make_request: {e}")
        return None

# Decode Protobuf response
def decode_protobuf(binary):
    try:
        items = like_count_pb2.Info()
        items.ParseFromString(bytes.fromhex(binary))
        return items
    except DecodeError as e:
        app.logger.error(f"Error decoding Protobuf: {e}")
        return None

@app.route('/like', methods=['GET'])
def handle_requests():
    uid = request.args.get("uid")
    server_name = request.args.get("server_name", "").upper()
    
    if not uid or not server_name:
        return jsonify({"error": "UID and server_name are required"}), 400

    try:
        tokens = load_tokens(server_name)
        if not tokens:
            return jsonify({"error": "Failed to load tokens."}), 500
        
        token = tokens[0]['token']
        encrypted_uid = enc(uid)
        if not encrypted_uid:
            return jsonify({"error": "Encryption of UID failed."}), 500

        before = make_request(encrypted_uid, server_name, token)
        if before is None:
            return jsonify({"error": "Failed to retrieve initial player info."}), 500

        before_like = int(json.loads(MessageToJson(before)).get('AccountInfo', {}).get('Likes', 0))

        url_map = {
            "IND": "https://client.ind.freefiremobile.com/LikeProfile",
            "BR": "https://client.us.freefiremobile.com/LikeProfile",
            "US": "https://client.us.freefiremobile.com/LikeProfile",
            "SAC": "https://client.us.freefiremobile.com/LikeProfile",
            "NA": "https://client.us.freefiremobile.com/LikeProfile",
        }
        url = url_map.get(server_name, "https://clientbp.ggblueshark.com/LikeProfile")

        asyncio.run(send_multiple_requests(uid, server_name, url, total_requests=len(tokens)))

        after = make_request(encrypted_uid, server_name, token)
        if after is None:
            return jsonify({"error": "Failed to retrieve player info after like requests."}), 500

        after_like = int(json.loads(MessageToJson(after)).get('AccountInfo', {}).get('Likes', 0))

        return jsonify({
            "LikesGivenByAPI": after_like - before_like,
            "LikesafterCommand": after_like,
            "LikesbeforeCommand": before_like,
            "status": 1 if after_like > before_like else 2
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)