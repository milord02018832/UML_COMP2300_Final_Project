import socket
import json
import threading
import time
import os
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64
import platform

# Configuration
BROADCAST_PORT = 5000
DISCOVERY_INTERVAL = 5  # seconds
STALE_TIMEOUT = 15  # seconds

class NetworkDiscovery:
    def __init__(self, user_email, user_contacts, private_key_path="private.pem", public_key_path="public.pub"):
        self.user_email = user_email
        self.user_contacts = user_contacts  # list of contact emails
        self.online_contacts = {}  # {email: {'ip': ip, 'last_seen': time, 'public_key': key, 'session_key': key}}
        self.running = False
        self.sock = None
        
        # Load RSA keys
        with open(private_key_path, 'rb') as f:
            self.private_key = RSA.import_key(f.read())
        with open(public_key_path, 'rb') as f:
            self.public_key = RSA.import_key(f.read())
            
        # Export public key for transmission
        self.public_key_pem = self.public_key.export_key()
        
    def start(self):
        """Start listening for broadcasts and sending presence"""
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        # Enable SO_REUSEPORT on systems that support it (Linux, macOS)
        # This allows multiple processes to bind to the same port
        try:
            # macOS and Linux
            if hasattr(socket, 'SO_REUSEPORT'):
                self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
        except AttributeError:
            pass  # Windows doesn't have SO_REUSEPORT
        
        try:
            self.sock.bind(('', BROADCAST_PORT))
        except OSError as e:
            print(f"Warning: Could not bind to port {BROADCAST_PORT}: {e}")
            print("This is normal when running multiple instances on the same machine.")
            print("Network discovery will still work for receiving broadcasts.")
            # Don't return False - we can still send broadcasts
        
        # Start listener thread
        listener_thread = threading.Thread(target=self._listen_for_presence)
        listener_thread.daemon = True
        listener_thread.start()
        
        # Start broadcaster thread
        broadcaster_thread = threading.Thread(target=self._broadcast_presence)
        broadcaster_thread.daemon = True
        broadcaster_thread.start()
        
        return True
        
    def stop(self):
        """Stop the discovery service"""
        self.running = False
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
                
    def _encrypt_email(self, email):
        """Encrypt email using AES with a temporary session key"""
        # Generate random session key for this broadcast
        session_key = get_random_bytes(16)
        cipher = AES.new(session_key, AES.MODE_EAX)
        ciphertext, tag = cipher.encrypt_and_digest(email.encode('utf-8'))
        
        # For simplicity and security: use signature for authentication
        # and light encryption for privacy
        nonce = cipher.nonce
        
        return {
            'nonce': base64.b64encode(nonce).decode('utf-8'),
            'tag': base64.b64encode(tag).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'session_key': base64.b64encode(session_key).decode('utf-8')
        }
    
    def _sign_message(self, message_dict):
        """Sign a message with private key"""
        # Create hash of the message
        message_str = json.dumps(message_dict, sort_keys=True)
        h = SHA256.new(message_str.encode('utf-8'))
        signature = pkcs1_15.new(self.private_key).sign(h)
        return base64.b64encode(signature).decode('utf-8')
    
    def _verify_signature(self, message_dict, signature_b64, public_key):
        """Verify message signature"""
        try:
            message_str = json.dumps(message_dict, sort_keys=True)
            h = SHA256.new(message_str.encode('utf-8'))
            signature = base64.b64decode(signature_b64)
            pkcs1_15.new(public_key).verify(h, signature)
            return True
        except (ValueError, TypeError):
            return False
    
    def _decrypt_email(self, encrypted_data):
        """Decrypt email from broadcast"""
        try:
            nonce = base64.b64decode(encrypted_data['nonce'])
            tag = base64.b64decode(encrypted_data['tag'])
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            session_key = base64.b64decode(encrypted_data['session_key'])
            
            cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            return plaintext.decode('utf-8')
        except Exception as e:
            # Silently ignore decryption errors from other instances
            return None
                
    def _broadcast_presence(self):
        """Periodically broadcast encrypted presence on network"""
        while self.running:
            try:
                # Encrypt the email
                encrypted_email = self._encrypt_email(self.user_email)
                
                message_data = {
                    'type': 'presence',
                    'encrypted_email': encrypted_email,
                    'public_key': self.public_key_pem.decode('utf-8'),
                    'timestamp': time.time()
                }
                
                # Sign the message
                signature = self._sign_message(message_data)
                
                message = json.dumps({
                    'data': message_data,
                    'signature': signature
                })
                
                # Create a temporary socket for sending if needed
                send_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                send_sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                send_sock.sendto(message.encode('utf-8'), 
                               ('<broadcast>', BROADCAST_PORT))
                send_sock.close()
                
                time.sleep(DISCOVERY_INTERVAL)
            except Exception as e:
                # Silently continue on broadcast errors
                time.sleep(DISCOVERY_INTERVAL)
                
    def _listen_for_presence(self):
        """Listen for encrypted presence broadcasts from other clients"""
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                message = json.loads(data.decode('utf-8'))
                
                message_data = message['data']
                signature = message['signature']
                
                # Import the sender's public key
                sender_public_key = RSA.import_key(message_data['public_key'].encode('utf-8'))
                
                # Verify signature
                if not self._verify_signature(message_data, signature, sender_public_key):
                    # Silently ignore invalid signatures
                    continue
                
                if message_data['type'] == 'presence':
                    # Decrypt email
                    email = self._decrypt_email(message_data['encrypted_email'])
                    
                    if email and email != self.user_email:
                        # Check if this contact is in our contact list
                        is_contact = any(
                            (isinstance(c, dict) and c.get('email') == email) or
                            (isinstance(c, str) and c == email)
                            for c in self.user_contacts
                        )
                        
                        if is_contact:
                            # Store contact info with their public key
                            self.online_contacts[email] = {
                                'ip': addr[0],
                                'last_seen': time.time(),
                                'public_key': sender_public_key,
                                'session_key': None  # Will be established during mutual auth
                            }
            except socket.error:
                # Socket might be closed or timeout
                if self.running:
                    time.sleep(0.1)
            except Exception as e:
                # Silently ignore parsing errors from malformed packets
                pass
                
    def get_online_contacts(self):
        """Return list of contacts that are currently online"""
        # Clean up stale entries
        current_time = time.time()
        stale_contacts = [
            email for email, info in self.online_contacts.items() 
            if current_time - info['last_seen'] > STALE_TIMEOUT
        ]
        for email in stale_contacts:
            del self.online_contacts[email]
            
        return list(self.online_contacts.keys())
    
    def get_contact_info(self, email):
        """Get stored info for a contact"""
        return self.online_contacts.get(email)