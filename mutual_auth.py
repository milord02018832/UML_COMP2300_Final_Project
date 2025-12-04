import socket
import json
import threading
import time
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
import base64

AUTH_PORT = 5001

class MutualAuthServer:
    def __init__(self, user_email, user_contacts, private_key, public_key):
        self.user_email = user_email
        self.user_contacts = user_contacts
        self.private_key = private_key
        self.public_key = public_key
        self.server_sock = None
        self.running = False
        self.established_sessions = {}  # {email: session_key}
        
    def start(self):
        """Start the mutual authentication server"""
        self.running = True
        
        def server_loop():
            try:
                self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                self.server_sock.bind(('', AUTH_PORT))
                self.server_sock.listen(5)
                
                while self.running:
                    try:
                        self.server_sock.settimeout(1.0)
                        client_sock, addr = self.server_sock.accept()
                        threading.Thread(target=self._handle_client, args=(client_sock, addr)).start()
                    except socket.timeout:
                        continue
                    except Exception as e:
                        if self.running:
                            print(f"Accept error: {e}")
            except Exception as e:
                print(f"Server error: {e}")
            finally:
                if self.server_sock:
                    self.server_sock.close()
        
        thread = threading.Thread(target=server_loop)
        thread.daemon = True
        thread.start()
        
    def stop(self):
        """Stop the authentication server"""
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except:
                pass
    
    def _sign_message(self, message_dict):
        """Sign a message with private key"""
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
        
    def _handle_client(self, client_sock, addr):
        """Handle mutual authentication request"""
        try:
            # Receive authentication request
            data = client_sock.recv(8192).decode('utf-8')
            request = json.loads(data)
            
            message_data = request['data']
            signature = request['signature']
            
            # Import requester's public key
            requester_public_key = RSA.import_key(message_data['public_key'].encode('utf-8'))
            
            # Verify signature
            if not self._verify_signature(message_data, signature, requester_public_key):
                response = json.dumps({'error': 'Invalid signature'})
                client_sock.sendall(response.encode('utf-8'))
                return
            
            requester_email = message_data['email']
            challenge = message_data['challenge']
            
            # Check if requester is in our contacts
            has_contact = any(
                (isinstance(c, dict) and c.get('email') == requester_email) or
                (isinstance(c, str) and c == requester_email)
                for c in self.user_contacts
            )
            
            if not has_contact:
                response = json.dumps({'has_contact': False})
                client_sock.sendall(response.encode('utf-8'))
                return
            
            # Generate session key for future communication
            session_key = get_random_bytes(32)
            self.established_sessions[requester_email] = session_key
            
            # Encrypt session key with requester's public key
            cipher_rsa = PKCS1_OAEP.new(requester_public_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key)
            
            # Create response with challenge response and our info
            response_data = {
                'has_contact': True,
                'email': self.user_email,
                'challenge_response': challenge,  # Echo back the challenge
                'encrypted_session_key': base64.b64encode(encrypted_session_key).decode('utf-8'),
                'timestamp': time.time()
            }
            
            # Sign the response
            response_signature = self._sign_message(response_data)
            
            response = json.dumps({
                'data': response_data,
                'signature': response_signature,
                'public_key': self.public_key.export_key().decode('utf-8')
            })
            
            client_sock.sendall(response.encode('utf-8'))
            
        except Exception as e:
            print(f"Auth handler error: {e}")
            try:
                error_response = json.dumps({'error': str(e)})
                client_sock.sendall(error_response.encode('utf-8'))
            except:
                pass
        finally:
            client_sock.close()
    
    def get_session_key(self, email):
        """Get established session key for a contact"""
        return self.established_sessions.get(email)


class MutualAuthClient:
    def __init__(self, my_email, private_key, public_key):
        self.my_email = my_email
        self.private_key = private_key
        self.public_key = public_key
        self.session_keys = {}  # {email: session_key}
        
    def _sign_message(self, message_dict):
        """Sign a message with private key"""
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
    
    def verify_mutual_contact(self, contact_email, contact_ip, contact_public_key):
        """
        Verify mutual contact relationship and establish session key
        Returns (has_mutual_relationship, session_key)
        """
        try:
            # Create socket connection
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(10)
            sock.connect((contact_ip, AUTH_PORT))
            
            # Generate challenge (random nonce)
            challenge = base64.b64encode(get_random_bytes(32)).decode('utf-8')
            
            # Create authentication request
            request_data = {
                'type': 'verify_mutual',
                'email': self.my_email,
                'challenge': challenge,
                'public_key': self.public_key.export_key().decode('utf-8'),
                'timestamp': time.time()
            }
            
            # Sign the request
            signature = self._sign_message(request_data)
            
            request = json.dumps({
                'data': request_data,
                'signature': signature
            })
            
            sock.sendall(request.encode('utf-8'))
            
            # Receive response
            response_data = sock.recv(8192).decode('utf-8')
            response = json.loads(response_data)
            
            sock.close()
            
            # Check for error
            if 'error' in response:
                print(f"Authentication error: {response['error']}")
                return False, None
            
            # Verify response structure
            if 'data' not in response or 'signature' not in response:
                return False, None
            
            response_msg = response['data']
            response_sig = response['signature']
            
            # Import and verify with contact's public key
            if not self._verify_signature(response_msg, response_sig, contact_public_key):
                print("Warning: Invalid response signature")
                return False, None
            
            # Check if they have us as a contact
            if not response_msg.get('has_contact', False):
                return False, None
            
            # Verify challenge response
            if response_msg.get('challenge_response') != challenge:
                print("Warning: Challenge response mismatch")
                return False, None
            
            # Decrypt session key
            encrypted_session_key = base64.b64decode(response_msg['encrypted_session_key'])
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            session_key = cipher_rsa.decrypt(encrypted_session_key)
            
            # Store session key
            self.session_keys[contact_email] = session_key
            
            return True, session_key
            
        except socket.timeout:
            print(f"Connection to {contact_email} timed out")
            return False, None
        except Exception as e:
            print(f"Verification error with {contact_email}: {e}")
            return False, None
    
    def get_session_key(self, email):
        """Get established session key for a contact"""
        return self.session_keys.get(email)


def encrypt_with_session_key(session_key, data):
    """Encrypt data using established session key"""
    cipher = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return {
        'nonce': base64.b64encode(cipher.nonce).decode('utf-8'),
        'tag': base64.b64encode(tag).decode('utf-8'),
        'ciphertext': base64.b64encode(ciphertext).decode('utf-8')
    }


def decrypt_with_session_key(session_key, encrypted_data):
    """Decrypt data using established session key"""
    nonce = base64.b64decode(encrypted_data['nonce'])
    tag = base64.b64decode(encrypted_data['tag'])
    ciphertext = base64.b64decode(encrypted_data['ciphertext'])
    
    cipher = AES.new(session_key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    return plaintext