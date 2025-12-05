import hashlib
import json
import os

# Port range for user assignment
BASE_DISCOVERY_PORT = 5000
BASE_AUTH_PORT = 6000
PORT_RANGE = 1000  # Allows 1000 unique users

class PortManager:
    """
    Manages unique port assignments for each user based on their email.
    Each user gets consistent ports across sessions.
    """
    
    def __init__(self, user_email):
        self.user_email = user_email
        self.discovery_port = None
        self.auth_port = None
        self._assign_ports()
        
    def _assign_ports(self):
        """
        Assign unique ports to user based on email hash.
        This ensures the same user always gets the same ports.
        """
        # Create a hash of the email
        email_hash = hashlib.sha256(self.user_email.encode('utf-8')).hexdigest()
        
        # Convert hash to integer and use modulo to get port offset
        hash_int = int(email_hash[:8], 16)  # Use first 8 hex chars
        port_offset = hash_int % PORT_RANGE
        
        # Assign ports with offset
        self.discovery_port = BASE_DISCOVERY_PORT + port_offset
        self.auth_port = BASE_AUTH_PORT + port_offset
        
        # Save port assignment to file
        self._save_port_assignment()
        
    def _save_port_assignment(self):
        """Save port assignment to a file for reference"""
        port_file = f"ports_{self.user_email.replace('@', '_at_').replace('.', '_')}.json"
        port_data = {
            'email': self.user_email,
            'discovery_port': self.discovery_port,
            'auth_port': self.auth_port
        }
        
        with open(port_file, 'w') as f:
            json.dump(port_data, f, indent=2)
    
    @staticmethod
    def load_port_assignment(user_email):
        """Load existing port assignment for a user"""
        port_file = f"ports_{user_email.replace('@', '_at_').replace('.', '_')}.json"
        
        if os.path.exists(port_file):
            with open(port_file, 'r') as f:
                port_data = json.load(f)
                return port_data['discovery_port'], port_data['auth_port']
        
        return None, None
    
    def get_discovery_port(self):
        """Get the user's unique discovery port"""
        return self.discovery_port
    
    def get_auth_port(self):
        """Get the user's unique authentication port"""
        return self.auth_port
    
    def __str__(self):
        return f"PortManager({self.user_email}): Discovery={self.discovery_port}, Auth={self.auth_port}"


def get_user_ports(user_email):
    """
    Convenience function to get ports for a user.
    Returns (discovery_port, auth_port)
    """
    # Try to load existing assignment
    discovery_port, auth_port = PortManager.load_port_assignment(user_email)
    
    if discovery_port and auth_port:
        return discovery_port, auth_port
    
    # Create new assignment
    pm = PortManager(user_email)
    return pm.get_discovery_port(), pm.get_auth_port()


def display_port_info(user_email):
    """Display port information for a user"""
    discovery_port, auth_port = get_user_ports(user_email)
    
    print(f"\n{'='*50}")
    print(f"Port Assignment for {user_email}")
    print(f"{'='*50}")
    print(f"Discovery Port (UDP): {discovery_port}")
    print(f"Authentication Port (TCP): {auth_port}")
    print(f"{'='*50}\n")
    
    return discovery_port, auth_port


if __name__ == "__main__":
    # Test the port manager
    print("Testing Port Manager\n")
    
    test_emails = [
        "alice@example.com",
        "bob@example.com",
        "charlie@example.com"
    ]
    
    for email in test_emails:
        pm = PortManager(email)
        print(pm)
    
    print("\n\nVerifying consistency (same email should get same ports):")
    for email in test_emails:
        disc, auth = get_user_ports(email)
        print(f"{email}: Discovery={disc}, Auth={auth}")