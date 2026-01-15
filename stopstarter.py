#!/usr/bin/env python3
"""
YouTube Stream Scheduler with OBS WebSocket 5.x Integration
"""

import json
import time
import socket
import struct
import hashlib
import base64
import random
import requests
import errno
from datetime import datetime, timedelta, timezone, time as dt_time
from dataclasses import dataclass
from typing import List, Optional, Tuple
import os
import glob

# ============================================================================
# USER CONFIGURATION
# ============================================================================

LIVESTREAM_NAME = "LIVESTREAM"

# Schedule sets: (STOP_TIME, START_TIME) in 24-hour format with leading zeros
SCHEDULE_SETS = [
    ("11:55", "12:00"),
    ("23:55", "00:00"),
]

# Schedule timing tolerance in seconds
SCHEDULE_TOLERANCE_SECONDS = 10

# How many seconds before scheduled start time to begin going live
START_EARLY_SECONDS = 2

# YouTube video category ID (25 = News & Politics; 28 = Science & Technology)
YOUTUBE_CATEGORY_ID = "28"

# ============================================================================
# FILE PATHS
# ============================================================================

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRETS_FILE = os.path.join(SCRIPT_DIR, "passwords/client_secrets.json")
PASSWORDS_FILE = os.path.join(SCRIPT_DIR, "passwords/passwords.txt")
THUMBNAILS_DIR = os.path.join(SCRIPT_DIR, "thumbnails")
DESCRIPTION_FILE = os.path.join(SCRIPT_DIR, "script_files/stopstarter_description.txt")

# ============================================================================
# DATA STRUCTURES
# ============================================================================

@dataclass
class ScheduledEvent:
    """Represents a scheduled event (START or STOP)"""
    event_type: str  # "STOP" or "START"
    time: dt_time
    original_start_time: dt_time  # For START events, this is the actual broadcast time
    
    def get_next_occurrence(self, from_datetime: datetime) -> datetime:
        """Get the next occurrence of this event after the given datetime"""
        today_event = datetime.combine(from_datetime.date(), self.time, timezone.utc)
        
        if today_event > from_datetime:
            return today_event
        else:
            # Event already passed today, return tomorrow's occurrence
            return today_event + timedelta(days=1)

# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def parse_time_string(time_str: str) -> Tuple[int, int]:
    """Convert time string like '11:55' to (hour, minute) tuple"""
    hour_str, minute_str = time_str.split(':')
    return (int(hour_str), int(minute_str))

# ============================================================================
# PASSWORD MANAGER
# ============================================================================

class PasswordManager:
    """Manages credentials from passwords file"""
    
    def __init__(self, passwords_file: str):
        self.passwords = {}
        self._load_passwords(passwords_file)
    
    def _load_passwords(self, file_path: str):
        """Load passwords from file"""
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue
                    if ':' in line:
                        key, value = line.split(':', 1)
                        self.passwords[key.strip()] = value.strip()
        except FileNotFoundError:
            print(f"Error: {file_path} not found")
            raise
        except Exception as e:
            print(f"Error reading passwords file: {e}")
            raise
    
    def get(self, key: str) -> Optional[str]:
        """Get password by key"""
        return self.passwords.get(key)

# ============================================================================
# YOUTUBE API CLIENT
# ============================================================================

class YouTubeAPI:
    """Handles all YouTube API interactions"""
    
    def __init__(self, client_secrets_file: str, refresh_token: str):
        if not refresh_token:
            raise ValueError("YouTube refresh token cannot be None or empty")
            
        self.client_secrets_file = client_secrets_file
        self.refresh_token = refresh_token
        self.access_token = None
        self._load_client_secrets()
    
    def _load_client_secrets(self):
        """Load OAuth client secrets"""
        with open(self.client_secrets_file, 'r') as f:
            secrets = json.load(f)
            client_info = secrets.get('installed', secrets.get('web', {}))
            self.client_id = client_info['client_id']
            self.client_secret = client_info['client_secret']
    
    def refresh_access_token(self) -> bool:
        """Get a fresh access token using the refresh token"""
        url = "https://oauth2.googleapis.com/token"
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
            "grant_type": "refresh_token"
        }
        
        try:
            response = requests.post(url, data=data)
            response.raise_for_status()
            token_data = response.json()
            self.access_token = token_data['access_token']
            print("Successfully refreshed YouTube API access token")
            return True
        except requests.RequestException as e:
            print(f"Error refreshing access token: {e}")
            if hasattr(e, 'response') and e.response:
                print(f"Response: {e.response.text}")
            return False
    
    def _make_api_request(self, url: str, method: str = 'GET', params: dict = None, data: dict = None):
        """Make authenticated API request with automatic token refresh"""
        if not self.access_token:
            if not self.refresh_access_token():
                return None
        
        headers = {
            'Authorization': f'Bearer {self.access_token}',
            'Content-Type': 'application/json'
        }
        
        try:
            if method == 'GET':
                response = requests.get(url, headers=headers, params=params)
            elif method == 'POST':
                if data:
                    response = requests.post(url, headers=headers, params=params, json=data)
                else:
                    response = requests.post(url, headers=headers, params=params)
            elif method == 'PUT':
                if data:
                    response = requests.put(url, headers=headers, params=params, json=data)
                else:
                    response = requests.put(url, headers=headers, params=params)
            else:
                raise ValueError(f"Unsupported HTTP method: {method}")
            
            response.raise_for_status()
            return response.json()
            
        except requests.HTTPError as e:
            if e.response.status_code == 401:
                print("Access token expired, refreshing...")
                if self.refresh_access_token():
                    return self._make_api_request(url, method, params, data)
            
            print(f"API request failed: HTTP {e.response.status_code}")
            print(f"Response: {e.response.text}")
            return None
        except Exception as e:
            print(f"Error making API request: {e}")
            return None
    
    def list_live_broadcasts(self) -> List[dict]:
        """List all current live broadcasts"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        params = {
            "part": "id,snippet,status",
            "mine": "true"
        }
        
        response = self._make_api_request(url, params=params)
        if response:
            return response.get('items', [])
        return []
    
    def find_test_stream(self) -> Optional[dict]:
        """Find and return the broadcast with LIVESTREAM_NAME in title"""
        broadcasts = self.list_live_broadcasts()
        
        for broadcast in broadcasts:
            title = broadcast['snippet']['title']
            status = broadcast['status']['lifeCycleStatus']
            
            if LIVESTREAM_NAME in title:
                if status in ['created', 'ready', 'testing', 'live']:
                    print(f"Found existing stream: {title}")
                    print(f"  ID: {broadcast['id']}")
                    print(f"  Status: {status}")
                    return broadcast
        
        return None
    
    def create_broadcast(self, title: str, start_time: datetime, category_id: str = '25') -> Optional[str]:
        """Create a new broadcast and bind a stream to it"""
        # Create broadcast
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        
        broadcast_data = {
            "snippet": {
                "title": title,
                "scheduledStartTime": start_time.isoformat(),
                "categoryId": category_id
            },
            "status": {
                "privacyStatus": "public",
                "selfDeclaredMadeForKids": False
            },
            "contentDetails": {
                "enableAutoStart": False,
                "enableAutoStop": False,
                "enableDvr": True,
                "recordFromStart": True,
                "startWithSlate": False
            }
        }
        
        params = {"part": "snippet,status,contentDetails"}
        response = self._make_api_request(url, method='POST', params=params, data=broadcast_data)
        
        if not response:
            return None
        
        broadcast_id = response['id']
        print(f"Created broadcast: {title}")
        print(f"  Broadcast ID: {broadcast_id}")
        
        # Load and set description
        try:
            with open(DESCRIPTION_FILE, 'r') as f:
                description = f.read()
        except FileNotFoundError:
            print(f"Description file not found: {DESCRIPTION_FILE}")
            description = "Live stream description goes here"
        
        self._update_broadcast_metadata(broadcast_id, description, title, start_time.isoformat())
        
        # Create and bind stream
        stream_id, stream_key = self.create_stream(title)
        if not stream_id:
            return None
        
        # Store the stream ID and key for later use
        self.current_stream_id = stream_id
        self.current_stream_key = stream_key
        
        if not self.bind_stream_to_broadcast(broadcast_id, stream_id):
            return None
        
        return broadcast_id
    
    def _update_broadcast_metadata(self, broadcast_id: str, description: str, title: str, scheduled_start_time: str):
        """Update broadcast with description and random thumbnail"""
        # Update description (requires all required snippet fields)
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        params = {
            "part": "snippet",
            "id": broadcast_id
        }
        
        broadcast_data = {
            "id": broadcast_id,
            "snippet": {
                "title": title,
                "scheduledStartTime": scheduled_start_time,
                "description": description
            }
        }
        
        response = self._make_api_request(url, method='PUT', params=params, data=broadcast_data)
        if response:
            print(f"Updated broadcast description")
        else:
            print(f"Warning: Failed to update broadcast description")
        
        # Upload random thumbnail
        self._upload_random_thumbnail(broadcast_id)
    
    def _upload_random_thumbnail(self, broadcast_id: str) -> bool:
        """Upload a random thumbnail from the thumbnails directory"""
        try:
            # Get list of image files
            thumbnail_files = []
            for ext in ['*.jpg', '*.jpeg', '*.png']:
                thumbnail_files.extend(glob.glob(os.path.join(THUMBNAILS_DIR, ext)))
            
            if not thumbnail_files:
                print(f"No thumbnail files found in {THUMBNAILS_DIR}")
                return False
            
            # Select random thumbnail
            thumbnail_path = random.choice(thumbnail_files)
            print(f"Selected thumbnail: {os.path.basename(thumbnail_path)}")
            
            # Upload thumbnail
            url = f"https://www.googleapis.com/upload/youtube/v3/thumbnails/set"
            params = {"videoId": broadcast_id}
            
            if not self.access_token:
                if not self.refresh_access_token():
                    return False
            
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            with open(thumbnail_path, 'rb') as f:
                files = {'file': f}
                response = requests.post(url, headers=headers, params=params, files=files)
                response.raise_for_status()
                print("Successfully uploaded thumbnail")
                return True
                
        except Exception as e:
            print(f"Error uploading thumbnail: {e}")
            return False
    
    def end_broadcast(self, broadcast_id: str) -> bool:
        """End a broadcast by transitioning to complete status"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts/transition"
        params = {
            "part": "status",
            "broadcastStatus": "complete",
            "id": broadcast_id
        }
        
        response = self._make_api_request(url, method='POST', params=params)
        if response:
            print(f"Successfully ended Youtube broadcast: {broadcast_id}")
            return True
        else:
            print(f"Failed to end broadcast: {broadcast_id}")
            return False
    
    def create_stream(self, title: str) -> Tuple[Optional[str], Optional[str]]:
        """Create a new liveStream resource"""
        url = "https://www.googleapis.com/youtube/v3/liveStreams"
        
        stream_data = {
            "snippet": {
                "title": title
            },
            "cdn": {
                "frameRate": "variable",
                "ingestionType": "rtmp",
                "resolution": "variable"
            }
        }
        
        params = {"part": "snippet,cdn"}
        response = self._make_api_request(url, method='POST', params=params, data=stream_data)
        
        if response:
            stream_id = response['id']
            stream_key = response['cdn']['ingestionInfo']['streamName']
            print(f"Created stream: {title} [ID: {stream_id}]")
            return stream_id, stream_key
        else:
            print(f"Failed to create stream: {title}")
            return None, None
    
    def bind_stream_to_broadcast(self, broadcast_id: str, stream_id: str) -> bool:
        """Bind a stream to a broadcast"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts/bind"
        params = {
            "part": "id,contentDetails",
            "id": broadcast_id,
            "streamId": stream_id
        }
        
        response = self._make_api_request(url, method='POST', params=params)
        if response:
            print(f"Successfully bound stream {stream_id} to broadcast {broadcast_id}")
            return True
        else:
            print(f"Failed to bind stream to broadcast")
            return False
    
    def wait_for_stream_active(self, stream_id: str, max_wait_seconds: int = 240) -> bool:
        """Wait for YouTube to detect the stream as active"""
        print(f"Waiting for stream {stream_id} to become active...")
        
        for attempt in range(max_wait_seconds // 10):
            url = "https://www.googleapis.com/youtube/v3/liveStreams"
            params = {
                "part": "status",
                "id": stream_id
            }
            
            response = self._make_api_request(url, params=params)
            if response and response.get('items'):
                stream_status = response['items'][0].get('status', {}).get('streamStatus')
                print(f"Stream status: {stream_status} (attempt {attempt + 1})")
                
                if stream_status == 'active':
                    print("Stream is now active!")
                    return True
            
            if attempt < (max_wait_seconds // 10) - 1:
                time.sleep(10)
        
        print(f"Stream did not become active within {max_wait_seconds} seconds")
        return False
    
    def transition_broadcast(self, broadcast_id: str, target_status: str) -> bool:
        """Transition broadcast to specified status"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts/transition"
        params = {
            "part": "status",
            "broadcastStatus": target_status,
            "id": broadcast_id
        }
        
        response = self._make_api_request(url, method='POST', params=params)
        if response:
            print(f"Successfully transitioned broadcast to {target_status}: {broadcast_id}")
            return True
        else:
            print(f"Failed to transition broadcast to {target_status}: {broadcast_id}")
            return False
    
    def start_broadcast(self, broadcast_id: str) -> bool:
        """Start a broadcast by transitioning to live status"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts/transition"
        params = {
            "part": "status",
            "broadcastStatus": "live",
            "id": broadcast_id
        }
        
        response = self._make_api_request(url, method='POST', params=params)
        if response:
            print(f"Successfully started broadcast: {broadcast_id}")
            return True
        else:
            print(f"Failed to start broadcast: {broadcast_id}")
            return False
    
    def get_broadcast_status(self, broadcast_id: str) -> Optional[str]:
        """Get current broadcast lifecycle status"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        params = {
            "part": "status",
            "id": broadcast_id
        }
        
        response = self._make_api_request(url, params=params)
        if response and response.get('items'):
            return response['items'][0]['status']['lifeCycleStatus']
        return None

# ============================================================================
# OBS WEBSOCKET CLIENT
# ============================================================================

class OBSWebSocket:
    """
    Handles OBS WebSocket 5.x communication
    
    Design considerations:
    - Stream stop operations use fire-and-forget to avoid waiting for responses
    - Connection drops during stop are expected and handled gracefully
    - Automatic reconnection when connection is lost
    """
    
    def __init__(self, host: str = 'localhost', port: int = None, password: str = ""):
        self.host = host
        self.port = int(port) if port is not None else None
        self.password = password
        self.socket = None
        self.authenticated = False
    
    def _is_connection_error(self, error: Exception) -> bool:
        """Check if an error indicates a broken connection"""
        if isinstance(error, (BrokenPipeError, ConnectionResetError)):
            return True
        if isinstance(error, OSError):
            # Check for specific errno values
            if hasattr(error, 'errno') and error.errno in (
                errno.EPIPE,      # Broken pipe
                errno.ECONNRESET, # Connection reset by peer
                errno.ENOTCONN,   # Socket is not connected
                errno.ESHUTDOWN   # Cannot send after transport endpoint shutdown
            ):
                return True
        return False
    
    def connect(self) -> bool:
        """Connect and authenticate to OBS WebSocket 5.x"""
        try:
            # Close existing connection if any
            if self.socket:
                try:
                    self.socket.close()
                except:
                    pass
            
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.host, self.port))
            
            # WebSocket handshake
            key = base64.b64encode(bytes([random.randint(0, 255) for _ in range(16)])).decode()
            handshake = (
                f"GET / HTTP/1.1\r\n"
                f"Host: {self.host}:{self.port}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"\r\n"
            )
            
            self.socket.send(handshake.encode())
            
            # Read handshake response
            handshake_response = b""
            while b"\r\n\r\n" not in handshake_response:
                chunk = self.socket.recv(1024)
                if not chunk:
                    break
                handshake_response += chunk
            
            try:
                response = handshake_response.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                response_lines = handshake_response.split(b'\r\n')
                response = response_lines[0].decode('utf-8', errors='ignore')
            
            if "101 Switching Protocols" not in response:
                raise Exception(f"WebSocket handshake failed: {response}")
            
            # Handle OBS WebSocket 5.x authentication
            hello_msg = self._receive_message()
            if hello_msg and hello_msg.get('op') == 0:  # Hello message
                auth_data = hello_msg.get('d', {}).get('authentication')
                
                if auth_data and self.password:
                    # Authenticate
                    challenge = auth_data.get('challenge', '')
                    salt = auth_data.get('salt', '')
                    
                    # Generate auth response
                    secret_hash = hashlib.sha256((self.password + salt).encode()).digest()
                    secret_string = base64.b64encode(secret_hash).decode()
                    auth_hash = hashlib.sha256((secret_string + challenge).encode()).digest()
                    auth_string = base64.b64encode(auth_hash).decode()
                    
                    identify_msg = {
                        "op": 1,  # Identify
                        "d": {
                            "rpcVersion": 1,
                            "authentication": auth_string
                        }
                    }
                else:
                    # No authentication required
                    identify_msg = {
                        "op": 1,  # Identify
                        "d": {
                            "rpcVersion": 1
                        }
                    }
                
                self._send_message(identify_msg)
                
                # Wait for Identified message
                identified_msg = self._receive_message()
                if identified_msg and identified_msg.get('op') == 2:  # Identified
                    self.authenticated = True
                    print("Connected to OBS WebSocket successfully")
                    return True
            
            return False
            
        except Exception as e:
            print(f"Error connecting to OBS: {e}")
            return False
    
    def _send_message(self, message_data: dict):
        """Send WebSocket message with proper framing"""
        message = json.dumps(message_data)
        message_bytes = message.encode('utf-8')
        
        frame = bytearray()
        frame.append(0x81)  # Text frame, final
        
        msg_len = len(message_bytes)
        if msg_len < 126:
            frame.append(msg_len | 0x80)  # Set mask bit
        elif msg_len < 65516:
            frame.append(126 | 0x80)
            frame.extend(struct.pack('>H', msg_len))
        else:
            frame.append(127 | 0x80)
            frame.extend(struct.pack('>Q', msg_len))
        
        # Add masking key
        mask_key = bytes([random.randint(0, 255) for _ in range(4)])
        frame.extend(mask_key)
        
        # Mask payload
        for i, byte in enumerate(message_bytes):
            frame.append(byte ^ mask_key[i % 4])
        
        self.socket.send(bytes(frame))
    
    def _receive_message(self) -> Optional[dict]:
        """Receive and parse WebSocket message"""
        try:
            self.socket.settimeout(5)
            response_data = self.socket.recv(4096)
            
            if len(response_data) < 2:
                return None
            
            # Parse WebSocket frame header
            first_byte = response_data[0]
            second_byte = response_data[1]
            
            # Extract payload length
            payload_len = second_byte & 0x7F
            mask_bit = (second_byte & 0x80) != 0
            
            header_length = 2
            
            if payload_len == 126:
                if len(response_data) < 4:
                    return None
                payload_len = struct.unpack('>H', response_data[2:4])[0]
                header_length = 4
            elif payload_len == 127:
                if len(response_data) < 10:
                    return None
                payload_len = struct.unpack('>Q', response_data[2:10])[0]
                header_length = 10
            
            # Handle masking
            if mask_bit:
                if len(response_data) < header_length + 4:
                    return None
                mask_key = response_data[header_length:header_length + 4]
                payload_start = header_length + 4
            else:
                payload_start = header_length
            
            # Extract payload
            if len(response_data) < payload_start + payload_len:
                remaining_bytes = payload_start + payload_len - len(response_data)
                try:
                    additional_data = self.socket.recv(remaining_bytes)
                    response_data += additional_data
                except socket.timeout:
                    return None
            
            payload_data = response_data[payload_start:payload_start + payload_len]
            
            # Unmask payload if masked
            if mask_bit:
                unmasked_payload = bytearray()
                for i in range(len(payload_data)):
                    unmasked_payload.append(payload_data[i] ^ mask_key[i % 4])
                payload_data = bytes(unmasked_payload)
            
            # Decode and parse JSON
            payload_str = payload_data.decode('utf-8')
            return json.loads(payload_str)
            
        except (socket.timeout, json.JSONDecodeError, UnicodeDecodeError):
            return None
        except Exception as e:
            if self._is_connection_error(e):
                self.authenticated = False
            return None
    
    def send_request(self, request_type: str, request_data: dict = None, 
                    expect_response: bool = True, max_retries: int = 3) -> bool:
        """
        Send request to OBS WebSocket
        
        Args:
            request_type: OBS request type (e.g., "StartStream")
            request_data: Optional request parameters
            expect_response: If False, send command without waiting for response
            max_retries: Number of retry attempts on failure
        """
        if not self.authenticated:
            print(f"Not authenticated to OBS WebSocket")
            return False
        
        for attempt in range(1, max_retries + 1):
            try:
                request_id = str(int(time.time() * 1000))
                message = {
                    "op": 6,  # Request
                    "d": {
                        "requestType": request_type,
                        "requestId": request_id
                    }
                }
                
                if request_data:
                    message["d"]["requestData"] = request_data
                
                self._send_message(message)
                
                # For commands that don't need responses, return immediately
                if not expect_response:
                    print(f"OBS command sent (no response expected): {request_type}")
                    time.sleep(0.2)  # Brief pause to let OBS process
                    return True
                
                # Wait for response
                start_time = time.time()
                timeout = 10
                
                while time.time() - start_time < timeout:
                    response = self._receive_message()
                    
                    if not response:
                        time.sleep(0.1)
                        continue
                    
                    if response.get('op') == 7:  # RequestResponse
                        request_status = response.get('d', {}).get('requestStatus', {})
                        
                        if request_status.get('result'):
                            if attempt > 1:
                                print(f"OBS command successful on attempt {attempt}: {request_type}")
                            else:
                                print(f"OBS command successful: {request_type}")
                            return True
                        else:
                            error_code = request_status.get('code', 'UNKNOWN')
                            error_comment = request_status.get('comment', 'No error message')
                            print(f"OBS command failed: {request_type}")
                            print(f"  Error: {error_comment} (code: {error_code})")
                            
                            # Don't retry on certain error codes
                            if error_code in [600, 601, 602]:
                                return False
                            break
                    elif response.get('op') == 5:  # Event - ignore
                        continue
                
                # Timeout or error occurred
                if not self.authenticated:
                    print(f"Connection lost during {request_type}")
                    if attempt < max_retries:
                        print("Attempting to reconnect...")
                        if self.connect():
                            print("Reconnected, retrying request...")
                        else:
                            print("Reconnection failed")
                else:
                    print(f"No response for: {request_type} (attempt {attempt}/{max_retries})")
                
            except Exception as e:
                if self._is_connection_error(e):
                    print(f"Connection error during {request_type}: {e}")
                    self.authenticated = False
                    if attempt < max_retries:
                        print("Attempting to reconnect...")
                        if self.connect():
                            print("Reconnected, retrying request...")
                        else:
                            print("Reconnection failed")
                else:
                    print(f"Error during {request_type}: {e}")
            
            if attempt < max_retries:
                time.sleep(2)
        
        print(f"All {max_retries} attempts failed for: {request_type}")
        return False
    
    def stop_streaming(self) -> bool:
        """
        Stop OBS streaming using fire-and-forget approach
        
        OBS often closes the connection during stop operations, so we send
        the command without waiting for a response.
        """
        try:
            request_id = str(int(time.time() * 1000))
            message = {
                "op": 6,
                "d": {
                    "requestType": "StopStream",
                    "requestId": request_id
                }
            }
            
            # Send the message
            self._send_message(message)
            print("OBS command sent: StopStream")
            
            # Allow time for OBS to process
            time.sleep(0.5)
            
            # Connection may be closed by OBS during this operation
            return True
            
        except Exception as e:
            if self._is_connection_error(e):
                print("Connection closed during StopStream")
                self.authenticated = False
                return True  # Still consider this successful
            else:
                print(f"Error during StopStream: {e}")
                return False
    
    def start_streaming(self) -> bool:
        """Start OBS streaming"""
        return self.send_request("StartStream", expect_response=True)
    
    def set_stream_settings(self, stream_key: str, 
                           server_url: str = "rtmp://a.rtmp.youtube.com/live2") -> bool:
        """Update OBS stream settings"""
        stream_settings = {
            "streamServiceType": "rtmp_custom",
            "streamServiceSettings": {
                "server": server_url,
                "key": stream_key
            }
        }
        return self.send_request("SetStreamServiceSettings", stream_settings)
    
    def get_stream_status(self) -> bool:
        """
        Get OBS streaming status
        
        Returns True if currently streaming, False otherwise.
        """
        if not self.authenticated:
            return False
        
        try:
            request_id = str(int(time.time() * 1000))
            message = {
                "op": 6,
                "d": {
                    "requestType": "GetStreamStatus",
                    "requestId": request_id
                }
            }
            
            self._send_message(message)
            
            # Wait for response
            for _ in range(10):  # Try for ~5 seconds
                response = self._receive_message()
                
                if not response:
                    time.sleep(0.5)
                    continue
                
                if response.get('op') == 7:  # RequestResponse
                    response_data = response.get('d', {}).get('responseData', {})
                    return response_data.get('outputActive', False)
                elif response.get('op') == 5:  # Event - ignore
                    continue
            
            return False
            
        except Exception as e:
            if self._is_connection_error(e):
                self.authenticated = False
            return False
    
    def close(self):
        """Close connection"""
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            finally:
                self.socket = None
                self.authenticated = False

# ============================================================================
# STREAM SCHEDULER
# ============================================================================

class StreamScheduler:
    """
    Main scheduler that coordinates OBS and YouTube operations
    
    Handles scheduled stream start/stop events, manages broadcast lifecycle,
    and maintains persistent connections with automatic recovery.
    """
    
    def __init__(self):
        # Load credentials
        self.passwords = PasswordManager(PASSWORDS_FILE)
        
        # Validate credentials
        refresh_token = self.passwords.get('YOUTUBE_REFRESH_TOKEN')
        if not refresh_token:
            raise ValueError("YOUTUBE_REFRESH_TOKEN not found in passwords.txt")
        
        obs_port = self.passwords.get('OBS_WEBSOCKET_PORT')
        if not obs_port:
            raise ValueError("OBS_WEBSOCKET_PORT not found in passwords.txt")
        
        # Initialize APIs
        self.category_id = YOUTUBE_CATEGORY_ID
        self.youtube = YouTubeAPI(CLIENT_SECRETS_FILE, refresh_token)
        self.obs = OBSWebSocket(
            password=self.passwords.get('OBS_WEBSOCKET_PASSWORD'),
            port=int(obs_port)
        )
        
        # Convert schedule to events
        self.events = self._create_events_from_schedule()
        
        # State
        self.current_broadcast_id = None
        self.current_stream_id = None
        self.next_broadcast_id = None
        self.next_stream_id = None
        self.next_stream_key = None
    
    def _create_events_from_schedule(self) -> List[ScheduledEvent]:
        """Convert schedule sets into list of events"""
        events = []
        
        for stop_time_str, start_time_str in SCHEDULE_SETS:
            stop_hour, stop_minute = parse_time_string(stop_time_str)
            start_hour, start_minute = parse_time_string(start_time_str)
            
            stop_time = dt_time(stop_hour, stop_minute, 0)
            start_time = dt_time(start_hour, start_minute, 0)
            
            # STOP event happens a few seconds before START
            actual_stop_time = dt_time(stop_hour, stop_minute, 60 - START_EARLY_SECONDS)
            
            events.append(ScheduledEvent("STOP", actual_stop_time, start_time))
            events.append(ScheduledEvent("START", start_time, start_time))
        
        return events
    
    def get_next_event(self, from_datetime: datetime) -> Tuple[Optional[ScheduledEvent], Optional[datetime]]:
        """Get the next event after specified datetime"""
        next_events = []
        
        for event in self.events:
            next_occurrence = event.get_next_occurrence(from_datetime)
            next_events.append((event, next_occurrence))
        
        if not next_events:
            return None, None
        
        next_events.sort(key=lambda x: x[1])
        return next_events[0]
    
    def ensure_obs_connection(self) -> bool:
        """Ensure OBS connection is active, reconnect if needed"""
        if not self.obs.authenticated:
            print("OBS not connected, attempting to connect...")
            max_attempts = 3
            for attempt in range(1, max_attempts + 1):
                if self.obs.connect():
                    print("Successfully connected to OBS")
                    return True
                else:
                    if attempt < max_attempts:
                        print(f"Connection attempt {attempt} failed, retrying in 3 seconds...")
                        time.sleep(3)
            
            print("Failed to connect to OBS after all attempts")
            return False
        return True
    
    def initialize(self) -> bool:
        """Initialize connections and find current stream"""
        print("Initializing stream scheduler...")
        
        # Connect to OBS
        if not self.obs.connect():
            print("Failed to connect to OBS WebSocket")
            return False
        
        # Find current stream
        test_stream = self.youtube.find_test_stream()
        if test_stream:
            self.current_broadcast_id = test_stream['id']
            print(f"Managing broadcast: {self.current_broadcast_id}")
        else:
            print("No existing stream to manage...")
        
        return True
    
    def wait_for_obs_stop(self):
        """
        Wait for OBS to fully stop streaming
        
        Polls stream status with automatic reconnection since OBS may have
        closed the connection during the stop operation.
        """
        max_wait_time = 30
        wait_interval = 2
        
        print("Verifying OBS has stopped...")
        
        for i in range(max_wait_time // wait_interval):
            # Ensure we're connected before checking
            if not self.ensure_obs_connection():
                print("Cannot verify OBS status - assuming stopped")
                return
            
            try:
                if self.obs.get_stream_status():
                    print(f"OBS still streaming, waiting... ({i+1})")
                    time.sleep(wait_interval)
                else:
                    print("OBS has stopped streaming")
                    return
            except Exception as e:
                print(f"Error checking OBS status: {e}")
                # Can't check, assume stopped
                return
        
        print("Wait timeout - proceeding anyway")
    
    def stop_current_stream(self):
        """
        Stop current stream and prepare for next
        
        Process:
        1. Send stop command to OBS (fire-and-forget)
        2. End YouTube broadcast
        3. Verify OBS has stopped (with reconnection if needed)
        """
        print("Stopping current stream...")
        
        # Step 1: Send stop command to OBS
        self.obs.stop_streaming()
        
        # Step 2: End YouTube broadcast
        if self.current_broadcast_id:
            success = self.youtube.end_broadcast(self.current_broadcast_id)
            if success:
                self.current_broadcast_id = None
            else:
                print("Failed to end YouTube broadcast")
        
        print("Stream stop sequence completed")
        
        # Step 3: Verify OBS has stopped
        self.wait_for_obs_stop()
        print("Ready for next stream")
    
    def start_obs_with_key(self, stream_key: str) -> bool:
        """Configure OBS with stream key and start streaming"""
        print(f"Configuring OBS with stream key...")
        
        # Ensure connection
        if not self.ensure_obs_connection():
            print("Failed to ensure OBS connection")
            return False
        
        if not self.obs.set_stream_settings(stream_key):
            print("Failed to configure OBS with stream key")
            return False
        
        print("Starting OBS streaming...")
        if not self.obs.start_streaming():
            print("Failed to start OBS streaming")
            return False
        
        print("OBS streaming started successfully!")
        return True
    
    def create_next_stream(self, target_start_time: dt_time) -> bool:
        """Create the next scheduled stream"""
        now = datetime.now(timezone.utc)
        
        # Calculate next occurrence
        next_start = datetime.combine(now.date(), target_start_time, timezone.utc)
        if next_start <= now:
            next_start += timedelta(days=1)
        
        # Generate title
        date_str = next_start.strftime('%y%m%d')
        if next_start.hour == 0 and next_start.minute == 0:
            title = f"{LIVESTREAM_NAME} {date_str}A"
        elif next_start.hour == 12 and next_start.minute == 0:
            title = f"{LIVESTREAM_NAME} {date_str}B"
        else:
            time_str = f"{next_start.hour:02d}:{next_start.minute:02d}"
            title = f"{LIVESTREAM_NAME} {date_str} {time_str}"
        
        print(f"Creating next stream: {title}")
        self.next_broadcast_id = self.youtube.create_broadcast(title, next_start, self.category_id)
        
        if self.next_broadcast_id:
            # Store stream ID and key
            self.next_stream_id = getattr(self.youtube, 'current_stream_id', None)
            self.next_stream_key = getattr(self.youtube, 'current_stream_key', None)
            
            # Configure and start OBS with new key
            if self.next_stream_key:
                if not self.start_obs_with_key(self.next_stream_key):
                    print("Failed to start OBS with new stream key")
                    return False
            
            print(f"Next stream scheduled for: {next_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            return True
        else:
            print("Failed to create next stream")
            return False
    
    def start_next_stream(self) -> bool:
        """Start the next YouTube broadcast with retry logic"""
        if not self.next_broadcast_id:
            print("No next broadcast to start")
            return False
        
        # OBS is already streaming with the correct key
        # Wait for YouTube to detect the stream as active
        if self.next_stream_id and self.youtube.wait_for_stream_active(self.next_stream_id):
            # Transition to testing if needed
            if self.youtube.get_broadcast_status(self.next_broadcast_id) == 'ready':
                print("Transitioning to 'testing' status...")
                if self.youtube.transition_broadcast(self.next_broadcast_id, 'testing'):
                    print("Successfully transitioned to testing")
                    time.sleep(10)
                else:
                    print("Failed to transition to testing")
                    return False
            
            # Retry logic for testing to live transition
            max_attempts = 30
            for attempt in range(1, max_attempts + 1):
                print(f"Attempting to go live (attempt {attempt}/{max_attempts})")
                success = self.youtube.start_broadcast(self.next_broadcast_id)
                
                if success:
                    self.current_broadcast_id = self.next_broadcast_id
                    self.current_stream_id = self.next_stream_id
                    self.next_broadcast_id = None
                    self.next_stream_id = None
                    print("Stream is now live!")
                    return True
                else:
                    print(f"Transition attempt {attempt} failed")
                    if attempt < max_attempts:
                        print("Waiting 10 seconds before retry...")
                        time.sleep(10)
            
            # All attempts failed
            print("CRITICAL ERROR - unable to transition to live")
            exit(1)
        
        print("Failed to start broadcast - stream not active")
        return False
    
    def run_schedule(self):
        """Main scheduling loop with event-based timing"""
        print(f"Stream scheduler running with {len(SCHEDULE_SETS)} daily schedule sets:")
        for i, (stop_time_str, start_time_str) in enumerate(SCHEDULE_SETS):
            print(f"  SET {i+1}: {stop_time_str} -> {start_time_str} UTC")
        print(f"Schedule tolerance: {SCHEDULE_TOLERANCE_SECONDS} seconds")
        print(f"Early start window: {START_EARLY_SECONDS} seconds")
        print()
        
        while True:
            try:
                now = datetime.now(timezone.utc)
                
                # Get next event
                next_event, event_time = self.get_next_event(now)
                
                if next_event and event_time:
                    time_until_event = (event_time - now).total_seconds()
                    
                    # Low-activity mode for long waits
                    if time_until_event > 3 * 60 * 60:  # More than 3 hours
                        print(f"\rNext event in {time_until_event/3600:.1f} hours - entering low-activity mode    ", end='', flush=True)
                        time.sleep(30 * 60)  # 30 minutes
                        continue
                    
                    # Execute if it's time
                    if time_until_event <= SCHEDULE_TOLERANCE_SECONDS:
                        if next_event.event_type == "STOP":
                            print(f"\nExecuting STOP event")
                            self.stop_current_stream()
                            self.create_next_stream(next_event.original_start_time)
                            time.sleep(15)  # Prevent duplicate execution
                        elif next_event.event_type == "START":
                            print()
                            print(f"\nExecuting START event")
                            if self.next_broadcast_id:
                                self.start_next_stream()
                            time.sleep(15)  # Prevent duplicate execution
                    
                    # Adaptive sleep timing
                    elif time_until_event <= 30:
                        time.sleep(0)  # High precision
                    elif time_until_event <= 300:  # 5 minutes
                        time.sleep(10)  # Medium precision
                    else:
                        time.sleep(30)  # Low precision
                else:
                    print("No scheduled events found")
                    time.sleep(60)
                    
            except Exception as e:
                print(f"Exception in main loop: {e}")
                print("Continuing...")
                time.sleep(5)

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

def main():
    print("=" * 70)
    print("24/7 Automated Livestream Relay System")
    print("Python3 + OBS WebSocket 5.1 + YouTube API v3")
    print("=" * 70)
    print()
    
    scheduler = None
    try:
        scheduler = StreamScheduler()
        
        if not scheduler.initialize():
            print("Failed to initialize scheduler")
            return
        
        scheduler.run_schedule()
        
    except KeyboardInterrupt:
        print("\nShutting down...")
    except Exception as e:
        print(f"Fatal error: {e}")
        raise
    finally:
        # Cleanup
        if scheduler and scheduler.obs:
            try:
                scheduler.obs.close()
            except:
                pass

if __name__ == "__main__":
    main()
