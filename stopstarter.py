#!/usr/bin/env python3
"""
YouTube Stream Scheduler with OBS WebSocket Integration
Automatically manages YouTube live stream lifecycle with proper API calls
"""
import json
import time
import socket
import struct
import hashlib
import base64
import requests
from datetime import datetime, timedelta, timezone, time as dt_time
from dataclasses import dataclass
from typing import List, Optional, Tuple
import os

# USER CONFIGURATION
# Stream identifier for matching broadcasts
LIVESTREAM_NAME = "LIVESTREAM"

# Format: ("STOP_TIME", "START_TIME") using 24-hour format with leading zeros
SCHEDULE_SETS = [
    ("11:56", "12:00"),
    ("23:56", "00:00"),
]

# Schedule timing tolerance in seconds
SCHEDULE_TOLERANCE_SECONDS = 10

# How many seconds before the scheduled start time to begin attempting to go live
START_EARLY_SECONDS = 2

# YouTube video category ID
# Refer to https://developers.google.com/youtube/v3/docs/videoCategories/list
YOUTUBE_CATEGORY_ID = "28"

@dataclass
class ScheduledEvent:
    event_type: str  # "STOP" or "START"
    time: dt_time
    original_start_time: dt_time  # For START events, this is the actual broadcast time
    
    def get_next_occurrence(self, from_datetime: datetime) -> datetime:
        """Get the next occurrence of this event after the given datetime"""
        # Create a datetime for today with this event's time
        today_event = datetime.combine(from_datetime.date(), self.time, timezone.utc)
        
        if today_event > from_datetime:
            return today_event
        else:
            # Event already passed today, return tomorrow's occurrence
            return today_event + timedelta(days=1)

def parse_time_string(time_str):
    """Convert time string like '11:55' to (hour, minute) tuple"""
    hour_str, minute_str = time_str.split(':')
    return (int(hour_str), int(minute_str))

# File paths
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
CLIENT_SECRETS_FILE = os.path.join(SCRIPT_DIR, "passwords/client_secrets.json")
PASSWORDS_FILE = os.path.join(SCRIPT_DIR, "passwords/passwords.txt")
THUMBNAILS_DIR = os.path.join(SCRIPT_DIR, "thumbnails")
DESCRIPTION_FILE = os.path.join(SCRIPT_DIR, "script_files/stopstarter_description.txt")

class PasswordManager:
    def __init__(self, passwords_file):
        self.passwords = {}
        self._load_passwords(passwords_file)
    
    def _load_passwords(self, file_path):
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
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
    
    def get(self, key):
        return self.passwords.get(key)

class YouTubeAPI:
    def __init__(self, client_secrets_file, refresh_token):
        if not refresh_token:
            raise ValueError("YouTube refresh token cannot be None or empty")
            
        self.client_secrets_file = client_secrets_file
        self.refresh_token = refresh_token
        self.access_token = None
        self._load_client_secrets()
    
    def _load_client_secrets(self):
        with open(self.client_secrets_file, 'r') as f:
            secrets = json.load(f)
            client_info = secrets.get('installed', secrets.get('web', {}))
            self.client_id = client_info['client_id']
            self.client_secret = client_info['client_secret']
    
    def refresh_access_token(self):
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
    
    def _make_api_request(self, url, method='GET', params=None, data=None):
        """Make authenticated API request with proper error handling"""
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
    
    def list_live_broadcasts(self):
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
    
    def find_test_stream(self):
        """Find and return the broadcast with '{LIVESTREAM_NAME}' in title"""
        broadcasts = self.list_live_broadcasts()
        
        for broadcast in broadcasts:
            title = broadcast['snippet']['title']
            status = broadcast['status']['lifeCycleStatus']
            
            if LIVESTREAM_NAME.upper() in title.upper() and status == 'live':
                print(f"Found active livestream: {title} [ID: {broadcast['id']}]")
                return broadcast
        
        print("NO ACTIVE STREAM FOUND; BUT STREAM WILL CONTINUE ANYWAYS")
        return None
    
    def end_broadcast(self, broadcast_id):
        """End a live broadcast by transitioning to complete status"""
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
    
    def get_thumbnail(self):
        """Get thumbnail.jpg from the thumbnails directory"""
        thumbnail_path = os.path.join(THUMBNAILS_DIR, "thumbnail.jpg")
        
        if os.path.exists(thumbnail_path):
            return thumbnail_path
        else:
            print(f"thumbnail.jpg not found in {THUMBNAILS_DIR}")
            return None
    
    def upload_thumbnail(self, broadcast_id, thumbnail_path):
        """Upload a thumbnail for the broadcast"""
        if not os.path.exists(thumbnail_path):
            print(f"Thumbnail file not found: {thumbnail_path}")
            return False
        
        try:
            # YouTube API v3 thumbnails endpoint
            url = f"https://www.googleapis.com/upload/youtube/v3/thumbnails/set"
            params = {"videoId": broadcast_id}
            
            headers = {
                'Authorization': f'Bearer {self.access_token}'
            }
            
            with open(thumbnail_path, 'rb') as thumbnail_file:
                files = {'file': (os.path.basename(thumbnail_path), thumbnail_file, 'image/jpeg')}
                
                response = requests.post(url, headers=headers, params=params, files=files)
                
                if response.status_code == 200:
                    print(f"Successfully uploaded thumbnail: {os.path.basename(thumbnail_path)}")
                    return True
                else:
                    print(f"Failed to upload thumbnail: HTTP {response.status_code}")
                    print(f"Response: {response.text}")
                    return False
                    
        except Exception as e:
            print(f"Error uploading thumbnail: {e}")
            return False
    
    def set_broadcast_category(self, broadcast_id, category_id):
        """Set the category of a broadcast using the videos.update API"""
        try:
            url = "https://www.googleapis.com/youtube/v3/videos"
            params = {"part": "snippet"}
            
            # First, get the current video snippet
            get_params = {"part": "snippet", "id": broadcast_id}
            current_video = self._make_api_request(url, params=get_params)
            
            if not current_video or not current_video.get('items'):
                print(f"Failed to retrieve current video data for {broadcast_id} - video may not be ready yet")
                return False
            
            # Update the snippet with the new category
            video_snippet = current_video['items'][0]['snippet']
            video_snippet['categoryId'] = category_id
            
            update_data = {
                "id": broadcast_id,
                "snippet": video_snippet
            }
            
            response = self._make_api_request(url, method='PUT', params=params, data=update_data)
            if response:
                print(f"Successfully updated category for broadcast {broadcast_id}")
                return True
            else:
                print(f"Failed to update category for broadcast {broadcast_id}")
                return False
                
        except Exception as e:
            print(f"Exception while setting category for {broadcast_id}: {e}")
            return False
    
    def create_broadcast(self, title, scheduled_start_time, category_id="28"):
        """Create a new broadcast scheduled for future start with thumbnail and category"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        params = {"part": "snippet,status,contentDetails"}
        
        # Load description from file
        description = "This livestream was created using stopstarter.py.\n\n[This is a fallback description.]"  # fallback
        try:
            with open(DESCRIPTION_FILE, 'r', encoding='utf-8') as f:
                description = f.read().strip()
        except FileNotFoundError:
            print(f"Warning: {DESCRIPTION_FILE} not found, using default description")
        except Exception as e:
            print(f"Warning: Error reading description file: {e}, using default description")
        
        broadcast_data = {
            "snippet": {
                "title": title,
                "description": description,
                "scheduledStartTime": scheduled_start_time.strftime('%Y-%m-%dT%H:%M:%S.000Z')
                # NOTE: categoryId is NOT supported in liveBroadcasts.insert
            },
            "status": {
                "privacyStatus": "public"
            },
            "contentDetails": {
                "latencyPreference": "low",
                "monitorStream": {
                "enableMonitorStream": True
            },
            }
        }
        
        response = self._make_api_request(url, method='POST', params=params, data=broadcast_data)
        if response:
            broadcast_id = response['id']
            print(f"Created new broadcast: {title} [ID: {broadcast_id}]")
            
            # Upload random thumbnail
            thumbnail_path = self.get_thumbnail()
            if thumbnail_path:
                self.upload_thumbnail(broadcast_id, thumbnail_path)
            else:
                print("No thumbnail uploaded - continuing without thumbnail")
            
            # Set category using videos.update API
            if self.set_broadcast_category(broadcast_id, category_id):
                print(f"Successfully set category to {category_id}")
            else:
                print(f"Warning: Failed to set category to {category_id}")
            
            # Create associated stream for status checking
            stream_id, stream_key = self.create_stream(f"Stream for {title}")
            if stream_id:
                # Bind stream to broadcast
                self.bind_stream_to_broadcast(broadcast_id, stream_id)
                # Store stream ID and key for this broadcast
                self.current_stream_id = stream_id
                self.current_stream_key = stream_key
            
            return broadcast_id
        else:
            print(f"Failed to create broadcast: {title}")
            return None
    
    def create_stream(self, title):
        """Create a new live stream"""
        url = "https://www.googleapis.com/youtube/v3/liveStreams"
        params = {"part": "snippet,cdn"}
        
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
        
        response = self._make_api_request(url, method='POST', params=params, data=stream_data)
        if response:
            stream_id = response['id']
            stream_key = response['cdn']['ingestionInfo']['streamName']
            print(f"Created stream: {title} [ID: {stream_id}]")
            return stream_id, stream_key
        else:
            print(f"Failed to create stream: {title}")
            return None, None
    
    def bind_stream_to_broadcast(self, broadcast_id, stream_id):
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
    
    def wait_for_stream_active(self, stream_id, max_wait_seconds=240):
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
    
    def transition_broadcast(self, broadcast_id, target_status):
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
    
    def start_broadcast(self, broadcast_id):
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

class OBSWebSocket:
    def __init__(self, host='localhost', port=None, password=""):
        self.host = host
        self.port = int(port) if port is not None else None
        self.password = password
        self.socket = None
        self.authenticated = False
    
    def connect(self):
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
            
            # Read handshake response more carefully
            handshake_response = b""
            while b"\r\n\r\n" not in handshake_response:
                chunk = self.socket.recv(1024)
                if not chunk:
                    break
                handshake_response += chunk
            
            # Only decode the HTTP headers portion as UTF-8
            try:
                response = handshake_response.decode('utf-8', errors='ignore')
            except UnicodeDecodeError:
                # If there's still an issue, extract just the status line
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
    
    def _send_message(self, message_data):
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
    
    def _receive_message(self):
        """Receive and parse WebSocket message with proper frame parsing"""
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
            
            # Handle masking (shouldn't be present in server-to-client frames, but check anyway)
            if mask_bit:
                if len(response_data) < header_length + 4:
                    return None
                mask_key = response_data[header_length:header_length + 4]
                payload_start = header_length + 4
            else:
                payload_start = header_length
            
            # Extract payload
            if len(response_data) < payload_start + payload_len:
                # Need more data, try to receive more
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
            
            # Decode payload as UTF-8 and parse JSON
            payload_str = payload_data.decode('utf-8')
            return json.loads(payload_str)
            
        except (socket.timeout, json.JSONDecodeError, UnicodeDecodeError):
            # Silently return None for common parsing issues to avoid spam
            return None
        except Exception as e:
            print(f"Unexpected error receiving message: {e}")
            return None
    
    def send_request(self, request_type, request_data=None, max_retries=3, retry_delay=2):
        """Send request to OBS using WebSocket 5.x format with retry logic"""
        if not self.authenticated:
            print("Not authenticated to OBS WebSocket")
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
                
                # Wait for response with timeout
                start_time = time.time()
                timeout = 10  # 10 second timeout per attempt
                
                while time.time() - start_time < timeout:
                    response = self._receive_message()
                    
                    if not response:
                        time.sleep(0.1)  # Brief pause before checking again
                        continue
                    
                    if response.get('op') == 7:  # RequestResponse
                        request_status = response.get('d', {}).get('requestStatus', {})
                        response_data = response.get('d', {}).get('responseData', {})
                        
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
                            print(f"  Error code: {error_code}")
                            print(f"  Error message: {error_comment}")
                            if response_data:
                                print(f"  Response data: {response_data}")
                            
                            # Don't retry on certain error codes
                            if error_code in [600, 601, 602]:  # Request errors that won't be fixed by retry
                                print(f"  Non-retryable error, aborting")
                                return False
                            
                            # Otherwise, will retry if attempts remain
                            break
                    elif response.get('op') == 5:  # Event - ignore and continue waiting
                        continue
                
                # If we get here, timeout occurred
                print(f"No response received for: {request_type} (attempt {attempt}/{max_retries})")
                
            except Exception as e:
                print(f"Exception during OBS request {request_type} (attempt {attempt}/{max_retries}): {e}")
            
            # Retry logic
            if attempt < max_retries:
                print(f"Retrying in {retry_delay} seconds...")
                time.sleep(retry_delay)
            else:
                print(f"All {max_retries} attempts failed for: {request_type}")
                return False
        
        return False
    
    def stop_streaming(self):
        """Stop OBS streaming"""
        return self.send_request("StopStream")
    
    def start_streaming(self):
        """Start OBS streaming"""
        return self.send_request("StartStream")
    
    def set_stream_settings(self, stream_key, server_url="rtmp://a.rtmp.youtube.com/live2"):
        """Update OBS stream settings"""
        stream_settings = {
            "streamServiceType": "rtmp_custom",
            "streamServiceSettings": {
                "server": server_url,
                "key": stream_key
            }
        }
        return self.send_request("SetStreamServiceSettings", stream_settings)
    
    def get_stream_status(self):
        """Get OBS streaming status"""
        request_id = str(int(time.time() * 1000))
        message = {
            "op": 6,  # Request
            "d": {
                "requestType": "GetStreamStatus",
                "requestId": request_id
            }
        }
        
        self._send_message(message)
        
        # Keep receiving messages until we get the response
        max_attempts = 5
        for attempt in range(max_attempts):
            response = self._receive_message()
            
            if not response:
                continue
                
            if response.get('op') == 7:  # RequestResponse
                response_data = response.get('d', {}).get('responseData', {})
                return response_data.get('outputActive', False)
            elif response.get('op') == 5:  # Event - ignore and continue waiting
                continue
        
        return False  # Assume not streaming if we can't get status
    
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

class StreamScheduler:
    def __init__(self):
        # Load credentials
        self.passwords = PasswordManager(PASSWORDS_FILE)
        
        # Validate required credentials
        refresh_token = self.passwords.get('YOUTUBE_REFRESH_TOKEN')
        if not refresh_token:
            raise ValueError("YOUTUBE_REFRESH_TOKEN not found in passwords.txt")
        
        obs_port = self.passwords.get('OBS_WEBSOCKET_PORT')
        if not obs_port:
            raise ValueError("OBS_WEBSOCKET_PORT not found in passwords.txt")
        
        # Get category ID from configuration
        self.category_id = YOUTUBE_CATEGORY_ID
        
        # Initialize APIs
        self.youtube = YouTubeAPI(CLIENT_SECRETS_FILE, refresh_token)
        
        self.obs = OBSWebSocket(
            password=self.passwords.get('OBS_WEBSOCKET_PASSWORD'),
            port=int(obs_port)
        )
        
        # Convert schedule sets to events
        self.events = self._create_events_from_schedule()
        
        # State
        self.current_broadcast_id = None
        self.next_broadcast_id = None
        self.current_stream_id = None
        self.next_stream_id = None
        self.current_stream_key = None
        self.next_stream_key = None
    
    def _create_events_from_schedule(self) -> List[ScheduledEvent]:
        """Convert SCHEDULE_SETS to ScheduledEvent objects"""
        events = []
        
        for stop_time_str, start_time_str in SCHEDULE_SETS:
            # Parse times
            stop_hour, stop_minute = parse_time_string(stop_time_str)
            start_hour, start_minute = parse_time_string(start_time_str)
            
            stop_time = dt_time(stop_hour, stop_minute, 0)
            start_time = dt_time(start_hour, start_minute, 0)
            # Create stop event
            events.append(ScheduledEvent("STOP", stop_time, start_time))
            
            # Create start event (early start time)
            start_datetime = datetime.combine(datetime.today(), start_time)
            early_start_datetime = start_datetime - timedelta(seconds=START_EARLY_SECONDS)
            early_start_time = early_start_datetime.time()
            
            events.append(ScheduledEvent("START", early_start_time, start_time))
        
        return events
    
    def get_next_event(self, from_datetime: datetime) -> Tuple[Optional[ScheduledEvent], Optional[datetime]]:
        """Get the next event and when it occurs"""
        upcoming_events = []
        
        for event in self.events:
            next_occurrence = event.get_next_occurrence(from_datetime)
            upcoming_events.append((event, next_occurrence))
        
        # Sort by occurrence time
        upcoming_events.sort(key=lambda x: x[1])
        
        if upcoming_events:
            return upcoming_events[0]
        return None, None
    
    def initialize(self):
        """Find current LIVESTREAM_NAME and prepare for management"""
        print("Initializing stream scheduler...")
        
        # Connect to OBS
        if not self.obs.connect():
            print("Failed to connect to OBS WebSocket")
            return False
        
        # Find current LIVESTREAM_NAME
        test_stream = self.youtube.find_test_stream()
        if test_stream:
            self.current_broadcast_id = test_stream['id']
            print(f"Managing broadcast: {self.current_broadcast_id}")
        else:
            print("No existing stream to manage...")
        
        return True
    
    def _wait_for_obs_stop(self):
        """Wait for OBS to fully stop streaming before proceeding"""
        max_wait_time = 30  # Maximum 30 seconds
        wait_interval = 2   # Check every 2 seconds
        
        for i in range(max_wait_time // wait_interval):
            if self.obs.get_stream_status():
                print(f"OBS still streaming, waiting... ({i+1})")
                time.sleep(wait_interval)
            else:
                print("OBS has stopped streaming")
                return
        
        print("Timeout waiting for OBS to stop streaming, proceeding anyway...")
    
    def stop_current_stream(self):
        """Stop current stream and prepare for next"""
        print("Stopping current stream...")
        
        # Step 1: Stop OBS streaming first
        success = self.obs.stop_streaming()
        if not success:
            print("Failed to stop OBS streaming")
        
        # Step 2: End YouTube broadcast
        if self.current_broadcast_id:
            success = self.youtube.end_broadcast(self.current_broadcast_id)
            if success:
                self.current_broadcast_id = None
            else:
                print("Failed to end YouTube broadcast")
        
        print("Stream stop sequence completed")
        
        # Step 3: Wait for OBS to fully stop streaming
        print("Waiting for OBS to fully stop streaming...")
        self._wait_for_obs_stop()
        print("OBS ready for next stream")
    
    def start_obs_with_key(self, stream_key):
        """Configure OBS with stream key and start streaming"""
        print(f"Configuring OBS with stream key...")
        
        if not self.obs.set_stream_settings(stream_key):
            print("Failed to configure OBS with stream key")
            return False
        
        print("Starting OBS streaming...")
        if not self.obs.start_streaming():
            print("Failed to start OBS streaming")
            return False
        
        print("OBS streaming started successfully!")
        return True
    
    def create_next_stream(self, target_start_time: dt_time):
        """Create the next scheduled stream"""
        now = datetime.now(timezone.utc)
        
        # Calculate the next occurrence of this start time
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
            # Store the stream ID and key from the created broadcast
            self.next_stream_id = getattr(self.youtube, 'current_stream_id', None)
            self.next_stream_key = getattr(self.youtube, 'current_stream_key', None)
            
            # Immediately configure and start OBS with the new key
            if self.next_stream_key:
                if not self.start_obs_with_key(self.next_stream_key):
                    print("Failed to start OBS with new stream key")
                    return False
            
            print(f"Next stream scheduled for: {next_start.strftime('%Y-%m-%d %H:%M:%S UTC')}")
            return True
        else:
            print("Failed to create next stream")
            return False
    
    def start_next_stream(self):
        """Start the next YouTube broadcast with retry logic"""
        if not self.next_broadcast_id:
            print("No next broadcast to start")
            return False
        
        # OBS is already streaming with the correct key from create_next_stream()
        # No need to verify - proceed directly to waiting for YouTube stream detection
        
        # Wait for YouTube to detect the stream as active
        if self.next_stream_id and self.youtube.wait_for_stream_active(self.next_stream_id):
            # First transition to testing if in ready status
            if self._get_broadcast_status(self.next_broadcast_id) == 'ready':
                print("Broadcast is in 'ready' status, transitioning to 'testing' first...")
                if self.youtube.transition_broadcast(self.next_broadcast_id, 'testing'):
                    print("Successfully transitioned to testing status")
                    time.sleep(10)  # Brief pause between transitions
                else:
                    print("Failed to transition to testing status")
                    return False
            
            # Retry logic for testing to live transition
            max_attempts = 30
            for attempt in range(1, max_attempts + 1):
                print(f"Attempting to transition to live (attempt {attempt}/{max_attempts})")
                success = self.youtube.start_broadcast(self.next_broadcast_id)
                
                if success:
                    self.current_broadcast_id = self.next_broadcast_id
                    self.current_stream_id = self.next_stream_id
                    self.next_broadcast_id = None
                    self.next_stream_id = None
                    print("Next stream is now live")
                    return True
                else:
                    print(f"Transition attempt {attempt} failed")
                    if attempt < max_attempts:
                        print("Waiting 10 seconds before retry...")
                        time.sleep(10)
            
            # If we get here, all attempts failed
            print("catastrophic error - unable to transition from testing to live")
            exit(1)
        
        print("Failed to start broadcast - stream not active or API call failed")
        return False
    
    def _get_broadcast_status(self, broadcast_id):
        """Get current broadcast lifecycle status"""
        url = "https://www.googleapis.com/youtube/v3/liveBroadcasts"
        params = {
            "part": "status",
            "id": broadcast_id
        }
        
        response = self.youtube._make_api_request(url, params=params)
        if response and response.get('items'):
            return response['items'][0]['status']['lifeCycleStatus']
        return None
    
    def run_schedule(self):
        """Main scheduling loop with event-based timing and low-activity mode"""
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
                    
                    # Check if we should enter low-activity mode
                    if time_until_event > 3 * 60 * 60:  # More than 3 hours until next event
                        print(f"Next event in {time_until_event/3600:.1f} hours - entering low-activity mode (30-minute intervals)")
                        time.sleep(30 * 60)  # 30 minutes
                        continue
                    
                    # Execute if it's time
                    if time_until_event <= SCHEDULE_TOLERANCE_SECONDS:
                        if next_event.event_type == "STOP":
                            print(f"Executing STOP event")
                            self.stop_current_stream()
                            self.create_next_stream(next_event.original_start_time)
                            time.sleep(15)  # Prevent duplicate execution
                        elif next_event.event_type == "START":
                            print()
                            print(f"Executing START event")
                            if self.next_broadcast_id:
                                self.start_next_stream()
                            time.sleep(15)  # Prevent duplicate execution
                    
                    # Adaptive sleep timing (for periods closer to events)
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

def main():
    print("24/7 Automated Livestream Relay System v0.23")
    print("Python3 + OBS WebSocket 5.1 + YouTube API v3")
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
        print(f"Error: {e}")
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
