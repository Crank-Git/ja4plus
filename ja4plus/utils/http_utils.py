"""
HTTP utility functions for JA4+ fingerprinting.
"""

from scapy.all import Raw, TCP, IP
import re
import logging

logger = logging.getLogger(__name__)

def parse_http_request(data):
    """
    Parse an HTTP request from raw data.
    
    Args:
        data: Raw bytes containing an HTTP request
        
    Returns:
        Dictionary with HTTP request details or None if not an HTTP request
    """
    if not data:
        return None
    
    try:
        # Convert bytes to string if needed
        if isinstance(data, bytes):
            data_str = data.decode('utf-8', errors='ignore')
        else:
            data_str = data
        
        # Split into lines
        lines = data_str.split('\r\n')
        if not lines:
            return None
        
        # Parse request line
        request_line = lines[0]
        parts = request_line.split(' ')
        if len(parts) < 3:
            return None
        
        method = parts[0].upper()
        path = parts[1]
        version = parts[2]
        
        # Check if this is an HTTP request
        http_methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT', 'TRACE']
        if method not in http_methods:
            return None
        
        # Parse headers
        headers = {}
        for i in range(1, len(lines)):
            line = lines[i]
            if not line or line == '':
                break
            
            if ':' not in line:
                continue
            
            header_parts = line.split(':', 1)
            if len(header_parts) != 2:
                continue
            
            header_name = header_parts[0].strip().lower()
            header_value = header_parts[1].strip()
            
            headers[header_name] = header_value
        
        # Extract cookies
        cookies = {}
        if 'cookie' in headers:
            cookie_str = headers['cookie']
            cookie_pairs = cookie_str.split(';')
            for pair in cookie_pairs:
                if '=' in pair:
                    cookie_parts = pair.split('=', 1)
                    if len(cookie_parts) == 2:
                        cookie_name = cookie_parts[0].strip()
                        cookie_value = cookie_parts[1].strip()
                        cookies[cookie_name] = cookie_value
        
        return {
            'method': method,
            'path': path,
            'version': version,
            'headers': headers,
            'cookies': cookies
        }
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.debug(f"Not an HTTP request: {e}")
        return None

def is_http_request(data):
    """
    Check if the data appears to be an HTTP request.
    
    Args:
        data: Raw bytes or string to check
        
    Returns:
        True if the data appears to be an HTTP request, False otherwise
    """
    http_methods = [b'GET ', b'POST ', b'PUT ', b'DELETE ', b'HEAD ', b'OPTIONS ', b'PATCH ', b'CONNECT ', b'TRACE ']
    
    if isinstance(data, str):
        data = data.encode('utf-8', errors='ignore')
    
    for method in http_methods:
        if data.startswith(method):
            return True
    
    return False

def extract_http_info(packet):
    """Extract HTTP information from a packet"""
    if not Raw in packet:
        return None
    
    try:
        data = bytes(packet[Raw]).decode('utf-8', errors='ignore')
        
        # Check if this is an HTTP request
        request_line_match = re.match(r'^(GET|POST|PUT|DELETE|HEAD|OPTIONS|CONNECT|TRACE|PATCH)\s+(\S+)\s+(HTTP/\d+\.\d+)', data)
        if not request_line_match:
            return None
        
        method = request_line_match.group(1)
        path = request_line_match.group(2)
        version = request_line_match.group(3)
        
        # Parse headers
        headers = {}
        header_names = []
        lines = data.split('\r\n')
        
        for line in lines[1:]:  # Skip request line
            if not line or line.isspace():
                break  # End of headers
                
            header_match = re.match(r'^([^:]+):\s*(.*)$', line)
            if header_match:
                name = header_match.group(1).strip()
                value = header_match.group(2).strip()
                headers[name.lower()] = value
                header_names.append(name)
        
        # Extract cookies
        cookies = {}
        cookie_fields = []
        cookie_values = []
        
        if 'cookie' in headers:
            cookie_str = headers['cookie']
            cookie_pairs = cookie_str.split(';')
            
            for pair in cookie_pairs:
                if '=' in pair:
                    name, value = pair.split('=', 1)
                    name = name.strip()
                    value = value.strip()
                    cookies[name] = value
                    cookie_fields.append(name)
                    cookie_values.append(value)
        
        # Extract language
        language = headers.get('accept-language', '')
        
        # Extract referer
        referer = headers.get('referer', '')
        
        return {
            'method': method,
            'path': path,
            'version': version,
            'headers': header_names,
            'cookies': cookies,
            'cookie_fields': cookie_fields,
            'cookie_values': cookie_values,
            'language': language,
            'referer': referer
        }
    
    except (ValueError, TypeError, UnicodeDecodeError) as e:
        logger.debug(f"Packet does not contain HTTP data: {e}")
        return None 