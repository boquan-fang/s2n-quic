#!/usr/bin/env python3

"""
Split s2n-quic logs into client and server columns with improved readability.

Usage:
    cargo test default_fips_test -- --nocapture | python3 scripts/split_logs_improved.py
"""

import sys
import shutil
import re
import signal

# Try to import colorama, but provide fallbacks if not available
try:
    import colorama
    from colorama import Fore, Style, Back
    colorama.init()
    HAS_COLORAMA = True
except ImportError:
    HAS_COLORAMA = False
    # Define simple color class for fallback
    class ColorFallback:
        def __init__(self, code):
            self.code = code
        
        def __add__(self, other):
            if isinstance(other, ColorFallback):
                return ColorFallback(self.code + other.code)
            return self
        
        def __str__(self):
            if HAS_COLORAMA:
                return self.code
            return ""
    
    class StyleFallback:
        RESET_ALL = ColorFallback("")
        BRIGHT = ColorFallback("")
        DIM = ColorFallback("")
    
    class ForeFallback:
        BLACK = ColorFallback("")
        RED = ColorFallback("")
        GREEN = ColorFallback("")
        YELLOW = ColorFallback("")
        BLUE = ColorFallback("")
        MAGENTA = ColorFallback("")
        CYAN = ColorFallback("")
        WHITE = ColorFallback("")
    
    class BackFallback:
        BLACK = ColorFallback("")
        RED = ColorFallback("")
        GREEN = ColorFallback("")
        YELLOW = ColorFallback("")
        BLUE = ColorFallback("")
        MAGENTA = ColorFallback("")
        CYAN = ColorFallback("")
        WHITE = ColorFallback("")
    
    # Use fallbacks if colorama is not available
    Fore = ForeFallback
    Style = StyleFallback
    Back = BackFallback

# Handle broken pipe errors gracefully
def handle_broken_pipe(signum, frame):
    # Close stdout without complaining about it
    try:
        sys.stdout.close()
    except:
        pass
    try:
        sys.stderr.close()
    except:
        pass
    sys.exit(0)

signal.signal(signal.SIGPIPE, handle_broken_pipe)

# Define colors for different event types
EVENT_COLORS = {
    # Connection lifecycle events
    "connection_started": Fore.GREEN,
    "handshake_status_updated": Fore.GREEN + Style.BRIGHT,
    "connection_closed": Fore.RED + Style.BRIGHT,
    
    # Packet events
    "packet_sent": Fore.BLUE,
    "packet_received": Fore.CYAN,
    "packet_lost": Fore.RED,
    "packet_dropped": Fore.RED,
    
    # Crypto events
    "key_update": Fore.MAGENTA,
    "tls_exporter_ready": Fore.MAGENTA,
    "key_space_discarded": Fore.MAGENTA,
    
    # Stream events
    "rx_stream_progress": Fore.YELLOW,
    "tx_stream_progress": Fore.YELLOW,
    
    # Frame events
    "frame_sent": Fore.WHITE,
    "frame_received": Fore.WHITE,
    
    # Path events
    "active_path_updated": Fore.GREEN,
    "path_created": Fore.GREEN,
    
    # Default color for other events
    "default": Fore.WHITE
}

# Define important events that should be highlighted
IMPORTANT_EVENTS = [
    "connection_started",
    "handshake_status_updated",
    "connection_closed",
    "rx_stream_progress",
    "tx_stream_progress",
    "active_path_updated",
    "key_update"
]

def main():
    # Get terminal width
    terminal_width = shutil.get_terminal_size().columns
    
    # Calculate column widths (no separator)
    col_width = terminal_width // 2
    
    # Print header
    try:
        print(f"{Back.BLUE}{Fore.WHITE}{'CLIENT'.center(col_width)}{Style.RESET_ALL}{Back.GREEN}{Fore.WHITE}{'SERVER'.center(col_width)}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}{'-' * col_width}{Style.RESET_ALL}{Fore.GREEN}{'-' * col_width}{Style.RESET_ALL}")
    except BrokenPipeError:
        handle_broken_pipe(None, None)
    
    client_buffer = []
    server_buffer = []
    
    # Process each line from stdin
    for line in sys.stdin:
        line = line.rstrip()
        
        # Skip test result lines, empty lines, and s2n_quic::tests::setup lines
        if line.startswith("test ") or line.startswith("running ") or not line or "s2n_quic::tests::setup" in line:
            if not "s2n_quic::tests::setup" in line:  # Skip printing setup lines
                print(line)
            continue
            
        # Check if it's a client or server log
        if "s2n_quic:client" in line:
            client_buffer.append(line)
        elif "s2n_quic:server" in line:
            server_buffer.append(line)
        else:
            # Print non-client/server lines centered
            print(line.center(terminal_width))
            continue
        
        # Process buffers if both have content
        if client_buffer and server_buffer:
            process_buffers(client_buffer, server_buffer, col_width)
            client_buffer = []
            server_buffer = []
    
    # Process any remaining buffer content
    if client_buffer or server_buffer:
        process_buffers(client_buffer, server_buffer, col_width)

def process_buffers(client_buffer, server_buffer, col_width):
    # Determine how many lines to print
    lines_to_print = max(len(client_buffer), len(server_buffer))
    
    for i in range(lines_to_print):
        client_line = client_buffer[i] if i < len(client_buffer) else ""
        server_line = server_buffer[i] if i < len(server_buffer) else ""
        
        # Check if either line is too long for its column
        client_too_long = len(client_line) > col_width if client_line else False
        server_too_long = len(server_line) > col_width if server_line else False
        
        if client_too_long and server_too_long:
            # Both lines are too long, print them one after another
            # First print the client line with proper wrapping
            print_colored_line(client_line, is_client=True, col_width=col_width)
            
            # Then print the server line with proper wrapping
            print_colored_line(server_line, is_client=False, col_width=col_width)
        elif client_too_long:
            # Client line is too long
            print_colored_line(client_line, is_client=True, col_width=col_width)
            
            if server_line:
                # Format and print the server line
                server_display = format_line(server_line, col_width, is_client=False)
                print(f"{' ' * col_width}{server_display}")
        elif server_too_long:
            # Server line is too long
            if client_line:
                # Format and print the client line
                client_display = format_line(client_line, col_width, is_client=True)
                print(f"{client_display}{' ' * (col_width - len(client_display))}")
            
            print_colored_line(server_line, is_client=False, col_width=col_width)
        else:
            # Both lines fit in their columns
            client_display = format_line(client_line, col_width, is_client=True)
            server_display = format_line(server_line, col_width, is_client=False)
            print(f"{client_display}{server_display}")

def print_colored_line(line, is_client, col_width=None):
    """Print a long line with appropriate coloring, wrapping within column width"""
    # Extract timestamp if present
    timestamp_match = re.match(r"(^\d+:\d+:\d+\.\d+)", line)
    timestamp = timestamp_match.group(1) if timestamp_match else ""
    
    # Extract event type
    event_match = re.search(r":\s*(\w+):", line)
    event_type = event_match.group(1) if event_match else "default"
    
    # Get color for this event type
    color = EVENT_COLORS.get(event_type, EVENT_COLORS["default"])
    
    # Check if this is an important event
    is_important = event_type in IMPORTANT_EVENTS
    
    # Apply color
    side_color = Fore.BLUE if is_client else Fore.GREEN
    
    # If no column width specified, use half the terminal width
    if col_width is None:
        terminal_width = shutil.get_terminal_size().columns
        col_width = terminal_width // 2
    
    # Format the line with colors and highlighting
    if is_important:
        # Highlight important events
        colored_timestamp = f"{side_color}{timestamp}{Style.RESET_ALL}"
        colored_content = f"{color}{Style.BRIGHT}{line[len(timestamp)+1:]}{Style.RESET_ALL}"
    else:
        colored_timestamp = f"{side_color}{timestamp}{Style.RESET_ALL}"
        colored_content = f"{color}{line[len(timestamp)+1:]}{Style.RESET_ALL}"
    
    # Calculate the effective width for content (accounting for timestamp)
    content_width = col_width - len(timestamp) - 1  # -1 for the space after timestamp
    
    # Split the content into chunks that fit within the column width
    content = line[len(timestamp)+1:]
    chunks = [content[i:i+content_width] for i in range(0, len(content), content_width)]
    
    try:
        # Print first line with timestamp
        if is_client:
            print(f"{colored_timestamp} {colored_content[:content_width].ljust(content_width)}")
        else:
            padding = " " * col_width
            print(f"{padding}{colored_timestamp} {colored_content[:content_width].ljust(content_width)}")
        
        # Print continuation lines if needed
        for i, chunk in enumerate(chunks[1:], 1):
            if is_client:
                # For client, pad the timestamp area and print in the left column
                print(f"{' ' * (len(timestamp) + 1)}{color}{chunk.ljust(content_width)}{Style.RESET_ALL}")
            else:
                # For server, pad the left column and timestamp area, then print in the right column
                padding = " " * col_width
                print(f"{padding}{' ' * (len(timestamp) + 1)}{color}{chunk.ljust(content_width)}{Style.RESET_ALL}")
    except BrokenPipeError:
        handle_broken_pipe(None, None)

def format_line(line, width, is_client=True):
    if not line:
        return " " * width
    
    # Extract timestamp if present
    timestamp_match = re.match(r"(^\d+:\d+:\d+\.\d+)", line)
    timestamp = timestamp_match.group(1) if timestamp_match else ""
    
    # Extract event type
    event_match = re.search(r":\s*(\w+):", line)
    event_type = event_match.group(1) if event_match else "default"
    
    # Get color for this event type
    color = EVENT_COLORS.get(event_type, EVENT_COLORS["default"])
    
    # Check if this is an important event
    is_important = event_type in IMPORTANT_EVENTS
    
    # If line is shorter, pad with spaces
    formatted = line.ljust(width)
    
    # Apply color
    side_color = Fore.BLUE if is_client else Fore.GREEN
    
    # Format the line with colors and highlighting
    if is_important:
        # Highlight important events
        return f"{side_color}{timestamp}{Style.RESET_ALL} {color}{Style.BRIGHT}{formatted[len(timestamp)+1:]}{Style.RESET_ALL}"
    else:
        return f"{side_color}{timestamp}{Style.RESET_ALL} {color}{formatted[len(timestamp)+1:]}{Style.RESET_ALL}"

if __name__ == "__main__":
    try:
        main()
    except BrokenPipeError:
        handle_broken_pipe(None, None)
    except KeyboardInterrupt:
        sys.exit(0)
