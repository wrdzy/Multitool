import os
import sys
import re
import socket
import requests
import json
import shodan
import hashlib
import base64
import ipaddress
import time
import psutil
import shutil
import random
import msvcrt  # Windows-specific module for key detection
import numpy as np
import matplotlib.pyplot as plt
from typing import Dict, Optional, Any
from mistralai import Mistral



# ANSI color codes
COLOR_BLUE = "\033[94m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_RED = "\033[91m"
COLOR_RESET = "\033[0m"

# =============================== Utility Functions ===============================
def clear_screen():
    """Clears the console screen based on the operating system."""
    os.system('cls' if os.name == 'nt' else 'clear')

def print_header():
    """Prints the tool's centered header with colors."""
    header = """
      ▄████▄   ██▀███   ▒█████   █     █░
    ▒██▀ ▀█  ▓██ ▒ ██▒▒██▒  ██▒▓█░ █ ░█░
    ▒▓█    ▄ ▓██ ░▄█ ▒▒██░  ██▒▒█░ █ ░█
    ▒▓▓▄ ▄██▒▒██▀▀█▄  ▒██   ██░░█░ █ ░█
    ▒ ▓███▀ ░░██▓ ▒██▒░ ████▓▒░░░██▒██▓
    ░ ░▒ ▒  ░░ ▒▓ ░▒▓░░ ▒░▒░▒░ ░ ▓░▒ ▒
      ░  ▒     ░▒ ░ ▒░  ░ ▒ ▒░   ▒ ░ ░
    ░          ░░   ░ ░ ░ ░ ▒    ░   ░
    ░ ░        ░░   ░ ░ ░ ░ ▒    ░   ░
    ░ ░
     version 1.555555.6
    """
    terminal_width = shutil.get_terminal_size().columns
    header_lines = header.split("\n")

    for line in header_lines:
        print(COLOR_BLUE + line.center(terminal_width) + COLOR_RESET)

print_header()

def center_text(text, width=80):
    """Center text within a specified width."""
    return text.center(width)

def wait_for_input():
    """Pauses the execution until the user presses Enter."""
    input("\nPress Enter to continue...")
    clear_screen()

class OSINTTool:
    def __init__(self, api_key_file: str = 'APIS.txt'):
        """
        Initialize the OSINT tool with API keys.
        """
        self.api_keys = self._read_api_keys(api_key_file)

    def _read_api_keys(self, file_name: str) -> dict:
        """
        Read API keys from a configuration file in the same directory as the executable.
        """
        api_keys = {}

        # Get the directory where the script or .exe is located
        if getattr(sys, 'frozen', False):
            # If running from the compiled .exe, use sys._MEIPASS
            base_path = os.path.dirname(sys.executable)
        else:
            # If running from the script, use the current directory
            base_path = os.path.dirname(os.path.abspath(__file__))

        # Define the full path to the APIS.txt file
        file_path = os.path.join(base_path, file_name)

        # Read the file
        try:
            with open(file_path, 'r') as file:
                for line in file:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        key, value = line.split('=', 1)
                        api_keys[key.strip()] = value.strip()
        except FileNotFoundError:
            print(f"API key file not found at {file_path}. Please ensure it exists.")
        except Exception as e:
            print(f"Error reading API keys: {str(e)}")

        return api_keys




    def validate_email(self, email: str) -> bool:
        clear_screen()
        """
        Validate email format

        :param email: Email address to validate
        :return: Boolean indicating email validity
        """
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def validate_ip(self, ip: str) -> bool:
        clear_screen()
        """
        Validate IP address

        :param ip: IP address to validate
        :return: Boolean indicating IP validity
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False

    def validate_credit_card(self, card_number: str) -> bool:
        clear_screen()

        """
        Enhanced credit card validation using Luhn algorithm

        :param card_number: Credit card number to validate
        :return: Boolean indicating card number validity
        """
        # Remove non-digit characters
        card_number = ''.join(filter(str.isdigit, card_number))

        # Check length and Luhn algorithm
        if not (13 <= len(card_number) <= 19):
            return False

        total = 0
        reverse_digits = card_number[::-1]
        for i, digit in enumerate(reverse_digits):
            n = int(digit)
            if i % 2 == 1:
                n *= 2
                if n > 9:
                    n -= 9
            total += n
        return total % 10 == 0

    def port_scanner(self, target: str, port_range: tuple = (1, 1024)) -> Dict[int, str]:

        """
        Basic port scanner implementation

        :param target: Target IP or hostname
        :param port_range: Tuple of start and end port numbers
        :return: Dictionary of open ports and their service names
        """
        clear_screen()
        if not self.validate_ip(target):
            print("Invalid IP address: " + target)
            return {}

        open_ports = {}
        for port in range(port_range[0], port_range[1] + 1):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((target, port))

                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "Unknown"
                    open_ports[port] = service

                sock.close()
            except Exception as e:
                print("Error scanning port " + str(port) + ": " + str(e))

        return open_ports

    def monitor_bandwidth(self, str, duration: int = 10):
        clear_screen()
        """
        Monitor network bandwidth usage live over a specified duration.

        :param interface: Network interface to monitor (e.g., 'eth0', 'wlan0')
        :param duration: Duration in seconds to monitor bandwidth usage
        """
        try:
            # Display available network interfaces with numbers
            interfaces = psutil.net_if_addrs()
            interface_list = list(interfaces.keys())
            print("\nAvailable Network Interfaces:")
            for idx, iface in enumerate(interface_list, start=1):
                print(f"{idx}. {iface}")

            # Prompt user to select an interface by number
            try:
                choice = int(input("\nSelect an interface by number: \n[CROW] > "))
                if choice < 1 or choice > len(interface_list):
                    print("Invalid choice. Please try again.")
                    input("\nPress Enter to continue...")
                    return
                interface = interface_list[choice - 1]
            except ValueError:
                print("Invalid input. Please enter a number.")
                input("\nPress Enter to continue...")
                return

            # Check if the selected interface exists
            if interface not in interfaces:
                print("Error: Interface '" + interface + "' not found. Please check the available interfaces.")
                input("\nPress Enter to continue...")
                return

            # Prompt user to enter the duration
            try:
                duration = int(input("\nEnter duration in seconds to monitor bandwidth: \n[CROW] > "))
                if duration <= 0:
                    print("Duration must be a positive integer.")
                    input("\nPress Enter to continue...")
                    return
            except ValueError:
                print("Invalid input. Please enter a valid number.")
                input("\nPress Enter to continue...")
                return

            # Monitor bandwidth usage live
            print("\nMonitoring bandwidth usage on " + interface + " for " + str(duration) + " seconds...\n")
            initial = psutil.net_io_counters(pernic=True)[interface]

            for second in range(1, duration + 1):
                time.sleep(1)
                current = psutil.net_io_counters(pernic=True)[interface]
                upload_speed = (current.bytes_sent - initial.bytes_sent) / (second * 1024)  # KB/s
                download_speed = (current.bytes_recv - initial.bytes_recv) / (second * 1024)  # KB/s

                # Display progress bar with enhanced visuals
                progress = int((second / duration) * 50)  # Scale progress to 50 characters
                bar = f"[{'█' * progress}{'░' * (50 - progress)}] {second}/{duration}s"
                print(f"{bar} | ⬆ Upload: {upload_speed:.2f} KB/s | ⬇ Download: {download_speed:.2f} KB/s", end="\r", flush=True)

            # Final bandwidth usage
            final = psutil.net_io_counters(pernic=True)[interface]
            total_upload = (final.bytes_sent - initial.bytes_sent) / 1024  # KB
            total_download = (final.bytes_recv - initial.bytes_recv) / 1024  # KB

            print("\n\nFinal Bandwidth Usage:")
            print(f"⬆ Total Upload: {total_upload:.2f} KB")
            print(f"⬇ Total Download: {total_download:.2f} KB")

            input("\nPress Enter to continue...")
        except KeyError:
            print(f"Error: Interface '{interface}' not found. Please check the available interfaces.")
            input("\nPress Enter to continue...")  # Pause to prevent clearing immediately
        except Exception as e:
            print(f"An error occurred: {str(e)}")
            input("\nPress Enter to continue...")  # Pause to prevent clearing immediately

# =============================== OSINT Section ===============================
def ip_lookup(tool: OSINTTool):
    clear_screen()
    target_ip = input("Enter IP address to lookup: \n[CROW] > ")

    if not tool.validate_ip(target_ip):
        print("Invalid IP address.")
        wait_for_input()
        return

    try:
        response = requests.get(f'http://ip-api.com/json/{target_ip}')
        if response.status_code == 200:
            data = response.json()
            print("\n===== IP Lookup Results =====")
            for key, value in data.items():
                if key not in ['status', 'query', 'lon', 'lat']:
                    print(f"{key.capitalize()}: {value}")
        else:
            print("Error: " + str(response.status_code))

        wait_for_input()

    except requests.RequestException as e:
        print("Network error: " + str(e))
        wait_for_input()

def hunter_io_search(tool: OSINTTool):
    clear_screen()
    target_email = input("Enter email to search: \n[CROW] > ")

    if not tool.validate_email(target_email):
        print("Invalid email address.")
        wait_for_input()
        return

    # Check if Hunter.io API key exists
    if "HUNTER_API_KEY" not in tool.api_keys:
        print("Hunter.io API key not found.")
        wait_for_input()
        return

    try:
        response = requests.get(
            f'https://api.hunter.io/v2/email-verifier',
            params={
                'email': target_email,
                'api_key': tool.api_keys.get("HUNTER_API_KEY", "")
            }
        )

        if response.status_code == 200:
            data = response.json()
            result_data = data.get('data', {})

            print("\nEmail Intelligence Result:")
            for key, value in result_data.items():
                print(f"{key.replace('_', ' ').title()}: {value}")
        else:
            print("Error: " + str(response.status_code))

    except requests.RequestException as e:
        print("Network error: " + str(e))

    wait_for_input()

def virustotal_check(tool: OSINTTool):
    clear_screen()
    # Check if VirusTotal API key exists
    if "VIRUSTOTAL_API_KEY" not in tool.api_keys:
        print("VirusTotal API key not found.")
        wait_for_input()
        return

    input_value = input("Enter URL or file path to check: \n[CROW] > ")

    # Check if the input is a file path
    if os.path.isfile(input_value):
        # Calculate file hash
        with open(input_value, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
        headers = {'x-apikey': tool.api_keys.get("VIRUSTOTAL_API_KEY", "")}

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                print("\nVirusTotal File Hash Result:")
                print("File Hash: " + file_hash)
                analysis_stats = data['data']['attributes'].get('last_analysis_stats', {})
                print("Malicious Votes: " + str(analysis_stats.get('malicious', 0)))
                print("Total Votes: " + str(analysis_stats.get('total', 0)))
            elif response.status_code == 404:
                print("File not found in VirusTotal database.")
            else:
                print("Error: " + str(response.status_code))

        except requests.RequestException as e:
            print("Network error: " + str(e))

    else:
        # URL check
        url = f'https://www.virustotal.com/api/v3/urls/{base64.urlsafe_b64encode(input_value.encode()).decode().strip("=")}'
        headers = {'x-apikey': tool.api_keys.get("VIRUSTOTAL_API_KEY", "")}

        try:
            response = requests.get(url, headers=headers)

            if response.status_code == 200:
                data = response.json()
                print("\nVirusTotal URL Check Result:")
                print("URL: " + data['data']['id'])
                analysis_stats = data['data']['attributes'].get('last_analysis_stats', {})
                print("Malicious Votes: " + str(analysis_stats.get('malicious', 0)))
                print("Total Votes: " + str(analysis_stats.get('total', 0)))
            else:
                print("Error: " + str(response.status_code))
        except requests.RequestException as e:
            print("Network error: " + str(e))

    wait_for_input()

def shodan_search(tool: OSINTTool):
    clear_screen()
    # Check if Shodan API key exists
    if "SHODAN_API_KEY" not in tool.api_keys:
        print("Shodan API key not found.")
        wait_for_input()
        return

    target_ip = input("Enter IP to search on Shodan: \n[CROW] > ")

    if not tool.validate_ip(target_ip):
        print("Invalid IP address.")
        wait_for_input()
        return

    try:
        api = shodan.Shodan(tool.api_keys.get("SHODAN_API_KEY", ""))
        info = api.host(target_ip)

        print("\nSHODAN Search Result:")
        print("IP: " + info['ip_str'])
        print("Organization: " + info.get('org', 'N/A'))
        location = info.get('location', {})
        print("Location: " + location.get('city', 'N/A') + ", " + location.get('country_name', 'N/A'))
        print("Services: " + ', '.join(service.get('product', 'Unknown') for service in info['data']))
    except shodan.APIError as e:
        print("Error: " + str(e))

    wait_for_input()

def verify_phone_number(tool: OSINTTool):
    clear_screen()
    # Check if NumVerify API key exists
    if "NUMVERIFY_API_KEY" not in tool.api_keys:
        print("NumVerify API key not found.")
        wait_for_input()
        return

    print("Enter phone number to lookup (e.g., +1234567890 for US numbers): ")
    phone_number = input("\n[CROW] > ")

    api_url = f"http://apilayer.net/api/validate"
    api_params = {
        'access_key': tool.api_keys.get("NUMVERIFY_API_KEY", ""),
        'number': phone_number,
        'country_code': '',  # Leave blank to detect automatically
        'format': 1  # Return detailed JSON response
    }

    try:
        response = requests.get(api_url, params=api_params)
        response.raise_for_status()
        data = response.json()

        print("\nPhone Number Validation:")
        for key, value in data.items():
            if key not in ['error']:
                print(f"{key.replace('_', ' ').title()}: {value}")

    except requests.exceptions.RequestException as e:
        print("Error connecting to the API: " + str(e))

    wait_for_input()

# =============================== Credit Card Section ===============================
def check_precise_bin(tool: OSINTTool):
    clear_screen()
    """Check Precise BIN details using Binlist API."""
    bin_number = input("Enter BIN (6 first numbers) number to check: \n[CROW] > ")

    # Validate BIN
    if not bin_number.isdigit() or len(bin_number) != 6:
        print("Invalid BIN. Must be 6 digits.")
        wait_for_input()
        return

    # Binlist.net
    url = f'https://lookup.binlist.net/{bin_number}'
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()

        print("\nPrecise BIN Check Result:")
        print("BIN: " + bin_number)
        print("Bank: " + data.get('bank', {}).get('name', 'N/A'))
        print("Card Type: " + data.get('type', 'N/A'))
        print("Card Brand: " + data.get('brand', 'N/A'))
        print("Country: " + data.get('country', {}).get('name', 'N/A'))
        print("Card Level: " + data.get('level', 'N/A'))
        print("Card Scheme: " + data.get('scheme', 'N/A'))
        print("Issuer: " + data.get('bank', {}).get('issuer', 'N/A'))
    else:
        print("Error: " + str(response.status_code))

    wait_for_input()

def card_type(card_number: str) -> str:
    """Determine card type based on BIN."""
    # Remove non-digit characters
    card_number = ''.join(filter(str.isdigit, card_number))

    if not card_number:
        return "Invalid"

    bin_number = card_number[:6]
    if bin_number.startswith(('4')):
        return "Visa"
    elif bin_number.startswith(('5')):
        return "MasterCard"
    elif bin_number.startswith(('3')):
        return "American Express"
    else:
        return "Unknown"

# =============================== Network Tools ===============================
def network_menu(tool: OSINTTool):
    while True:
        clear_screen()
        print_header()
        print("\nNetwork Tools:")
        print("[01] -> Port Scanner")
        print("[02] -> Network Mapper")
        print("[03] -> IP Ping")
        print("[04] -> Bandwidth Monitor")
        print("[M] -> Back to Main Menu")

        choice = input("\n[CROW] > ")

        if choice == '1':
            clear_screen()
            target_ip = input("Enter IP to scan: \n[CROW] > ")
            ports = tool.port_scanner(target_ip)
            print("\nOpen Ports:")
            for port, service in ports.items():
                print(f"Port {port}: {service}")
            wait_for_input()
        elif choice == '2':
            print("Network Mapper - Not Fully Implemented")
            input("Press Enter to continue...")
        elif choice == '3':
            clear_screen()
            target_ip = input("Enter IP to ping: \n[CROW] > ")
            try:
                # Determine the correct ping command based on OS
                if os.name == 'nt':  # Windows
                    response = os.system(f"ping -n 1 {target_ip}")
                elif os.name == 'posix':  # Unix-based
                    response = os.system(f"ping -c 1 {target_ip}")
                else:
                    print("Unsupported operating system.")
                    response = 1  # Treat as unreachable

                if response == 0:
                    print(target_ip + " is reachable.")
                elif response == 1:
                    print(target_ip + " is unreachable.")
                else:
                    print("An error occurred while trying to ping the target.")
            except Exception as e:
                print("Error pinging " + target_ip + ": " + str(e))
            wait_for_input()
        elif choice == '4':
            tool.monitor_bandwidth(str)
        elif choice == 'm':
            return
        else:
            print("Invalid choice.")
            input("Press Enter to continue...")

# =============================== AI CHATBOT Section ===============================
def chatbot_menu(tool: OSINTTool):
    while True:
        clear_screen()
        print_header()
        print("\nAI Chatbots:")
        print("[01] -> Mistral AI")
        print("[02] -> Gemini AI")
        print("[03] -> Grok AI")
        print("[M] -> Back to Main Menu")

        choice = input("\n[CROW] > ")

        if choice == '1':
            clear_screen()
            api_key = tool.api_keys.get("MISTRALAI_API_KEY", "")
            if not api_key:
                print("Mistral API key is missing.")
                input("Press Enter to continue...")
                continue

            make_mistral_request(api_key)

        elif choice == '2':
            print("Gemini AI - Not Fully Implemented")
            input("Press Enter to continue...")
        elif choice == '3':
            clear_screen()
            api_key = tool.api_keys.get("GROKAI_API_KEY", "")
            if not api_key:
                print("Grok API key is missing.")
                input("Press Enter to continue...")
                continue
            print("\nWelcome to Grok AI chat")
            print("Type 'exit' anytime to return to the menu.\n")

            make_grok_request(api_key)

        elif choice == 'm':
            return

        else:
            print("Invalid choice.")
            input("Press Enter to continue...")

def make_mistral_request(api_key):
    clear_screen()
    model = "mistral-small-latest"
    client = Mistral(api_key=api_key)
    print("\nWelcome to Mistral AI chat")
    print("'exit' anytime to return to the menu,\n'clear' anytime to clear the chat.\n-------------------------------------\n")

    while True:
        prompt = input("[CROW] > ").strip()

        if not prompt:
            print("Empty input. Please enter a prompt.")
            continue

        if prompt.lower() == "exit":
            print("\nReturning to the menu...\n")
            break

        if prompt.lower() == "clear":
            clear_screen()
            print("\nWelcome to Mistral AI chat")
            print("'exit' anytime to return to the menu,\n'clear' anytime to clear the chat.\n-------------------------------------\n")
            continue

        print("\nMistral AI: ", end=" ")

        stream_response = client.chat.stream(
            model=model,
            messages=[
                {"role": "system", "content": "Always respond in the language used by the user."},
                {"role": "user", "content": prompt}
            ]
        )

        for chunk in stream_response:
            if chunk.data.choices[0].delta.content is not None:
                print(chunk.data.choices[0].delta.content, end="", flush=True)

        print("\n")

def make_grok_request(api_key):
    clear_screen()
    model = "grok-2-latest"
    api_url = "https://api.x.ai/v1/chat/completions"

    clear_screen()

    print("\nWelcome to Grok AI chat")
    print("Type 'exit' anytime to return to the menu.\n")

    while True:
        prompt = input("[CROW] > ")

        if prompt.lower() == "exit":
            print("\nReturning to the menu...\n")
            break

        if prompt.lower() == "clear":
            clear_screen()
            print("\nWelcome to Grok AI chat")
            print("Type 'exit' anytime to return to the menu.\n")
            continue

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}"
        }

        data = {
            "messages": [{"role": "user", "content": prompt}],
            "model": model,
            "stream": False,
            "temperature": 0.7
        }

        response = requests.post(api_url, headers=headers, data=json.dumps(data))

        if response.status_code == 200:
            response_data = response.json()
            print("\nGrok AI: " + response_data['choices'][0]['message']['content'])
        else:
            print("\nError: " + str(response.status_code) + "\n" + response.text)

        print("\n")

def wave_animation():
    clear_screen()
    try:
        terminal_width = os.get_terminal_size().columns
        terminal_height = os.get_terminal_size().lines
    except Exception:
        terminal_width = 80
        terminal_height = 24
    clear_screen()

    WAVE_CHARS = [
        '$', '%', '&', '#', '@', '*', '+', '=', '^', '!', '~',
        '.', ',', ';', ':', '(', ')', '[', ']', '{', '}', '<', '>',
        '|', '\\', '/', '?', '€', '£', '©', '®', '±', '™', '°', '¶',
        '∞', '♥', '♦', '♣', '♠', '✪', '✯', '★', '☆'
    ]

    RESET_COLOR = "\033[0m"

    print("\033[2J\033[H", end='', flush=True)
    print("Press any key to stop the animation...".center(terminal_width))

    def generate_wave(phase, amplitude_factor):
        wave = []
        for y in range(terminal_height - 2):
            line = [' '] * terminal_width
            wave_positions = []

            for x in range(terminal_width):
                wavelength_factor = terminal_width / 0.8
                wave_height = int((amplitude_factor * terminal_height / 10) * np.sin((x / wavelength_factor * np.pi) + phase))
                middle = (terminal_height - 2) // 2
                wave_position = middle + wave_height
                wave_positions.append(wave_position)

            for x in range(terminal_width):
                if y >= wave_positions[x]:
                    line[x] = random.choice(WAVE_CHARS)

            wave.append(''.join(line))
        return wave

    try:
        phase = 0.0
        amplitude_factor = 3.0

        speed_factor = random.uniform(0.005, 0.02)  # Initial random speed
        speed_change_rate = 0.00002  # Gradual speed variation
        target_speed = random.uniform(0.003, 0.025)  # Random initial target

        while True:
            if msvcrt.kbhit():
                msvcrt.getch()
                break

            wave = generate_wave(phase, amplitude_factor)

            print("\033[H", end="")
            print("Press any key to stop the animation...".center(terminal_width))
            print("\n".join(wave) + RESET_COLOR, end='', flush=True)

            time.sleep(speed_factor)  # Wave speed changes dynamically

            phase += speed_factor

            if phase > 2 * np.pi:
                phase -= 2 * np.pi

            # Gradually adjust speed toward target speed
            if speed_factor < target_speed:
                speed_factor = min(speed_factor + speed_change_rate, target_speed)
            else:
                speed_factor = max(speed_factor - speed_change_rate, target_speed)

            # Occasionally pick a new target speed
            if random.random() < 0.02:  # 2% chance per frame to change speed
                target_speed = random.uniform(0.05, 0.25)

    except KeyboardInterrupt:
        print("\033[2J\033[H", end='')
        print("Animation stopped.")

    print("\033[2J\033[H", end='')
    print("Returning to menu...")

# The function is defined but not executed

# =============================== Main Menu ===============================
def get_terminal_size():

    """Get the size of the terminal."""
    return shutil.get_terminal_size((80, 20))

def draw_box(title, options, width=44, height=12):
    """Draw a box with a title, options, and a customizable number of lines."""
    lines = []

    # Create the title line with the title centered
    title_with_spaces = f" {title} "
    padding = (width - len(title_with_spaces) - 2) // 2
    title_line = '╔' + '═' * padding + title_with_spaces + '═' * (width - len(title_with_spaces) - 2 - padding) + '╗'
    lines.append(title_line)

    # Draw the separator line
    lines.append('║' + ' ' * (width - 2) + '║')

    # Draw the options
    num_options = height - 4  # We have 2 lines for the title and separator, so options fit in the remaining space
    for i in range(num_options):
        if i < len(options):
            lines.append('║ ' + options[i].ljust(width - 4) + ' ║')  # Padding for text inside the box
        else:
            lines.append('║' + ' ' * (width - 2) + '║')  # Empty space if there are fewer options

    # Draw the bottom border
    lines.append('╚' + '═' * (width - 2) + '╝')

    return '\n'.join(lines)

def main_menu():
    tool = OSINTTool()

    while True:
        clear_screen()
        print_header()

        terminal_size = get_terminal_size()
        terminal_width = terminal_size.columns
        box_width = min(44, terminal_width // 3 - 4)

        osint_tools_box = draw_box("OSINT TOOLS", ["[01] Email Intelligence", "[02] IP Information", "[03] Shodan Search", "[04] Phone Lookup", "[05] Virustotal"], width=box_width)
        card_analysis_box = draw_box("CARD ANALYSIS", ["[06] BIN Lookup", "[07] Card Validation", "[08] Card Type Check"], width=box_width)
        network_tools_box = draw_box("NETWORK TOOLS", ["[09] Port Scanner", "[10] Network Mapper", "[11] IP Ping", "[12] Bandwidth Monitor"], width=box_width)

        boxes = [osint_tools_box.split('\n'), card_analysis_box.split('\n'), network_tools_box.split('\n')]
        for lines in zip(*boxes):
            print('    '.join(lines).center(terminal_width))

        print("\n[E] Exit       [W] Wave       [N] Next Page >".center(terminal_width))

        choice = input("\n[CROW] > ").strip().lower()

        if choice == '1':
            hunter_io_search(tool)
        elif choice == '2':
            ip_lookup(tool)
        elif choice == '3':
            shodan_search(tool)
        elif choice == '4':
            verify_phone_number(tool)
        elif choice == '5':
            virustotal_check(tool)
        elif choice == '6':
            check_precise_bin(tool)
        elif choice == '7':
            clear_screen()
            card_number = input("Enter Credit Card number for validation: \n[CROW] > ")
            if tool.validate_credit_card(card_number):
                print("Card number is valid according to Luhn's algorithm.")
            else:
                print("Card number is invalid according to Luhn's algorithm.")
            wait_for_input()
        elif choice == '8':
            clear_screen()
            print("Enter Credit Card number to check type: ")
            card_number = input("\n[CROW] > ")
            card_type_name = card_type(card_number)
            print("Card Type: " + card_type_name)
            wait_for_input()
        elif choice == '9':
            clear_screen()
            print("Enter IP to scan: ")
            target_ip = input("\n[CROW] > ")
            ports = tool.port_scanner(target_ip)
            print("\nOpen Ports:")
            for port, service in ports.items():
                print(f"Port {port}: {service}")
            wait_for_input()
        elif choice == '10':
            print("Network Mapper - Not Fully Implemented")
            input("Press Enter to continue...")
        elif choice == '11':
            clear_screen()
            print("Enter IP to ping: ")
            target_ip = input("\n[CROW] > ")
            try:
                ping_command = f"ping -n 1 {target_ip}" if os.name == 'nt' else f"ping -c 1 {target_ip}"
                response = os.system(ping_command)
                if response == 0:
                    print(target_ip + " is reachable.")
                else:
                    print(target_ip + " is unreachable.")
            except Exception as e:
                print("Error pinging " + target_ip + ": " + str(e))
            wait_for_input()
        elif choice == '12':
            tool.monitor_bandwidth(str)
        elif choice == 'n':
            clear_screen()
            print_header()

            ai_chatbots_box = draw_box("AI Chatbots", ["[13] Mistral AI", "[14] Gemini AI", "[15] Grok AI"], width=box_width)

            boxes = [ai_chatbots_box.split('\n')]
            for lines in zip(*boxes):
                print('    '.join(lines).center(terminal_width))

            print("\n< [P] Previous Page       [N] Next Page >".center(terminal_width))

            choice = input("\n[CROW] > ").strip().lower()

            if choice == '13':
                clear_screen()
                api_key = tool.api_keys.get("MISTRALAI_API_KEY", "")
                if not api_key:
                    print("Mistral API key is missing.")
                    input("Press Enter to continue...")
                    continue

                make_mistral_request(api_key)
            elif choice == '14':
                print("Gemini AI - Not Fully Implemented")
                input("Press Enter to continue...")
            elif choice == '15':
                clear_screen()
                api_key = tool.api_keys.get("GROKAI_API_KEY", "")
                if not api_key:
                    print("Grok API key is missing.")
                    input("Press Enter to continue...")
                    continue
                print("\nWelcome to Grok AI chat")
                print("Type 'exit' anytime to return to the menu.\n")

                make_grok_request(api_key)
            elif choice == 'w':
                wave_animation()
            elif choice == 'e':
                print("Goodbye!")
                sys.exit(0)
            elif choice == 'p':
                continue
            else:
                print("Invalid choice.")
                input("Press Enter to continue...")
        elif choice == 'w':
            wave_animation()
        elif choice == 'e':
            print("Goodbye!")
            sys.exit(0)
        else:
            print("Invalid choice.")
            input("Press Enter to continue...")

# =============================== Execute the Program ===============================
if __name__ == '__main__':
    main_menu()
