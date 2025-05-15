#!/usr/bin/env python3
"""
Lookout CVE Reporter

A tool for fetching and reporting devices vulnerable to specific CVEs from the
Lookout Mobile Endpoint Protection API. Supports both CLI and GUI interfaces.

This script allows users to:
1. Search for devices vulnerable to specific CVEs
2. Filter results by platform (iOS or Android) and OS version
3. Export results to CSV for further analysis

Author: Lookout CVE Reporter Contributors
License: MIT
"""

import os
import csv
import argparse
import requests
import sys
import threading
from dotenv import load_dotenv
import PySimpleGUI as sg

# API Endpoints
TOKEN_URL = "https://api.lookout.com/oauth2/token"
OS_VULNS_DEVICES_URL = "https://api.lookout.com/mra/api/v2/os-vulns/devices"
DEVICE_DETAIL_URL = "https://api.lookout.com/mra/api/v2/device"

# Default values
DEFAULT_CSV_FILENAME = "vulnerable_devices.csv"

# ===== CORE FUNCTIONALITY =====

def get_lookout_access_token(api_key, status_callback=None):
    """
    Authenticates with the Lookout API to get an access token.
    
    Args:
        api_key (str): The Lookout Application Key used for authentication
        status_callback (callable, optional): Function to call with status updates
        
    Returns:
        str or None: The access token if successful, None otherwise
    """
    if status_callback:
        status_callback("Authenticating with Lookout API...")
    
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Bearer {api_key}"
    }
    data = {"grant_type": "client_credentials"}
    try:
        response = requests.post(TOKEN_URL, headers=headers, data=data, timeout=30)
        response.raise_for_status()  # Raise an exception for bad status codes
        return response.json().get("access_token")
    except requests.exceptions.RequestException as e:
        error_msg = f"Error obtaining access token: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return None
    except ValueError as e: # Includes JSONDecodeError
        error_msg = f"Error decoding token response: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return None

def fetch_vulnerable_os_info(access_token, cve_id, status_callback=None):
    """
    Fetches OS and vulnerability-specific info for devices vulnerable to a given CVE.
    
    Args:
        access_token (str): The Lookout API access token
        cve_id (str): The CVE ID to search for (e.g., CVE-2023-12345)
        status_callback (callable, optional): Function to call with status updates
        
    Returns:
        list or None: List of vulnerable devices if successful, None otherwise
    """
    if status_callback:
        status_callback(f"Fetching OS info for devices vulnerable to {cve_id}...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"name": cve_id}
    try:
        response = requests.get(OS_VULNS_DEVICES_URL, headers=headers, params=params, timeout=60)
        response.raise_for_status()
        return response.json().get("devices", [])
    except requests.exceptions.RequestException as e:
        error_msg = f"Error fetching vulnerable OS info for devices: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return None
    except ValueError as e: # Includes JSONDecodeError
        error_msg = f"Error decoding vulnerable OS info response: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return None

def fetch_device_details_by_guid(access_token, guid, status_callback=None, progress_callback=None, index=None, total=None):
    """
    Fetches detailed information for a single device by its GUID.
    
    Args:
        access_token (str): The Lookout API access token
        guid (str): The GUID of the device to fetch details for
        status_callback (callable, optional): Function to call with status updates
        progress_callback (callable, optional): Function to call with progress updates
        index (int, optional): Current index in a batch operation
        total (int, optional): Total number of items in a batch operation
        
    Returns:
        dict or None: Device details if successful, None otherwise
    """
    if status_callback:
        if index is not None and total is not None:
            status_callback(f"Fetching details for GUID: {guid} ({index+1}/{total})...")
        else:
            status_callback(f"Fetching details for GUID: {guid}...")
    
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"guid": guid}
    try:
        response = requests.get(DEVICE_DETAIL_URL, headers=headers, params=params, timeout=30)
        response.raise_for_status()
        
        if progress_callback and index is not None and total is not None:
            progress_callback((index + 1) / total * 100)
            
        return response.json()
    except requests.exceptions.RequestException as e:
        error_msg = f"Error fetching details for device GUID {guid}: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return None
    except ValueError as e: # Includes JSONDecodeError
        error_msg = f"Error decoding device details response for GUID {guid}: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return None

def filter_devices(devices, platform_filter, os_version_filter, status_callback=None):
    """
    Filters devices based on platform and OS version.
    
    Args:
        devices (list): List of device dictionaries to filter
        platform_filter (str, optional): Platform to filter by (e.g., 'ios', 'android')
        os_version_filter (str, optional): OS version to filter by (exact match)
        status_callback (callable, optional): Function to call with status updates
        
    Returns:
        list: Filtered list of devices
    """
    if not devices:
        return []
    
    if status_callback:
        status_callback(f"Filtering devices (Platform: {platform_filter or 'Any'}, OS Version: {os_version_filter or 'Any'})...")
    
    filtered_list = []
    for device in devices:
        matches_platform = True
        matches_os_version = True

        if platform_filter:
            if device.get("platform", "").lower() != platform_filter.lower():
                matches_platform = False
        
        if os_version_filter:
            if device.get("os_version") != os_version_filter: # Exact match
                matches_os_version = False
        
        if matches_platform and matches_os_version:
            filtered_list.append(device)
            
    if status_callback and not filtered_list and devices:
        status_callback("No devices matched the specified filters.")
        
    return filtered_list

def export_to_csv(devices, filename, status_callback=None):
    """
    Exports the list of devices to a CSV file.
    
    Args:
        devices (list): List of device dictionaries to export
        filename (str): Path to the output CSV file
        status_callback (callable, optional): Function to call with status updates
        
    Returns:
        bool: True if export was successful, False otherwise
    """
    if not devices:
        if status_callback:
            status_callback("No devices to export.")
        else:
            print("No devices to export.")
        return False

    # CSV Columns: guid, email, customer_device_id, platform, device_model, os_version, latest_os_version, security_patch_level
    fieldnames = ["guid", "email", "customer_device_id", "platform", "device_model", "os_version", "latest_os_version", "security_patch_level"]
    
    try:
        with open(filename, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for device in devices:
                writer.writerow(device)
        
        success_msg = f"Successfully exported {len(devices)} devices to {filename}"
        if status_callback:
            status_callback(success_msg)
        else:
            print(success_msg)
        return True
    except IOError as e:
        error_msg = f"Error writing to CSV file {filename}: {e}"
        if status_callback:
            status_callback(error_msg, is_error=True)
        else:
            print(error_msg, file=sys.stderr)
        return False

def process_devices(access_token, cve_id, platform_filter=None, os_version_filter=None,
                    status_callback=None, progress_callback=None):
    """
    Process devices workflow - fetch, enrich, and filter devices.
    
    This function orchestrates the entire process of:
    1. Fetching devices vulnerable to a specific CVE
    2. Enriching them with detailed information
    3. Filtering based on platform and OS version
    
    Args:
        access_token (str): The Lookout API access token
        cve_id (str): The CVE ID to search for
        platform_filter (str, optional): Platform to filter by (e.g., 'ios', 'android')
        os_version_filter (str, optional): OS version to filter by (exact match)
        status_callback (callable, optional): Function to call with status updates
        progress_callback (callable, optional): Function to call with progress updates
        
    Returns:
        list or None: Filtered list of devices if successful, None if an error occurred
    """
    # Fetch vulnerable OS info
    vulnerable_os_info_list = fetch_vulnerable_os_info(access_token, cve_id, status_callback)
    
    if vulnerable_os_info_list is None:  # Error occurred during initial fetch
        return None
        
    if not vulnerable_os_info_list:
        if status_callback:
            status_callback(f"No devices found vulnerable to {cve_id} from the API.")
        else:
            print(f"No devices found vulnerable to {cve_id} from the API.")
        return []
    
    # Status update
    if status_callback:
        status_callback(f"Found {len(vulnerable_os_info_list)} device(s) with OS vulnerabilities for {cve_id}. Fetching full details...")
    else:
        print(f"Found {len(vulnerable_os_info_list)} device(s) with OS vulnerabilities for {cve_id}. Fetching full details...")
    
    # Enrich with device details
    enriched_devices = []
    for i, device_os_info in enumerate(vulnerable_os_info_list):
        guid = device_os_info.get("guid")
        if not guid:
            if status_callback:
                status_callback(f"Skipping device entry {i+1} due to missing GUID.", is_error=True)
            else:
                print(f"Skipping device entry {i+1} due to missing GUID.", file=sys.stderr)
            continue
        
        detailed_info = fetch_device_details_by_guid(
            access_token, guid, status_callback, progress_callback, i, len(vulnerable_os_info_list)
        )
        
        if detailed_info:
            # Merge os_info with detailed_info
            merged_info = {**device_os_info}  # Start with OS info
            merged_info["email"] = detailed_info.get("email")
            merged_info["customer_device_id"] = detailed_info.get("customer_device_id")
            hardware_info = detailed_info.get("hardware", {})
            merged_info["device_model"] = hardware_info.get("model")
            enriched_devices.append(merged_info)
        else:
            # If fetching details fails, we might still want to include the OS info
            if status_callback:
                status_callback(f"Could not fetch full details for GUID {guid}. Including OS info only.", is_error=True)
            else:
                print(f"Could not fetch full details for GUID {guid}. Including OS info only.", file=sys.stderr)
            enriched_devices.append(device_os_info)  # Add with available data
    
    # Filter devices
    filtered_devices = filter_devices(enriched_devices, platform_filter, os_version_filter, status_callback)
    
    return filtered_devices

# ===== CLI INTERFACE =====

def run_cli(args):
    """
    Run the application in CLI mode.
    
    Args:
        args (Namespace): Command line arguments parsed by argparse
        
    Returns:
        int: Exit code (0 for success, 1 for failure)
    """
    # Load environment variables
    load_dotenv()
    
    # Get API key
    api_key = os.getenv("LOOKOUT_APPLICATION_KEY")
    if not api_key or api_key == "YOUR_LOOKOUT_APPLICATION_KEY_HERE":
        print("Error: LOOKOUT_APPLICATION_KEY not found or not set in .env file.", file=sys.stderr)
        return 1
    
    # Get access token
    access_token = get_lookout_access_token(api_key)
    if not access_token:
        return 1
    
    # Process devices
    filtered_devices = process_devices(
        access_token, args.cve, args.platform, args.os_version
    )
    
    if filtered_devices is None:  # Error occurred
        return 1
    
    # Export to CSV
    output_filename = args.output or os.getenv("DEFAULT_OUTPUT_FILENAME") or DEFAULT_CSV_FILENAME
    if export_to_csv(filtered_devices, output_filename):
        return 0
    else:
        return 1

# ===== GUI INTERFACE =====

def create_gui_layout():
    """
    Create the PySimpleGUI layout for the application.
    
    Returns:
        list: PySimpleGUI layout definition
    """
    # No theme setting - work with default appearance
    
    # Define the table columns
    table_headings = ['GUID', 'Email', 'Customer ID', 'Platform', 'Model', 'OS Version', 'Latest OS', 'Security Patch']
    
    # Input section
    input_section = [
        [sg.Text('CVE ID:', size=(12, 1)), 
         sg.InputText(key='-CVE-', size=(30, 1)), 
         sg.Button('Fetch Data', key='-FETCH-')],
        [sg.Text('Platform:', size=(12, 1)), 
         sg.Combo(['', 'ios', 'android'], default_value='', key='-PLATFORM-', size=(28, 1))],
        [sg.Text('OS Version:', size=(12, 1)), 
         sg.InputText(key='-OS_VERSION-', size=(30, 1))],
        [sg.Text('Output File:', size=(12, 1)), 
         sg.InputText(default_text=DEFAULT_CSV_FILENAME, key='-OUTPUT-', size=(30, 1)),
         sg.Button('Browse...', key='-BROWSE-')],
        [sg.HSeparator()],
    ]
    
    # Progress section
    progress_section = [
        [sg.Text('Status:')],
        [sg.Multiline(size=(80, 5), key='-STATUS-', autoscroll=True, disabled=True)],
        [sg.ProgressBar(100, orientation='h', size=(80, 20), key='-PROGRESS-')],
        [sg.HSeparator()],
    ]
    
    # Results table
    results_section = [
        [sg.Text('Results:')],
        [sg.Table(values=[], headings=table_headings, 
                 auto_size_columns=False,
                 col_widths=[10, 20, 10, 8, 15, 10, 10, 15],
                 justification='left',
                 num_rows=15,
                 key='-TABLE-',
                 enable_events=True,
                 enable_click_events=True,
                 tooltip='Results Table')],
        [sg.Text('Filter:'), 
         sg.InputText(key='-FILTER-', size=(30, 1)), 
         sg.Button('Apply', key='-APPLY_FILTER-'), 
         sg.Button('Clear Filter', key='-CLEAR_FILTER-')],
        [sg.HSeparator()],
    ]
    
    # Action buttons
    action_section = [
        [sg.Button('Export to CSV', key='-EXPORT-'), 
         sg.Button('Clear Results', key='-CLEAR-'), 
         sg.Button('Exit')]
    ]
    
    # Combine all sections
    layout = [
        [sg.Text('Lookout CVE Reporter', font=('Helvetica', 16))],
        *input_section,
        *progress_section,
        *results_section,
        *action_section
    ]
    
    return layout

def update_status(window, message, is_error=False):
    """
    Update the status display in the GUI.
    
    Args:
        window (sg.Window): The PySimpleGUI window object
        message (str): The status message to display
        is_error (bool, optional): Whether this is an error message
    """
    if is_error:
        window['-STATUS-'].print(f"ERROR: {message}", text_color='red')
    else:
        window['-STATUS-'].print(message)
    window.refresh()

def update_progress(window, value):
    """
    Update the progress bar in the GUI.
    
    Args:
        window (sg.Window): The PySimpleGUI window object
        value (float): Progress value (0-100)
    """
    window['-PROGRESS-'].update(value)
    window.refresh()

def update_table(window, devices):
    """
    Update the results table with device data.
    
    Args:
        window (sg.Window): The PySimpleGUI window object
        devices (list): List of device dictionaries to display
    """
    table_data = []
    for device in devices:
        row = [
            device.get('guid', ''),
            device.get('email', ''),
            device.get('customer_device_id', ''),
            device.get('platform', ''),
            device.get('device_model', ''),
            device.get('os_version', ''),
            device.get('latest_os_version', ''),
            device.get('security_patch_level', '')
        ]
        table_data.append(row)
    
    window['-TABLE-'].update(values=table_data)

def filter_table_data(window, devices, filter_text):
    """
    Filter the table data based on the filter text.
    
    Args:
        window (sg.Window): The PySimpleGUI window object
        devices (list): List of device dictionaries to filter
        filter_text (str): Text to filter by (case-insensitive)
    """
    if not filter_text:
        update_table(window, devices)
        return
    
    filter_text = filter_text.lower()
    filtered_devices = []
    
    for device in devices:
        # Check if any field contains the filter text
        for key, value in device.items():
            if value and filter_text in str(value).lower():
                filtered_devices.append(device)
                break
    
    update_table(window, filtered_devices)
    update_status(window, f"Filtered to {len(filtered_devices)} devices matching '{filter_text}'")

def fetch_data_thread(window, values):
    """
    Thread function to fetch data without freezing the GUI.
    
    This function runs in a separate thread to keep the GUI responsive
    while fetching data from the Lookout API.
    
    Args:
        window (sg.Window): The PySimpleGUI window object
        values (dict): Values from the GUI form
    """
    # Load environment variables
    load_dotenv()
    
    # Get API key
    api_key = os.getenv("LOOKOUT_APPLICATION_KEY")
    if not api_key or api_key == "YOUR_LOOKOUT_APPLICATION_KEY_HERE":
        update_status(window, "LOOKOUT_APPLICATION_KEY not found or not set in .env file.", is_error=True)
        window.write_event_value('-THREAD_DONE-', {'success': False})
        return
    
    # Get access token
    access_token = get_lookout_access_token(
        api_key, 
        lambda msg, is_error=False: window.write_event_value('-STATUS_UPDATE-', {'message': msg, 'is_error': is_error})
    )
    
    if not access_token:
        window.write_event_value('-THREAD_DONE-', {'success': False})
        return
    
    # Process devices
    filtered_devices = process_devices(
        access_token, 
        values['-CVE-'], 
        values['-PLATFORM-'] if values['-PLATFORM-'] else None,
        values['-OS_VERSION-'] if values['-OS_VERSION-'] else None,
        lambda msg, is_error=False: window.write_event_value('-STATUS_UPDATE-', {'message': msg, 'is_error': is_error}),
        lambda value: window.write_event_value('-PROGRESS_UPDATE-', {'value': value})
    )
    
    if filtered_devices is None:  # Error occurred
        window.write_event_value('-THREAD_DONE-', {'success': False})
    else:
        window.write_event_value('-THREAD_DONE-', {'success': True, 'devices': filtered_devices})

def run_gui():
    """
    Run the application in GUI mode.
    
    Returns:
        int: Exit code (0 for success)
    """
    layout = create_gui_layout()
    window = sg.Window('Lookout CVE Reporter', layout, finalize=True, resizable=True)
    
    # Initialize variables
    all_devices = []
    
    # Event loop
    while True:
        event, values = window.read()
        
        if event == sg.WIN_CLOSED or event == 'Exit':
            break
            
        elif event == '-FETCH-':
            # Validate input
            if not values['-CVE-']:
                update_status(window, "Please enter a CVE ID", is_error=True)
                continue
                
            # Clear previous results
            all_devices = []
            update_table(window, [])
            update_status(window, f"Fetching data for CVE: {values['-CVE-']}...")
            window['-PROGRESS-'].update(0)
            
            # Start the fetch thread
            threading.Thread(
                target=fetch_data_thread, 
                args=(window, values), 
                daemon=True
            ).start()
            
        elif event == '-STATUS_UPDATE-':
            update_status(window, values[event]['message'], values[event]['is_error'])
            
        elif event == '-PROGRESS_UPDATE-':
            update_progress(window, values[event]['value'])
            
        elif event == '-THREAD_DONE-':
            if values[event]['success']:
                all_devices = values[event]['devices']
                update_table(window, all_devices)
                update_status(window, f"Found {len(all_devices)} devices matching the criteria")
                update_progress(window, 100)
            else:
                update_status(window, "Operation failed. See errors above.", is_error=True)
                update_progress(window, 0)
                
        elif event == '-APPLY_FILTER-':
            filter_table_data(window, all_devices, values['-FILTER-'])
            
        elif event == '-CLEAR_FILTER-':
            window['-FILTER-'].update('')
            update_table(window, all_devices)
            update_status(window, "Filter cleared")
            
        elif event == '-EXPORT-':
            if not all_devices:
                update_status(window, "No data to export", is_error=True)
                continue
                
            output_filename = values['-OUTPUT-'] or DEFAULT_CSV_FILENAME
            if export_to_csv(
                all_devices, 
                output_filename, 
                lambda msg, is_error=False: update_status(window, msg, is_error)
            ):
                update_status(window, f"Successfully exported {len(all_devices)} devices to {output_filename}")
                
        elif event == '-BROWSE-':
            try:
                filename = sg.popup_get_file('Save As', save_as=True, default_extension=".csv")
                if filename:
                    window['-OUTPUT-'].update(filename)
            except Exception as e:
                update_status(window, f"Error with file browser: {e}. Please type the filename manually.", is_error=True)
                
        elif event == '-CLEAR-':
            all_devices = []
            update_table(window, [])
            update_status(window, "Results cleared")
            update_progress(window, 0)
    
    window.close()
    return 0

# ===== MAIN ENTRY POINT =====

def main():
    """
    Main function to orchestrate the script.
    
    Parses command line arguments and determines whether to run in CLI or GUI mode.
    
    Returns:
        int: Exit code (0 for success, non-zero for failure)
    """
    parser = argparse.ArgumentParser(description="Fetch Lookout CVE vulnerable devices.")
    parser.add_argument("--gui", action="store_true", help="Launch in GUI mode")
    parser.add_argument("--cve", help="CVE ID (e.g., CVE-2023-12345)")
    parser.add_argument("--platform", choices=["ios", "android"], help="Filter by platform (iOS or Android)")
    parser.add_argument("--os-version", help="Filter by OS version (exact match)")
    parser.add_argument("--output", help="Output CSV filename")
    
    args = parser.parse_args()
    
    # If --gui is specified or no arguments are provided, run in GUI mode
    if args.gui or (len(sys.argv) == 1):
        return run_gui()
    elif not args.cve:
        parser.error("the --cve argument is required when not using GUI mode")
    else:
        return run_cli(args)

if __name__ == "__main__":
    sys.exit(main())