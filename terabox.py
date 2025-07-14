import uuid
import requests
import os
import sys
import json
import hashlib
import argparse
import re
import time
import getpass
from tqdm import tqdm
from tbox_crypto import init_db, save_key, get_key_data, list_keys, encrypt_file, decrypt_file, generate_strong_password
from tbox_auth import login_and_add_account, get_account_data
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

class TeraboxManager:
    """A class to manage all API interactions with Terabox."""

    def __init__(self, cookies, js_token, account_label):
        self.session = requests.Session()
        self.session.cookies.update(cookies)
        self.account_label = account_label
        
        # --- Using the dynamic, scraped tokens ---
        self.bds_token = cookies.get('csrfToken')
        self.js_token = js_token
        
        if not self.bds_token or not self.js_token:
            raise ValueError(f"Incomplete authentication tokens for account '{account_label}'. Please log in again using the 'add' command.")

        self.base_headers = {
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/137.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*', 'X-Requested-With': 'XMLHttpRequest',
            'Origin': 'https://1024terabox.com',
        }
    
    # ... All other manager functions (track, ls, mkdir, etc.) are identical ...
    def _track_task(self, taskid):
        print(f"Tracking task ID: {taskid}... ", end="", flush=True)
        while True:
            try:
                url = "https://1024terabox.com/share/taskquery"
                params = {'taskid': taskid, 'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token}
                res = self.session.get(url, params=params, headers=self.base_headers, verify=False)
                res.raise_for_status(); data = res.json(); status = data.get('status')
                if status == 'success': print("Success!"); return data
                elif status in ['running', 'pending']: print(".", end="", flush=True); time.sleep(2)
                else: print(f"Failed! Reason: {data.get('task_errno', 'Unknown error')}"); return None
            except Exception as e: print(f"\nError tracking task: {e}"); return None

    def list_files(self, path):
        print(f"Listing contents of '{path}'...")
        params = {'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token, 'order': 'time', 'desc': '1', 'dir': path, 'num': '100', 'page': '1', 'showempty': '0'}
        headers = {**self.base_headers, 'Referer': 'https://1024terabox.com/main?category=all'}
        try:
            res = self.session.get('https://1024terabox.com/api/list', params=params, headers=headers, verify=False)
            res.raise_for_status(); data = res.json()
            if data.get("errno") == 0:
                if not data.get("list"): print("Directory is empty or does not exist."); return
                print("-" * 60); print(f"{'Type':<5} {'Size':>10}   {'Filename'}"); print("-" * 60)
                for item in data["list"]:
                    item_type = "[D]" if item["isdir"] == 1 else "[F]"; size_mb = item.get("size", 0) / (1024*1024); size_str = f"{size_mb:,.2f} MB" if size_mb > 0 else "-"
                    print(f"{item_type:<5} {size_str:>10}   {item['server_filename']}")
                print("-" * 60)
            else: print(f"Error listing files: {data}")
        except Exception as e: print(f"An error occurred: {e}")

    def create_folder(self, path):
        print(f"Creating folder: {path}...")
        params = {'a': 'commit', 'bdstoken': self.bds_token, 'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token}
        data = {'path': path, 'isdir': '1', 'block_list': '[]'}
        headers = {**self.base_headers, 'Referer': 'https://1024terabox.com/main?category=all', 'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            res = self.session.post('https://1024terabox.com/api/create', params=params, data=data, headers=headers, verify=False)
            res.raise_for_status(); res_data = res.json()
            if res_data.get("errno") == 0: print(f"✅ Successfully created folder '{res_data.get('path')}'.")
            else: print(f"❌ Error creating folder: {res_data}")
        except Exception as e: print(f"An error occurred: {e}")

    def move_or_copy(self, source, dest, operation='move'):
        print(f"{operation.capitalize()}ing '{source}' to '{dest}'...")
        if not dest.endswith('/'): dest += '/'
        filelist = json.dumps([{"path": source, "dest": dest, "newname": os.path.basename(source)}])
        params = {'async': '2', 'onnest': 'fail', 'bdstoken': self.bds_token, 'opera': operation, 'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token}
        data = {'filelist': filelist}; headers = {**self.base_headers, 'Referer': 'https://1024terabox.com/main?category=all', 'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            res = self.session.post('https://1024terabox.com/api/filemanager', params=params, data=data, headers=headers, verify=False)
            res.raise_for_status(); res_data = res.json()
            if res_data.get("errno") == 0 and 'taskid' in res_data: self._track_task(res_data['taskid'])
            else: print(f"❌ Error initiating {operation}: {res_data}")
        except Exception as e: print(f"An error occurred: {e}")

    def delete(self, paths):
        print(f"Deleting: {', '.join(paths)}...")
        filelist = json.dumps(paths); params = {'async': '2', 'onnest': 'fail', 'bdstoken': self.bds_token, 'opera': 'delete', 'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token}
        data = {'filelist': filelist}; headers = {**self.base_headers, 'Referer': 'https://1024terabox.com/main?category=all', 'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            res = self.session.post('https://1024terabox.com/api/filemanager', params=params, data=data, headers=headers, verify=False)
            res.raise_for_status(); res_data = res.json()
            if res_data.get("errno") == 0 and 'taskid' in res_data: self._track_task(res_data['taskid'])
            else: print(f"❌ Error initiating delete: {res_data}")
        except Exception as e: print(f"An error occurred: {e}")
            
    def upload(self, file_path):
        if not os.path.exists(file_path): print(f"Upload Error: File not found at '{file_path}'"); return False
        chunk_size = 4 * 1024 * 1024; file_size = os.path.getsize(file_path); file_name = os.path.basename(file_path)
        try:
            print(f"Step 1: Pre-allocating file '{file_name}' on server...")
            with open(file_path, 'rb') as f: first_chunk_for_md5 = f.read(256 * 1024)
            md5_hash = hashlib.md5(first_chunk_for_md5).hexdigest()
            precreate_params = {'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token, 'dp-logid': '71171000921377310030'}
            precreate_data = {'path': f"/{file_name}", 'size': str(file_size), 'autoinit': '1', 'target_path': '/', 'block_list': json.dumps([md5_hash, "a5fc157d78e6ad1c7e114b056c92821e"]), 'file_limit_switch_v34': 'true', 'g_identity': '', 'local_mtime': '1752338659'}
            precreate_headers = {**self.base_headers, 'Referer': 'https://1024terabox.com/main?category=all', 'Content-Type': 'application/x-www-form-urlencoded'}
            precreate_response = self.session.post('https://1024terabox.com/api/precreate', params=precreate_params, data=precreate_data, headers=precreate_headers, verify=False)
            precreate_response.raise_for_status(); precreate_json = precreate_response.json()
            if precreate_json.get("errno") != 0:
                print(f"Precreate failed: {precreate_json}")
                if precreate_json.get("errno") == -6: 
                     print(f"This error (-6) often means your login session for account '{self.account_label}' has expired. Please refresh it by running:\n   python terabox.py add {self.account_label.split(' ')[0]}")
                return False
            
            upload_id = precreate_json.get("uploadid"); remote_path = precreate_json.get("path"); block_md5_list = []
            
            print("Step 2: Uploading file data...")
            upload_headers = {**self.base_headers, 'Referer': 'https://1024terabox.com/'}
            with open(file_path, 'rb') as f:
                with tqdm(total=file_size, unit='B', unit_scale=True, unit_divisor=1024, desc="Uploading") as progress_bar:
                    while True:
                        chunk = f.read(chunk_size)
                        if not chunk: break
                        upload_params = {'method': 'upload', 'app_id': '250528', 'path': remote_path, 'uploadid': upload_id, 'partseq': progress_bar.n // chunk_size}
                        files = {'file': (file_name, chunk, 'application/octet-stream')}
                        upload_response = self.session.post("https://c-jp.1024terabox.com/rest/2.0/pcs/superfile2", params=upload_params, files=files, headers=upload_headers, verify=False)
                        upload_response.raise_for_status(); md5_from_server = upload_response.json().get('md5'); block_md5_list.append(md5_from_server)
                        progress_bar.update(len(chunk))
            
            print("Step 3: Committing file on server...")
            create_params = {'isdir': '0', 'rtype': '1', 'bdstoken': self.bds_token, 'app_id': '250528', 'web': '1', 'channel': 'dubox', 'clienttype': '0', 'jsToken': self.js_token, 'dp-logid': '71171000921377310031'}
            create_payload = {'path': remote_path, 'size': str(file_size), 'uploadid': upload_id, 'target_path': "/", 'block_list': json.dumps(block_md5_list), 'local_mtime': "1752338659"}
            create_headers = {**self.base_headers, 'Referer': "https://1024terabox.com/main?category=all", 'Content-Type': 'application/x-www-form-urlencoded'}
            create_response = self.session.post("https://1024terabox.com/api/create", params=create_params, data=create_payload, headers=create_headers, verify=False)
            create_response.raise_for_status(); create_json = create_response.json()
            if create_json.get("errno") != 0: print(f"File creation failed: {create_json}"); return False
            
            print("\n✅ Upload Complete!")
            return True
        except Exception as e: print(f"\nAn error occurred during upload: {e}"); return False

def main():
    parser = argparse.ArgumentParser(description="A command-line interface for secure Terabox uploads and file management.")
    account_group = parser.add_mutually_exclusive_group()
    account_group.add_argument('-p', '--primary', action='store_true', help='Use the primary account (default).')
    account_group.add_argument('-s', '--secondary', type=int, metavar='N', help='Use the Nth secondary account (e.g., -s 1 for the first).')
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="Available commands")

    add_parser = subparsers.add_parser("add", help="Add a new primary or secondary account via automated browser login.")
    add_parser.add_argument("role", choices=['primary', 'secondary'], help="The role of the account to add.")
    
    upload_parser = subparsers.add_parser("upload", help="Upload a file with flexible encryption options.")
    upload_parser.add_argument("local_path", help="The path to the local file to upload.")
    upload_group = upload_parser.add_mutually_exclusive_group()
    upload_group.add_argument("-s", "--secure", action="store_true", help="Force secure, encrypted upload.")
    upload_group.add_argument("-i", "--insecure", action="store_true", help="Force insecure, direct upload.")

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a local file downloaded from Terabox.")
    decrypt_parser.add_argument("local_path", help="The path to the local .enc file.")
    subparsers.add_parser("keys", help="List all stored file encryption keys from the local database.")
    ls_parser = subparsers.add_parser("ls", help="List files and directories in a Terabox path.")
    ls_parser.add_argument("remote_path", nargs="?", default="/", help="The remote path to list (default: root '/').")
    mkdir_parser = subparsers.add_parser("mkdir", help="Create a directory on Terabox.")
    mkdir_parser.add_argument("remote_path", help="The full path of the directory to create.")
    mv_parser = subparsers.add_parser("mv", help="Move a file or directory on Terabox.")
    mv_parser.add_argument("source", help="The source path of the file/directory.")
    mv_parser.add_argument("destination", help="The destination directory path.")
    cp_parser = subparsers.add_parser("cp", help="Copy a file or directory on Terabox.")
    cp_parser.add_argument("source", help="The source path of the file/directory.")
    cp_parser.add_argument("destination", help="The destination directory path.")
    rm_parser = subparsers.add_parser("rm", help="Delete one or more files/directories on Terabox.")
    rm_parser.add_argument("paths", nargs="+", help="One or more remote paths to delete.")

    args = parser.parse_args()
    init_db()

    if args.command == "add":
        email = input(f"Enter the email for the new '{args.role}' account: ")
        password = getpass.getpass("Enter the password (will not be shown): ")
        login_and_add_account(args.role, email, password)
        return

    account_role = 'primary'; account_index = 0; account_label = 'primary'
    if args.secondary:
        account_role = 'secondary'; account_index = args.secondary - 1
        account_label = f'secondary account #{args.secondary}'
    
    # --- Using the new get_account_data function ---
    account_data = get_account_data(account_role, account_index)
    if not account_data or 'cookies' not in account_data or 'js_token' not in account_data:
        print(f"❌ Incomplete or missing data for {account_label}. Please refresh the session:")
        print(f"   python terabox.py add {('secondary' if args.secondary else 'primary')}")
        sys.exit(1)

    print(f"--- Operating on {account_label} account ---")
    manager = TeraboxManager(account_data['cookies'], account_data['js_token'], account_label)

    if args.command == "upload":
        secure_upload = False
        if args.secure: secure_upload = True
        elif args.insecure: secure_upload = False
        else:
            choice = input("Upload with encryption? (y/n): ").lower()
            if choice == 'y': secure_upload = True
        
        if secure_upload:
            print("--- Starting Secure Upload ---")
            original_path = args.local_path
            if not os.path.exists(original_path): print(f"Error: Local file not found at '{original_path}'"); return
            password = generate_strong_password()
            print("\n" + "*"*60 + "\nIMPORTANT: Your randomly generated password for this file is:\n\n" + f"    {password}\n\n" + "It has been saved to passwords.db. Please back up passwords.db!" + "\n" + "*"*60 + "\n")
            file_uuid = str(uuid.uuid4()); original_basename = os.path.basename(original_path)
            encrypted_filename = f"{os.path.splitext(original_basename)[0]}.[{file_uuid}].enc"
            encrypted_filepath = os.path.join(os.path.dirname(original_path), encrypted_filename)
            if encrypt_file(original_path, encrypted_filepath, password):
                save_key(file_uuid, original_basename, password)
                if manager.upload(encrypted_filepath):
                    cleanup = input(f"Delete local encrypted file '{encrypted_filepath}'? (y/n): ").lower()
                    if cleanup == 'y': os.remove(encrypted_filepath); print("Local encrypted file deleted.")
        else:
            print("--- Starting Insecure Upload ---")
            manager.upload(args.local_path)
    
    elif args.command == "decrypt":
        encrypted_path = args.local_path
        if not os.path.exists(encrypted_path): print(f"Error: Local file not found at '{encrypted_path}'"); return
        filename = os.path.basename(encrypted_path); match = re.search(r"\[([a-f0-9\-]+)\]\.enc$", filename)
        if not match: print("Error: Could not find a UUID in the filename. Format: 'filename.[uuid].enc'"); return
        file_uuid = match.group(1); password, original_name = get_key_data(file_uuid)
        if not password: print(f"Error: No password found in the database for ID: {file_uuid}"); return
        print(f"Found key. Original filename was '{original_name}'.")
        decrypted_path = os.path.join(os.path.dirname(encrypted_path), original_name)
        decrypt_file(encrypted_path, decrypted_path, password)
        
    elif args.command == "keys": list_keys()
    elif args.command == "ls": manager.list_files(args.remote_path)
    elif args.command == "mkdir": manager.create_folder(args.remote_path)
    elif args.command == "mv": manager.move_or_copy(args.source, args.destination, 'move')
    elif args.command == "cp": manager.move_or_copy(args.source, args.destination, 'copy')
    elif args.command == "rm": manager.delete(args.paths)

if __name__ == "__main__":
    main()
