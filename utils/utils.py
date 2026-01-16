# type: ignore
import json
import ipaddress
from configs.settings import *
from typing import Dict, List
from pathlib import Path


def get_ip_version(ip: str) -> int | None:
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.version
    except ValueError:
        return None


def read_file(path:Path) -> None | List | str:
    try:
        if not os.path.exists(path.parent):
            return None

        with open(path, 'r', encoding='UTF-8') as f:
            file = f.readlines()
        
        if file:
            return file
        
    except Exception as e:
        print(f"ERROR: {e}.")


def save_a_json(path:Path, args:Dict | List) -> None:
    try:
        json_output = {}

        if not path.parent.exists():
            path.parent.mkdir(parents=True, exist_ok=True)

        if os.path.exists(path):
            with open(path, 'r') as file:
                try:
                    json_output = json.load(file)
                except:
                    pass
    
        if json_output.get('indicators'):
            if json_output.get('indicators').get(args.get('indicator_type')):
                json_output.get('indicators').get(args.get('indicator_type')).append(args)
            else:
                json_output.get('indicators').update({args.get('indicator_type'): [args]})
        else:
            json_output.update({'indicators':{args.get('indicator_type'): [args]}})

        with open(path, 'w') as file:            
            json.dump(json_output, file, ensure_ascii=True, indent=2)

    except Exception as e:
        print(f"ERROR: {e}.")


def read_a_json(path:Path | str) -> Dict:
    try:
        with open(path, 'r') as file:
            json_data = json.load(file)
        return json_data
    
    except FileNotFoundError:
        print(f"File not found: {path}")
        return {}
    
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON {path}: {e}")
        return {}