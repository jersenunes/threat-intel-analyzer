import os
from pathlib import Path
from dotenv import load_dotenv

#Set .env variables
load_dotenv()
API_SECRET_VIRUS_TOTAL = os.getenv('API_SECRET_VIRUS_TOTAL')
API_SECRET_ABUSE_IPDB = os.getenv('API_SECRET_ABUSE_IPDB')
API_SECRET_OTX_ALIENVAULT = os.getenv('API_SECRET_OTX_ALIENVAULT')

#Set context
INDICATORS_TYPE = ['json', 'ip', 'domain', 'url', 'hash', 'file']
PULSE_TAGS = ['malware', 'backdoor', 'ransom', 'malicious']
PROVIDERS = {
        'VirusTotal': ['virustotal', 'vt'],
        'AbuseIPDB': ['abuseipdb', 'aipdb', 'abuse'],
        'OTXAlienVault': ['otxalienvault', 'alienvault', 'otx', 'otxav']
    }
USAGE_MESSAGE = "Usage: python main.py json=examples/inputs_file.json" \
                "Usage: python main.py ip=1.1.1.1" \
                "Usage: python main.py ip=1.1.1.1 provider=abuse" \
                "Usage: python main.py domain=google.com provider=virustotal" \
                "Usage: python main.py url=https://www.youtube.com provider=otx" \
                "Usage: python main.py hash=23792BDD1136C3A69AD6A5BDC0914A45 provider=alienvault" \
                "Usage: python main.py file=examples/file.pdf provider=vt"

#Set paths
ROOT_FOLDER = Path(__file__).parent.parent
EXAMPLES_INPUT = ROOT_FOLDER / 'examples'
INDICATORS_OUTPUT = ROOT_FOLDER / 'output' / 'indicators_output.json'