import os
from pathlib import Path
from dotenv import load_dotenv

#Set .env variables
load_dotenv()
API_SECRET_VIRUS_TOTAL = os.getenv('API_SECRET_VIRUS_TOTAL')
API_SECRET_ABUSE_IPDB = os.getenv('API_SECRET_ABUSE_IPDB')

#Set paths
ROOT_FOLDER = Path(__file__).parent.parent
EXAMPLES_INPUT = ROOT_FOLDER / 'examples'
INDICATORS_OUTPUT = ROOT_FOLDER / 'output' / 'indicators_output.json'