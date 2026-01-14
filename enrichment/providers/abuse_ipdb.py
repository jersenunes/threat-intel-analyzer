# type: ignore
import time
from configs.settings import *
from core.http.client import HTTPClient
from enrichment.normalizer import parse_response
from typing import Dict
from utils.utils import *


class AbuseIPDB:
    def __init__(self) -> None:
        self.__endpoint_url = "https://api.abuseipdb.com/api/v2/check"
        self.__headers = {
                "Accept": "application/json",
                "Key": API_SECRET_ABUSE_IPDB
                }
        

    def verify_ip(self, indicator: str) -> None:
        querystring = {
            'ipAddress': indicator,
            'maxAgeInDays': '30'
            }
        
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=self.__endpoint_url, params=querystring)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='ip', source='AbuseIPDB')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)
