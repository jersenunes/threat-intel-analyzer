# type: ignore
import time
from configs.settings import *
from core.http.client import HTTPClient
from enrichment.normalizer import parse_response
from typing import Dict
from utils.utils import *


class VirusTotal:
    def __init__(self) -> None:
        self.__endpoint_url_template = "https://www.virustotal.com/api/v3/{type}/{indicator}"
        self.__headers = {
                "accept": "application/json",
                "x-apikey": API_SECRET_VIRUS_TOTAL
                }
        

    def __post_url(self, indicator) -> None | str:
        payload = {"url": indicator}
        endpoint_url = self.__endpoint_url_template.replace('{type}','urls').replace('/{indicator}','')

        client = HTTPClient(headers=self.__headers)
        response = client.post(url=endpoint_url, data=payload)

        if isinstance(response, Dict):
            if response.get('error'):
                raise Exception(response.get('error'))

            elif response.get('data').get('id'):
                return response.get('data').get('id')


    def __post_file(self, indicator) -> None | str:
        if not os.path.isfile(indicator):
            raise FileNotFoundError(f"File not found: {indicator}")
        
        endpoint_url = self.__endpoint_url_template.replace('{type}','files').replace('/{indicator}','')
        with open(indicator, "rb") as f:
            files = {
                "file": (indicator.name, f, "application/octet-stream")
            }

            client = HTTPClient(headers=self.__headers)
            response = client.post(url=endpoint_url, files=files)

        if isinstance(response, Dict):
            if response.get('error'):
                raise Exception(response.get('error'))

            elif response.get('data').get('id'):
                return response.get('data').get('id')


    def verify_ip(self, indicator: str) -> None:
        endpoint_url = self.__endpoint_url_template.replace('{type}','ip_addresses').replace('{indicator}',indicator)
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=endpoint_url)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='ip', source='VirusTotal')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)


    def verify_url(self, indicator: str) -> None:
        analysis_id = self.__post_url(indicator=indicator)
        if analysis_id:
            response = None
            endpoint_url = self.__endpoint_url_template.replace('{type}','analyses').replace('{indicator}',analysis_id)
            analysis_status = ''

            client = HTTPClient(headers=self.__headers)
            for i in range(5):
                time.sleep(20)                
                response = client.get(url=endpoint_url)
                analysis_status = response.get('data').get('attributes').get('status')
                
                if analysis_status == "completed":
                    break
        if not response:
            return None

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='url', source='VirusTotal')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)


    def verify_domain(self, indicator: str) -> None:
        endpoint_url = self.__endpoint_url_template.replace('{type}','domains').replace('{indicator}',indicator)
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=endpoint_url)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='domain', source='VirusTotal')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)
    

    def verify_hash(self, indicator: str) -> None:        
        endpoint_url = self.__endpoint_url_template.replace('{type}','files').replace('{indicator}',indicator)
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=endpoint_url)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='hash', source='VirusTotal')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)

    
    def verify_file(self, indicator: Path) -> None:
        analysis_id = self.__post_file(indicator=indicator)
        if analysis_id:
            response = None
            endpoint_url = self.__endpoint_url_template.replace('{type}','analyses').replace('{indicator}',analysis_id)
            analysis_status = ''

            client = HTTPClient(headers=self.__headers)
            for i in range(5):
                time.sleep(20)                
                response = client.get(url=endpoint_url)
                analysis_status = response.get('data').get('attributes').get('status')

                if analysis_status == "completed":
                    break
            
            if not response:
                return None

            if response.get('error'):
                print(response.get('error'))
                return None

            indicator_json = parse_response(response=response, indicator=indicator.name, type='file', source='VirusTotal')

            if indicator_json:
                save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)
        else:
            raise Exception("Analysis ID Not Generated!")
