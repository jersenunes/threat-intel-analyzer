# type: ignore
from configs.settings import *
from core.http.client import HTTPClient
from enrichment.normalizer import parse_response
from typing import Dict
from utils.utils import *


class OTXAlientVault:
    def __init__(self) -> None:        
        self.__endpoint_url_template = "https://otx.alienvault.com/api/v1/indicators/{type}/{indicator}/{section}"
        self.__headers = {
                "Accept": "application/json",
                "X-OTX-API-KEY": API_SECRET_OTX_ALIENVAULT
                }


    def __post_file(self, indicator) -> None:
        if not os.path.isfile(indicator):
            raise FileNotFoundError(f"File not found: {indicator}")
        
        endpoint_url = self.__endpoint_url_template.replace('{type}',f'submit_file').replace('/{indicator}','').replace('/{section}','')
        with open(indicator, "rb") as f:
            files = {"file": (indicator.name, f, "application/octet-stream")}
            client = HTTPClient(headers=self.__headers)
            response = client.post(url=endpoint_url, files=files)
        
        if response is None:
            return {
                "error": {
                    "code": "EmptyResponse",
                    "message": "No response returned from HTTP client"
                }
            }


        if isinstance(response, Dict):
            if response.get('error'):
                raise Exception(response.get('error'))
            return response.get('sha256')
    
    
    def verify_ip(self, indicator: str) -> None:
        ip_version = get_ip_version(indicator)
        endpoint_url = self.__endpoint_url_template.replace('{type}',f'IPv{ip_version}').replace('{indicator}',indicator).replace('{section}','general')
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=endpoint_url)

        with open('output/test_ip.json', 'w') as file:
            json.dump(response, file, ensure_ascii=True, indent=2)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='ip', source='OTXAlienVault')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)


    def verify_url(self, indicator: str) -> None:
        endpoint_url = self.__endpoint_url_template.replace('{type}','url').replace('{indicator}',indicator).replace('{section}','general')
        client = HTTPClient(headers=self.__headers)        
        response = client.get(url=endpoint_url)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='url', source='OTXAlienVault')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)


    def verify_domain(self, indicator: str) -> None:
        endpoint_url = self.__endpoint_url_template.replace('{type}','domain').replace('{indicator}',indicator).replace('{section}','general')
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=endpoint_url)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='domain', source='OTXAlienVault')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)
    

    def verify_hash(self, indicator: str) -> None:
        endpoint_url = self.__endpoint_url_template.replace('{type}','file').replace('{indicator}',indicator).replace('{section}','general')
        client = HTTPClient(headers=self.__headers)
        response = client.get(url=endpoint_url)

        if response.get('error'):
            print(response.get('error'))
            return None

        indicator_json = parse_response(response=response, indicator=indicator, type='hash', source='OTXAlienVault')

        if indicator_json:
            save_a_json(path=INDICATORS_OUTPUT, args=indicator_json)


    def verify_file(self, indicator: Path) -> None:
        indicator = self.__post_file(indicator=indicator)
        
        self.verify_hash(indicator)
