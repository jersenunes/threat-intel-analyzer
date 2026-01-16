# type: ignore
from enrichment.providers.otx_alienvault import OTXAlientVault
from enrichment.providers.virus_total import VirusTotal
from typing import List

provider = ['VirusTotal', 'AlientVault']

def check_hash(indicators: str | List[str], provider: None | str):
    if 'VirusTotal' == provider or not provider:
        search_VT = VirusTotal()
        if isinstance(indicators, str):
            search_VT.verify_hash(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                if isinstance(indicator, dict):
                    search_VT.verify_hash(indicator=indicator.get('value'))
                elif isinstance(indicator, str):
                    search_VT.verify_hash(indicator=indicator)
        
        else:
            raise ValueError(f"Indicator type not supported.")

    if 'OTXAlienVault' == provider or not provider:
        search_otx = OTXAlientVault()
        if isinstance(indicators, str):
            search_otx.verify_hash(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                if isinstance(indicator, dict):
                    search_otx.verify_hash(indicator=indicator.get('value'))
                elif isinstance(indicator, str):
                    search_otx.verify_hash(indicator=indicator)
        
        else:
            print("Indicator type not supported.")

    if 'AbuseIPDB' == provider:
        print("Provider type not supported.")
                