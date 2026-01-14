from enrichment.providers.virus_total import VirusTotal
from typing import List

def check_hash(indicators: str | List, providers:List = []):
    if 'VirusTotal' in providers or not providers:
        search_VT = VirusTotal()
        if isinstance(indicators, str):
            search_VT.verify_hash(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_VT.verify_hash(indicator=indicator.get('value'))
    
    if 'AbuseIPDB' in providers:
        raise ValueError(f'Indicator type not supported by the specified provider.')