from enrichment.providers.abuse_ipdb import AbuseIPDB
from enrichment.providers.virus_total import VirusTotal
from typing import List


def check_ip(indicators: str | List[str], providers:List = []):
    if 'VirusTotal' in providers or not providers:
        search_VT = VirusTotal()
        if isinstance(indicators, str):
            search_VT.verify_ip(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_VT.verify_ip(indicator=indicator)
        
        else:
            raise ValueError(f"Indicator type not supported.")
        
    if 'AbuseIPDB' in providers or not providers:
        search_AIPDB = AbuseIPDB()
        if isinstance(indicators, str):
            search_AIPDB.verify_ip(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_AIPDB.verify_ip(indicator=indicator)
        
        else:
            raise ValueError(f"Indicator type not supported.")

    if 'Teste' in providers:
        raise ValueError(f"Provider type not supported.")
                