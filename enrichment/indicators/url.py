from enrichment.providers.virus_total import VirusTotal
from typing import List


def check_url(indicators: str | List[str], providers:List = []):
    if 'VirusTotal' in providers or not providers:
        search_VT = VirusTotal()
        if isinstance(indicators, str):
            search_VT.verify_url(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_VT.verify_url(indicator=indicator)
        
        else:
            raise ValueError(f"Indicator type not supported.")

    if 'AbuseIPDB' in providers:
        raise ValueError(f"Provider type not supported.")
                