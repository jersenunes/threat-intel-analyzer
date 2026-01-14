# type: ignore
from enrichment.providers.virus_total import VirusTotal
from typing import List


def check_hash(indicators: str | List[str], providers:List = []):
    if 'VirusTotal' in providers or not providers:
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

    if 'AbuseIPDB' in providers:
        raise ValueError(f"Provider type not supported.")
                