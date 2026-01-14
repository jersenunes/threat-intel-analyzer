from configs.settings import *
from enrichment.providers.virus_total import VirusTotal
from typing import List

def check_file(indicators: str | Path | List[Path], providers:List = []):
    if 'VirusTotal' in providers or not providers:
        search_VT = VirusTotal()
        if isinstance(indicators, Path):
            search_VT.verify_file(indicator=indicators)
        
        elif isinstance(indicators, str):
            path = EXAMPLES_INPUT / indicators
            search_VT.verify_file(indicator=path)

        elif isinstance(indicators, List):
            for indicator in indicators:
                path = EXAMPLES_INPUT / indicator
                search_VT.verify_file(indicator=path)
        
        else:
            raise ValueError(f"Indicator type not supported.")

    if 'AbuseIPDB' in providers:
        raise ValueError(f"Provider type not supported.")
