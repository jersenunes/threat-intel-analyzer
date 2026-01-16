from configs.settings import *
from enrichment.providers.otx_alienvault import OTXAlientVault
from enrichment.providers.virus_total import VirusTotal
from typing import List


def check_file(indicators: str | Path | List[Path], provider: None | str):
    if 'VirusTotal' == provider or not provider:
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

    if 'OTXAlienVault' == provider or not provider:
        search_otx = OTXAlientVault()
        if isinstance(indicators, Path):
            search_otx.verify_file(indicator=indicators)
        
        elif isinstance(indicators, str):
            path = EXAMPLES_INPUT / indicators
            search_otx.verify_file(indicator=path)

        elif isinstance(indicators, List):
            for indicator in indicators:
                path = EXAMPLES_INPUT / indicator
                search_otx.verify_file(indicator=path)
        
        else:
            print("Indicator type not supported.")

    if 'AbuseIPDB' == provider:
        print("Provider type not supported.")
