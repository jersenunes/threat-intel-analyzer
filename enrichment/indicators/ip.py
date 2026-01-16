from enrichment.providers.abuse_ipdb import AbuseIPDB
from enrichment.providers.otx_alienvault import OTXAlientVault
from enrichment.providers.virus_total import VirusTotal
from typing import List


def check_ip(indicators: str | List[str], provider: None | str):
    if 'VirusTotal' == provider or not provider:
        search_VT = VirusTotal()
        if isinstance(indicators, str):
            search_VT.verify_ip(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_VT.verify_ip(indicator=indicator)
        
        else:
            raise ValueError(f"Indicator type not supported.")
        
    if 'AbuseIPDB' == provider or not provider:
        search_AIPDB = AbuseIPDB()
        if isinstance(indicators, str):
            search_AIPDB.verify_ip(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_AIPDB.verify_ip(indicator=indicator)
        
        else:
            raise ValueError(f"Indicator type not supported.")

    if 'OTXAlienVault' == provider or not provider:
        search_otx = OTXAlientVault()
        if isinstance(indicators, str):
            search_otx.verify_ip(indicator=indicators)

        elif isinstance(indicators, List):
            for indicator in indicators:
                search_otx.verify_ip(indicator=indicator)
        
        else:
            print("Indicator type not supported.")

    if 'Teste' == provider:
        print("Provider type not supported.")

                