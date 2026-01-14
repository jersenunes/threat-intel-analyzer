import os
from enrichment.indicators.domain import check_domain
from enrichment.indicators.file import check_file
from enrichment.indicators.hash import check_hash
from enrichment.indicators.ip import check_ip
from enrichment.indicators.url import check_url
from utils.indicator_loader import load_indicators_from_json
    

def orchestrator(input: str):
    providers = []
    ip_list = []
    domain_list = []
    url_list = []
    hash_list = []
    file_list = []

    type, indicators = input.split('=')

    if type.lower() == "json":
        if os.path.isfile(indicators):
            indicators = load_indicators_from_json(indicators)
            ip_list = indicators["ip"]
            domain_list = indicators["domain"]
            url_list = indicators["url"]
            hash_list = indicators["hash"]
            file_list = indicators["file"]

    if type.lower() == "ip":
        ip_list.append(indicators)
    
    if type.lower() == "domain":
        domain_list.append(indicators)        
    
    if type.lower() == "url":
        url_list.append(indicators)        
    
    if type.lower() == "hash":
        hash_list.append(indicators)        
    
    if type.lower() == "file":
        file_list.append(indicators)        

    check_ip(indicators=ip_list, providers=providers)
    check_domain(indicators=domain_list, providers=providers)
    check_url(indicators=url_list, providers=providers)
    check_hash(indicators=hash_list, providers=providers)
    check_file(indicators=file_list, providers=providers)