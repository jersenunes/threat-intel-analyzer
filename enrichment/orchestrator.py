# type: ignore
import os
from enrichment.indicators.domain import check_domain
from enrichment.indicators.file import check_file
from enrichment.indicators.hash import check_hash
from enrichment.indicators.ip import check_ip
from enrichment.indicators.url import check_url
from pathlib import Path
from utils.indicator_loader import load_indicators_from_json
from utils.parse_args import parse_args
from typing import List


def get_indicators(inputs):
    indicators_structure = {'ip':[], 'domain':[], 'url':[], 'hash':[], 'file':[]}

    if inputs.get('type') == 'json':
        file_path = inputs.get('indicators')
        if isinstance(file_path, (str or Path)) and os.path.isfile(file_path):
            indicators = load_indicators_from_json(file_path)
            indicators_structure.update({'ip': indicators['ip']})
            indicators_structure.update({'domain': indicators['domain']})
            indicators_structure.update({'url': indicators['url']})
            indicators_structure.update({'hash': indicators['hash']})
            indicators_structure.update({'file': indicators['file']})

    if inputs.get('type') == 'ip':
        indicators_structure.get('ip').append(inputs.get('indicators'))
        
    if inputs.get('type') == 'domain':
        indicators_structure.get('domain').append(inputs.get('indicators'))
        
    if inputs.get('type') == 'url':
        indicators_structure.get('url').append(inputs.get('indicators'))
        
    if inputs.get('type') == 'hash':
        indicators_structure.get('hash').append(inputs.get('indicators'))
        
    if inputs.get('type') == 'file':
        indicators_structure.get('file').append(inputs.get('indicators'))
    
    return indicators_structure
    

def orchestrator(input: List):
    input_args = parse_args(input)

    if input_args:
        provider = input_args.get('provider')
        indicators_structure = get_indicators(inputs=input_args)

        if indicators_structure.get('ip'):
            check_ip(indicators=indicators_structure.get('ip'), provider=provider)
        if indicators_structure.get('domain'):
            check_domain(indicators=indicators_structure.get('domain'), provider=provider)
        if indicators_structure.get('url'):
            check_url(indicators=indicators_structure.get('url'), provider=provider)
        if indicators_structure.get('hash'):
            check_hash(indicators=indicators_structure.get('hash'), provider=provider)
        if indicators_structure.get('file'):
            check_file(indicators=indicators_structure.get('file'), provider=provider)
