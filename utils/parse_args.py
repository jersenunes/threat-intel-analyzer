from configs.settings import *
from typing import Dict

def parse_args(args) -> None | Dict:
    structure = {}
    provider_temp = ''

    for type in INDICATORS_TYPE:
        if len(args) == 3:
            if type in args[1]:
                indicators = args[1].split('=')[1]
                structure.update({'type': type})
                structure.update({'indicators': indicators})
                provider_temp = args[2].split('=')[1]
                break

            elif type in args[2]:
                indicators = args[2].split('=')[1]
                structure.update({'type': type})
                structure.update({'indicators': indicators})
                provider_temp = args[1].split('=')[1]
                break

        if len(args) == 2:
            if type in args[1]:
                indicators = args[1].split('=')[1]
                structure.update({'type': type})
                structure.update({'indicators': indicators})
                break

    if provider_temp:
        for key, value in PROVIDERS.items():
            if provider_temp.lower() in value:
                structure.update({'provider': key})
                break

    return structure
