from configs.settings import *
from enrichment.indicators.domain import check_domain
from enrichment.indicators.file import check_file
from enrichment.indicators.hash import check_hash
from enrichment.indicators.ip import check_ip
from enrichment.indicators.url import check_url
from utils.indicator_loader import load_indicators_from_json


indicators = load_indicators_from_json("examples/indicators_input.json")

check_ip(indicators=indicators["ip"])

check_domain(indicators=indicators["domain"])

check_url(indicators=indicators["url"])

check_hash(indicators=indicators["hash"])

check_file(indicators=indicators["file"])