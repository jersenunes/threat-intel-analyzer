# type: ignore
from configs.settings import *
from datetime import datetime
from typing import Dict

def parse_virus_total(response: Dict, json_to_parse: Dict) -> Dict | None:
    if response.get('data').get('attributes'):
        attributes = response.get('data').get('attributes')

        if attributes.get('country'):
            indicator_country = attributes.get('country')
            json_to_parse.get("info").update({"geo": indicator_country})
            
        if attributes.get('as_owner'):
            indicator_isp = attributes.get('as_owner')
            json_to_parse.get("info").update({"isp": indicator_isp})

        if attributes.get('last_dns_records'):
            last_dns_records = attributes.get('last_dns_records')
            indicator_records = []
            for records in last_dns_records:
                if records.get('type') == 'A' or records.get('type') == 'AAAA':
                    records.pop('ttl')
                    indicator_records.append(records)
            if indicator_records:
                json_to_parse.get("info").update({"dns_records": indicator_records})

        if attributes.get('date'):
            indicator_last_analysis_date = attributes.get('date')
            json_to_parse.get("metadata").update({"last_analysis": indicator_last_analysis_date})
                
        if attributes.get('last_analysis_date'):
            indicator_last_analysis_date = attributes.get('last_analysis_date')
            json_to_parse.get("metadata").update({"last_analysis": indicator_last_analysis_date})
        
        indicator_stats = {}

        if attributes.get('last_analysis_stats'):
            indicator_stats = attributes.get('last_analysis_stats')
                
        elif attributes.get('stats'):
            indicator_stats = attributes.get('stats')
                
        if indicator_stats:
            indicator_score = set_score(analysis = indicator_stats)
            json_to_parse.get("verdict").update({"score": indicator_score})
            indicator_reputation = set_reputation(score = indicator_score)
            json_to_parse.get("verdict").update({"reputation": indicator_reputation})
        
        json_to_parse.get("verdict").update({"confidence": "high"})
            
    if response.get('meta'):
        if response.get('meta').get('file_info'):
            file_info = response.get('meta').get('file_info')

            indicator_sha256 = file_info.get('sha256')
            json_to_parse.get("info").update({"sha256": indicator_sha256})
                                                      
            indicator_sha1 = file_info.get('sha1')
            json_to_parse.get("info").update({"sha1": indicator_sha1})
                                                      
            indicator_md5 = file_info.get('md5')
            json_to_parse.get("info").update({"md5": indicator_md5})
            
    if len(json_to_parse.get("info")) == 0:
        json_to_parse.pop("info")
    
    return json_to_parse   


def parse_abuse_ipdb(response: Dict, json_to_parse: Dict) -> Dict | None:
    if response.get('data'):
        attributes = response.get('data')

        if attributes.get('countryCode'):
            indicator_country = attributes.get('countryCode')
            json_to_parse.get("info").update({"geo": indicator_country})
            
        if attributes.get('isp'):
            indicator_isp = attributes.get('isp')
            json_to_parse.get("info").update({"isp": indicator_isp})
        
        if attributes.get('totalReports'):
            indicator_reports = attributes.get('totalReports')
            json_to_parse.get("info").update({"total_reports": indicator_reports})
        
        if attributes.get('isTor'):
            if attributes.get('isTor') != 'False':
                indicator_tor = attributes.get('isTor')
                json_to_parse.get("info").update({"Tor": indicator_tor})

        if attributes.get('lastReportedAt'):
            indicator_last_analysis_date = attributes.get('lastReportedAt')
            json_to_parse.get("metadata").update({"last_report": indicator_last_analysis_date})

        if attributes.get('abuseConfidenceScore'):
            indicator_stats = attributes.get('abuseConfidenceScore')
                
            if indicator_stats:
                indicator_score = set_score(analysis = indicator_stats)
                json_to_parse.get("verdict").update({"score": indicator_score})
                indicator_reputation = set_reputation(score = indicator_score)
                json_to_parse.get("verdict").update({"reputation": indicator_reputation})
            
        json_to_parse.get("verdict").update({"confidence": "high"})
            
    if len(json_to_parse.get("info")) == 0:
        json_to_parse.pop("info")
    
    return json_to_parse


def parse_response(response: Dict, indicator: str, type: str, source: str) -> Dict | None:
    try:
        if response and indicator and type and source:
            json_to_parse = {
                "indicator_type": type,
                "indicator": indicator,
                "verdict":{},
                "info":{},
                "metadata": {            
                        "source": source
                    }
                }
            
            json_to_parse.get("metadata").update({"timestamp_current": int(datetime.now().timestamp())})            
            
            if source == 'VirusTotal':
                return parse_virus_total(response=response, json_to_parse=json_to_parse)

            elif source == 'AbuseIPDB':
                return parse_abuse_ipdb(response=response, json_to_parse=json_to_parse)
        
    except Exception as e:
        print(f"ERROR: {e}.")


def set_score(analysis: dict | int) -> None | int:
    try:
        indicator_score = 0

        if isinstance(analysis, dict):
            if analysis.get('malicious') > 0:
                indicator_score = 3

            elif analysis.get('suspicious') > 0:
                indicator_score = 2

            elif analysis.get('harmless') > 0:
                indicator_score = 1
        
        elif isinstance(analysis, int):
            if analysis > 50:
                indicator_score = 3

            elif 50 >= analysis <= 1 :
                indicator_score = 2

            elif analysis == 0:
                indicator_score = 1

        return indicator_score
    
    except Exception as e:
        print(f"ERROR: {e}.")


def set_reputation(score: int) -> None | str:
    try:
        indicator_reputation = 'unknown'

        if score == 3:
            indicator_reputation = 'malicious'
        elif score == 2:
            indicator_reputation = 'suspicious'
        elif score == 1:
            indicator_reputation = 'benign'
        
        return indicator_reputation
    
    except Exception as e:
        print(f"ERROR: {e}.")
