#!/usr/bin/env python3
"""Catalog verified XML/INI declarations without treating them as live endpoints."""
import argparse
import configparser
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--input',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args(); rows=[]
    for path in sorted(a.input.rglob('*')):
        if not path.is_file() or path.suffix.lower() not in ('.xml','.ini','.service','.conf'): continue
        raw=path.read_bytes()
        row=dict(path=path.relative_to(a.input).as_posix(),sha256=hashlib.sha256(raw).hexdigest(),
                 bytes=len(raw),classification='STATIC_DECLARATION_NOT_RUNTIME_VERIFIED')
        if path.suffix.lower()=='.xml':
            try:
                root=ET.fromstring(raw)
                row['root_tag']=root.tag
                row['actions']=[x.text for x in root.findall('.//{*}actionList/{*}action/{*}name')]
                row['services']=[{k:(s.findtext('{*}'+k)) for k in ('serviceType','serviceId','SCPDURL','controlURL','eventSubURL')}
                                 for s in root.findall('.//{*}serviceList/{*}service')]
                row['state_variables']=[dict(name=x.findtext('{*}name'),send_events=x.get('sendEvents'))
                                        for x in root.findall('.//{*}serviceStateTable/{*}stateVariable')]
                row['device_metadata']={k:root.findtext('.//{*}device/{*}'+k) for k in ('friendlyName','modelName','modelNumber','UDN')}
            except ET.ParseError as e: row['parse_error']=str(e)
        else:
            config=configparser.ConfigParser(strict=False,interpolation=None)
            config.optionxform=str
            try:
                config.read_string(raw.decode('utf-8'))
                row['sections']=config.sections()
                if path.suffix=='.service': row['declarations']={s:dict(config[s]) for s in config.sections()}
            except (configparser.Error,UnicodeError) as e: row['parse_error']=str(e)
        rows.append(row)
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(rows,ensure_ascii=False,indent=2)+'\n')
    print('Catalogued',len(rows),'configuration files')

if __name__=='__main__': main()
