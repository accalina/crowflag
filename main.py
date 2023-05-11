
import sys
import json
import xmltodict
import requests

def xml2json(xml_content): 
    """
        Converts Nmap XML Output to JSON 
    """
    json_data = json.dumps(xmltodict.parse(xml_content), indent=4, sort_keys=True)
    dict_data = json.loads(json_data)
    return dict_data, json_data


def display_report(dict_data):
    print("\n..::: CrowFlag :::..")
    base_data = dict_data.get('nmaprun', {}).get('host', {})
    host_info  = "{} [{}]\n".format(
        base_data.get('address',{}).get('@addr'),
        " aka: ".join([item.get('@name') for item in base_data.get('hostnames',{}).get('hostname')])
    )
    print(host_info)
    port_list = base_data.get('ports', {}).get('port')
    for port in port_list:
        port_num = port.get('@portid').strip()
        service_name = port.get('service', {}).get('@product')
        service_version = port.get('service', {}).get('@version', '')
        cpe = port.get('service', {}).get('cpe')
        print(f"port: {port_num}")
        print(f"service: {service_name}:{service_version}")
        if not any(['or' in service_version, 'later' in service_version]):
            parse_cpe(cpe)
        else:
            print("cpe:", trim_cpe(cpe))
        print("\n")

def trim_cpe(cpe_name):
    cpe_name = cpe_name.replace('cpe:','')
    cpe_name = cpe_name.replace('/a','a')
    cpe_name = cpe_name.replace('/o','o')
    return cpe_name

def parse_cpe(cpe_list):
    if not isinstance(cpe_list, list):
        cpe_list = [cpe_list]

    for cpe in cpe_list:
        if 'linux_kernel' in cpe:
            continue
        fetch_vuln(trim_cpe(cpe))


def fetch_vuln(cpe):
    res = requests.get(f'https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:2.3:{cpe}').json()
    base_data = res.get('result', {}).get('CVE_Items', [])
    for data in base_data:
        cve = data.get('cve')
        print(f"\n   URL: https://nvd.nist.gov/vuln/detail/{cve.get('CVE_data_meta', {}).get('ID')}")
        print("   Description:", cve.get('description').get('description_data')[0].get('value'))

def banner():
    print("usage: python main.py <result.xml>")

def main():
    try:
        filename = sys.argv[1]
        with open(filename) as xml_file:
            dict_data, _ = xml2json(xml_file.read())
        
        display_report(dict_data)
    except IndexError:
        banner()
        exit()

main()