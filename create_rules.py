#!/usr/bin/python3
import argparse
import subprocess
import sys
import xml.etree.ElementTree as ET
import concurrent.futures
import json
import os

tmp_file_name_candidate = "/tmp/tmp_get_candidate"
tmp_file_name_running = "/tmp/tmp_get_running"
tmp_file_commit = "/tmp/tmp_commit"


def create_file_request():
    """
    Create and write XML request files.
    """
    request_commit = ('<?xml version="1.0" encoding="UTF-8"?><hello '
                      'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params'
                      ':netconf:base:1.0</capability></capabilities></hello>]]>]]><rpc '
                      'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" message-id="42"><commit/></rpc>]]>]]>')

    try:
        with open(tmp_file_commit, "w") as file:
            file.write(request_commit)
    except Exception as ex:
        print(f'Error: {ex}')
        sys.exit(-1)

    request_candidate = ('<?xml version="1.0" encoding="UTF-8"?><hello '
                         'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params'
                         ':netconf:base:1.0</capability></capabilities></hello>]]>]]><rpc '
                         'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" '
                         'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" '
                         'message-id="131"><get-config><source><candidate/></source></get-config></rpc>]]>]]>')

    try:
        with open(tmp_file_name_candidate, "w") as file:
            file.write(request_candidate)
    except Exception as ex:
        print(f'Error: {ex}')
        sys.exit(-1)

    request_running = ('<?xml version="1.0" encoding="UTF-8"?><hello '
                       'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params'
                       ':netconf:base:1.0</capability></capabilities></hello>]]>]]><rpc '
                       'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" '
                       'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0" '
                       'message-id="131"><get-config><source><running/></source></get-config></rpc>]]>]]>')

    try:
        with open(tmp_file_name_running, "w") as file:
            file.write(request_running)
    except Exception as ex:
        print(f'Error: {ex}')
        sys.exit(-1)


def check_response(xml_string: str):
    """
    Check if the XML response string from the server includes any RPC errors.
    Return 0 if no error is found, and -1 otherwise.
    """
    root = ET.fromstring(xml_string)
    ns = {'ns': 'urn:ietf:params:xml:ns:netconf:base:1.0'}
    rpc_error = root.find("ns:rpc-error", ns)

    if rpc_error is None:
        return 0
    else:
        return -1


def get_candidate_db(username: str, server: str):
    """
    Submit the created candidate DB request to the server.
    Check the response for errors and return 0 for successful request and -1 otherwise.
    """
    command = "cat " + tmp_file_name_candidate + f" | ssh {username}@{server} -s netconf"
    response = subprocess.run(args=command, shell=True, capture_output=True)
    answer = response.stdout.decode('utf-8')
    if answer == '':
        print(f'Error: Candidate db for server {server} is empty')
        return ''
    else:
        answer_sp = answer.split(']]>]]>')

    result = check_response(answer_sp[1])
    if result == -1:
        print(f'Error: {answer_sp[1]}')
        return ''
    else:
        return answer_sp[1]


def get_running_db(username: str, server: str):
    """
    Submit the created running DB request to the server.
    Check the response for errors and return 0 for successful request and -1 otherwise.
    """
    command = "cat " + tmp_file_name_running + f" | ssh {username}@{server} -s netconf"
    response = subprocess.run(args=command, shell=True, capture_output=True)
    answer = response.stdout.decode('utf-8')
    if answer == '':
        print(f'Error: Running db for server {server} is empty')
        return ''
    else:
        answer_sp = answer.split(']]>]]>')

    result = check_response(answer_sp[1])
    if result == -1:
        print(f'Error: {answer_sp[1]}')
        return ''
    else:
        return answer_sp[1]


def get_servers_from_file(file_path: str):
    """
    Reads a file with hostnames. Each hostname should be on a new line.
    """
    try:
        with open(file_path, 'r') as file:
            return [host.strip() for host in file.readlines()]
    except Exception as ex:
        print(f'Error: {ex}')
        sys.exit(-1)


def check_dbs(user: str, server: str):
    """
    Function to run in each thread. Gets both dbs and checks for differences.
    """
    candidate_result = get_candidate_db(user, server)
    running_result = get_running_db(user, server)

    if (candidate_result or running_result) == '':
        return -1

    if candidate_result != running_result:
        print(f'Error: Databases for server {server} are not equal')
        return -1
    else:
        return 0


def get_networks_from_file(file_path: str):
    """
    Reads a JSON file and extracts the network addresses categorised under 'allowed', 'prohibited' and 'trusted'.
    Returns the data in the form of a dictionary.
    """
    try:
        with open(file_path, 'r') as file:
            data = json.load(file)
        return data
    except Exception as ex:
        print(f'Error: {ex}')
        sys.exit(-1)


def create_rules(context: str, data: dict, server: str, username: str, size: int):
    """
    This function is used to create netconf access rules for a context and send it to the server.

    The function creates groups, acls (access control lists), and secs (security entries) for each subnet with the
    datatypes 'allowed', 'prohibited', and 'trusted'.
    These entries are then combined in a single XML request and written to a temporary file.

    The request is then separated by a delimiter (']]>]]>') and sent to the server via an SSH connection.
    The response from the server is assessed for any potential errors.

    If the response indicates an error (or the response is empty), the function will return -1 and print an error message.
    If the 'check_response' function confirms no errors in the response, the function will return 0.
    """
    if len(data['allowed']) < 1 or len(data['prohibited']) < 1 or len(data['trusted']) < 1:
        print(f'Error: Length of allowed, prohibited, or trusted is less than 1')
        return -1

    if size != len(data['allowed']):
        print(f'Error: Capacity subnets not equal count acl')
        return -1

    request_group_allowed = ''
    count = 1
    for ip in data['allowed']:
        subnet_allowed = f'<ip-subnets nc:operation="replace">{ip}</ip-subnets>'
        request_group_allowed += f'<address-group><group-name>allowed-{count}</group-name><address-types>{subnet_allowed}</address-types></address-group>'
        count += 1

    request_group_prohibited = ''
    count = 1
    for ip in data['prohibited']:
        subnet_prohibited = f'<ip-subnets nc:operation="replace">{ip}</ip-subnets>'
        request_group_prohibited += f'<address-group><group-name>prohibited-{count}</group-name><address-types>{subnet_prohibited}</address-types></address-group>'
        count += 1

    subnet_trusted = ''
    for ip in data['trusted']:
        subnet_trusted += f'<ip-subnets nc:operation="replace">{ip}</ip-subnets>'
    request_group_trusted = f'<address-group><group-name>trusted</group-name><address-types>{subnet_trusted}</address-types></address-group>'

    acls_allowed = ''
    count = 1
    for i in range(1, size + 1):
        acls_allowed += (f'<acl-entry><sequence-id>{i}</sequence-id><actions><config><forwarding-action '
                         'nc:operation="replace">accept</forwarding-action></config></actions><src-address '
                         f'nc:operation="replace">allowed-{count}</src-address></acl-entry>')
        count += 1

    acls_prohibited = ''
    count = 1
    for i in range(size + 1, size * 2 + 1):
        acls_prohibited += (f'<acl-entry><sequence-id>{i}</sequence-id><actions><config><forwarding-action '
                            'nc:operation="replace">drop</forwarding-action></config></actions><src-address '
                            f'nc:operation="replace">prohibited-{count}</src-address></acl-entry>')
        count += 1

    acls_trusted = (
        f'<acl-entry><sequence-id>{size * 3 + 1}</sequence-id><actions><config><forwarding-action '
        'nc:operation="replace">accept</forwarding-action></config></actions><src-address '
        'nc:operation="replace">trusted</src-address></acl-entry>')

    sec_allowed = ''
    count = 1
    for i in range(1, size + 1):
        sec_allowed += (f'<sec-entry><sequence-id>{i}</sequence-id><enabled>true</enabled><actions><config><forwarding'
                        '-action>accept</forwarding-action></config></actions><src-address '
                        f'nc:operation="replace">allowed-{count}</src-address></sec-entry>')
        count += 1

    sec_prohibited = ''
    count = 1
    for i in range(size + 1, size * 2 + 1):
        sec_prohibited += (f'<sec-entry><sequence-id>{i}</sequence-id><enabled>true</enabled><actions><config'
                           f'><forwarding-action>drop</forwarding-action></config></actions><src-address '
                           f'nc:operation="replace">prohibited-{count}</src-address></sec-entry>')
        count += 1

    sec_trusted = (f'<sec-entry><sequence-id>{size * 3 + 1}</sequence-id><enabled>true</enabled><actions'
                   f'><config><forwarding-action>accept</forwarding-action></config></actions><src-address '
                   'nc:operation="replace">trusted</src-address></sec-entry>')

    secs = sec_allowed + sec_prohibited + sec_trusted
    acls = acls_allowed + acls_prohibited + acls_trusted
    addr_groups = request_group_allowed + request_group_prohibited + request_group_trusted
    request_body = ('<?xml version="1.0" encoding="UTF-8"?><hello '
                    'xmlns="urn:ietf:params:xml:ns:netconf:base:1.0"><capabilities><capability>urn:ietf:params'
                    ':netconf:base:1.0</capability></capabilities></hello>]]>]]>'
                    '<rpc xmlns="urn:ietf:params:xml:ns:netconf:base:1.0" '
                    'xmlns:nc="urn:ietf:params:xml:ns:netconf:base:1.0"'
                    'message-id="42"><edit-config><target><candidate/></target><default-operation>none</default'
                    '-operation><config><contexts xmlns="urn:ietf:params:xml:ns:yang:ietf-netconf-acm"><context><name'
                    f'>{context}</name><firewall><access-policies-ipv4><access-policy><type>acl_ipv4</type><config'
                    '><default-policy nc:operation="replace">drop</default-policy><name '
                    f'nc:operation="replace">def_drop</name></config><acl-entries nc:operation="replace">{acls}</acl'
                    f'-entries></access-policy></access-policies-ipv4><security-policies-ipv4><security-policy><type'
                    f'>sec_ipv4</type><sec-entries nc:operation="replace">{secs}</sec-entries></security-policy>'
                    f'</security-policies-ipv4><address><ipv4><ipv4-address>{addr_groups}</ipv4-address></ipv4>'
                    '</address></firewall></context></contexts></config></edit-config></rpc>]]>]]>')
    file_name = f'/tmp/tmp_{server}.xml'
    try:
        with open(file_name, "w") as file:
            file.write(request_body)
    except Exception as ex:
        print(f'Error: {ex}')
        return -1

    command = "cat " + file_name + f" | ssh {username}@{server} -s netconf"
    response = subprocess.run(args=command, shell=True, capture_output=True)
    answer = response.stdout.decode('utf-8')
    if answer == '':
        print(f'Error: Answer for server {server} is empty')
        return -1
    else:
        answer_sp = answer.split(']]>]]>')

    result = check_response(answer_sp[1])
    if result == -1:
        print(f'Error: {answer_sp[1]}')
        return -1


def send_commit(username: str, server: str) -> int:
    """
    Sends a commit RPC request through SSH to the specified server under the given username.
    The commit request is stored in a temporary file.
    """
    command = "cat " + f'{tmp_file_commit}' + f" | ssh {username}@{server} -s netconf"
    response = subprocess.run(args=command, shell=True, capture_output=True)
    answer = response.stdout.decode('utf-8')
    if answer == '':
        print(f'Error: Answer for server {server} is empty')
        return -1
    else:
        answer_sp = answer.split(']]>]]>')

    result = check_response(answer_sp[1])
    if result == -1:
        print(f'Error: {answer_sp[1]}')
        return -1


# Example: create_rules.py -u [user] -S [size] -s [servers] -c [context] -n [network]
# Example: create_rules.py -u sysadmin1 -s hosts.txt -c sample -n networks.json -S 3
# example file (trust_subnet)
# $ cat hosts.txt
# 172.17.135.59
# 172.17.135.60
# 172.17.135.61
# 172.17.135.62
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script for generating subnets')
    parser.add_argument('-u', '--user', type=str, required=True,
                        help='Name user for netconf request. This argument is required.')
    parser.add_argument('-S', '--size', type=int, required=True,
                        help='The number of rules being created. This argument is required.')
    parser.add_argument('-s', '--servers', type=str, required=True,
                        help='Path to the file with the names of the servers. This argument is required.')
    parser.add_argument('-c', '--context', type=str, required=True,
                        help='The name of the context that we are editing. This argument is required.')
    parser.add_argument('-n', '--network', type=str, required=True,
                        help='Added network in acl. This argument is required.')

    args = parser.parse_args()

    servers = get_servers_from_file(args.servers)
    if len(servers) < 1:
        print(f'Error: List hosts is empty')
        sys.exit(-1)

    print(f'Find servers: {servers}')

    create_file_request()

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(check_dbs, args.user, server) for server in servers]
        results = [f.result() for f in futures]
        if any(result == -1 for result in results):
            print(f"Error: DB not correct")
            sys.exit(-1)
    print('The databases have been checked. Begin loading rules! WAIT...')

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(create_rules, args.context, get_networks_from_file(args.network), server, args.user,
                                   args.size) for server in servers]
        results = [f.result() for f in futures]
        if any(result == -1 for result in results):
            print(f"Error: Create rules")
            sys.exit(-1)

    print('The configuration is loaded. Begin commit! WAIT...')

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = [executor.submit(send_commit, args.user, server) for server in servers]
        results = [f.result() for f in futures]
        if any(result == -1 for result in results):
            print(f"Error: Run commit")
            sys.exit(-1)

    print('Database editing completed successfully!')
