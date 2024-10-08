#!/usr/bin/python3
import argparse
import ipaddress
import json
import random
import sys


def is_valid_ipv4_cidr(ip_with_cidr: str) -> bool:
    """
    Verifies if a string is a valid IPv4 subnet in CIDR notation (x.x.x.x/y).

    Parameters:
    ip_with_cidr (str): The string potentially representing an IPv4 subnet.

    Returns:
    bool: True if the string is a valid IPv4 subnet in CIDR notation, False otherwise.
    """

    # 'ipaddress.IPv4Network' function is used to create an IPv4 network object.
    # If the provided string is not a valid IPv4 subnet, a ValueError exception is raised.
    try:
        ipaddress.IPv4Network(ip_with_cidr)
        return True
    except ValueError:
        return False


def read_file(file_path: str) -> list:
    """
    Reads a list of strings from a .txt file, one string per line.

    Parameters:
    file_path (str): The path to the file to be read;

    Returns:
    str_list (list): A list of strings.
    """
    try:
        with open(file_path, 'r') as file:
            str_list = [line.strip() for line in file if is_valid_ipv4_cidr(line.strip())]
            return str_list
    except Exception as ex:
        print(f"Error: File {file_path}: {ex}")
        sys.exit(-1)


def create_subnet(generated_ips: set) -> str:
    """
    Generates a unique IP address, ensures that the
    generated IP not exists in the `generated_ips` set.
    """
    while True:
        octet_1 = random.randint(1, 255)
        octet_2 = random.randint(1, 255)
        octet_3 = random.randint(1, 255)
        octet_4 = random.randint(1, 255)

        ip = f"{octet_1}.{octet_2}.{octet_3}.{octet_4}/32"
        if ip not in generated_ips:
            generated_ips.add(ip)
            return ip


def create_subnets(size: int) -> dict:
    """
    Generates a specified number of unique subnets
    for each "allowed" and "prohibited" categories in the IP rules.
    """
    print(f"Generate subnets ...")
    generated_ips = set()
    subnets = {"allowed": [], "prohibited": [], "trusted": []}

    for _ in range(size):
        # for key in subnets.keys():  # temporary
        for key in ["allowed", "prohibited"]:
            subnets[key].append(create_subnet(generated_ips))
    subnets["trusted"] = read_file(args.trust_subnet)

    return subnets


def save_to_file(filename, data) -> None:
    """
    Saves the generated subnets into the specified file in JSON format.
    """
    print(f"Save json in file {filename} ...")
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)


# Example: generate_ips.py -s [size] -f [file] -t [trust_subnet]
# Example: generate_ips.py -s 3 -f sub.json -t sub.txt
# example file (trust_subnet)
# $ cat sub.txt
# 10.0.0.0/24
# 10.0.1.0/24
# 10.0.2.0/24
# 10.0.3.0/24
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Script for generating subnets')
    parser.add_argument('-s', '--size', type=int, required=True,
                        help='The number of subnets to be created for each category. This argument is required.')
    parser.add_argument('-f', '--file', type=str, required=True,
                        help='Path to the file where the generated subnets will be saved. This argument is required.')
    parser.add_argument('-t', '--trust_subnet', type=str, required=True,
                        help='Path to the file with trust subnets. This argument is required.')

    args = parser.parse_args()

    subnets = create_subnets(args.size)
    try:
        save_to_file(args.file, subnets)
    except Exception as ex:
        print(f'Error: {ex}')

    print(f"Generate subnets and save file successfully")
