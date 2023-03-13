import xml.etree.ElementTree as ET
import csv

# Chemin du fichier de configuration XML de pfSense
xml_file_path = "/chemin/vers/pfsense.xml"

# Fonction pour extraire les règles de filtrage et les écrire dans un fichier CSV
def extract_firewall_rules(xml_root):
    # Ouvre le fichier CSV pour écrire les règles de filtrage
    with open('firewall_rules.csv', mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Écrit les en-têtes de colonnes
        writer.writerow(['Interface', 'Protocole', 'Adresse source', 'Adresse de destination', 'Port source', 'Port de destination', 'Action'])
        # Parcourt les règles de filtrage
        for rule in xml_root.findall("./filter/rules/rule"):
            # Récupère les valeurs des attributs
            interface = rule.get('interface')
            protocol = rule.get('protocol')
            src_addr = rule.get('source')
            dst_addr = rule.get('destination')
            src_port = rule.get('sourceport')
            dst_port = rule.get('destinationport')
            action = rule.get('action')
            # Écrit une ligne dans le fichier CSV avec les valeurs récupérées
            writer.writerow([interface, protocol, src_addr, dst_addr, src_port, dst_port, action])

# Fonction pour extraire la configuration des interfaces et les écrire dans un fichier CSV
def extract_interfaces(xml_root):
    # Ouvre le fichier CSV pour écrire la configuration des interfaces
    with open('interfaces.csv', mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Écrit les en-têtes de colonnes
        writer.writerow(['Interface', 'Adresse IP', 'Masque de sous-réseau'])
        # Parcourt les interfaces
        for interface in xml_root.findall("./interfaces/interface"):
            # Récupère les valeurs des attributs
            name = interface.get('descr')
            ipaddr = interface.find('ipaddr').text
            subnet = interface.find('subnet').text
            # Écrit une ligne dans le fichier CSV avec les valeurs récupérées
            writer.writerow([name, ipaddr, subnet])

# Fonction pour extraire la configuration DHCP et les écrire dans un fichier CSV
def extract_dhcp(xml_root):
    # Ouvre le fichier CSV pour écrire la configuration DHCP
    with open('dhcp.csv', mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Écrit les en-têtes de colonnes
        writer.writerow(['Interface', 'Adresse IP', 'Durée de bail', 'DNS', 'Passerelle', 'Domaine'])
        # Parcourt les configurations DHCP
        for dhcp in xml_root.findall("./dhcpd/lan/"):
            # Récupère les valeurs des attributs
            interface = dhcp.get('interface')
            ipaddr = dhcp.find('range').get('from')
            lease_time = dhcp.find('defaultleasetime').text
            dns = dhcp.find('dnsserver').text
            gateway = dhcp.find('gateway').text
            domain = dhcp.find('domainname').text
            # Écrit une ligne dans le fichier CSV avec les valeurs récupérées
            writer.writerow([interface, ipaddr


######

import xml.etree.ElementTree as ET
import csv

# Chemin du fichier de configuration XML de pfSense
xml_file_path = "/chemin/vers/pfsense.xml"

# Fonction pour extraire les règles de filtrage et les écrire dans un fichier CSV
def extract_firewall_rules(xml_root):
    # Ouvre le fichier CSV pour écrire les règles de filtrage
    with open('firewall_rules.csv', mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Écrit les en-têtes de colonnes
        writer.writerow(['Interface', 'Protocole', 'Adresse source', 'Adresse de destination', 'Port source', 'Port de destination', 'Action'])
        # Parcourt les règles de filtrage
        for rule in xml_root.findall("./filter/rules/rule"):
            # Récupère les valeurs des attributs
            interface = rule.get('interface')
            protocol = rule.get('protocol')
            src_addr = rule.get('source')
            dst_addr = rule.get('destination')
            src_port = rule.get('sourceport')
            dst_port = rule.get('destinationport')
            action = rule.get('action')
            # Écrit une ligne dans le fichier CSV avec les valeurs récupérées
            writer.writerow([interface, protocol, src_addr, dst_addr, src_port, dst_port, action])

# Fonction pour extraire la configuration des utilisateurs et les écrire dans un fichier CSV
def extract_users(xml_root):
    # Ouvre le fichier CSV pour écrire la configuration des utilisateurs
    with open('users.csv', mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Écrit les en-têtes de colonnes
        writer.writerow(['Nom d\'utilisateur', 'Description', 'Mot de passe'])
        # Parcourt les utilisateurs
        for user in xml_root.findall("./system/user"):
            # Récupère les valeurs des attributs
            username = user.get('name')
            description = user.get('descr')
            password = user.get('password')
            # Écrit une ligne dans le fichier CSV avec les valeurs récupérées
            writer.writerow([username, description, password])

# Fonction pour extraire la configuration des groupes et les écrire dans un fichier CSV
def extract_groups(xml_root):
    # Ouvre le fichier CSV pour écrire la configuration des groupes
    with open('groups.csv', mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        # Écrit les en-têtes de colonnes
        writer.writerow(['Nom du groupe', 'Description', 'Membres'])
        # Parcourt les groupes
        for group in xml_root.findall("./system/group"):
            # Récupère les valeurs des attributs
            groupname = group.get('name')
            description = group.get('descr')
            members = ''
            # Parcourt les membres du groupe
            for member in group.findall('member'):
                members += member.text + ', '
            members = members.rstrip(', ')
            # Écrit une ligne dans le fichier CSV avec les valeurs récupérées
            writer.writerow([groupname, description, members])

# Parse le fichier XML de pfSense
tree = ET.parse(xml_file_path)
root = tree.getroot()

# Appelle les fonctions d'extraction des données

