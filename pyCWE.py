#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cwe import Database
import pandas
import re
import warnings

warnings.simplefilter(action='ignore', category=FutureWarning)


db = Database()
weakness = db.get(287)

# Using the "error_bad_lines=False" as 
df = pandas.read_csv('3000.csv',
                     error_bad_lines=False,
                     sep=';',
                     header=0,
                     names=["ID", "Name", "Description", "Likelihood Of Attack", "Typical Severity"],
                     encoding='cp1252')

capec_info = df[df['ID']==194]
print (capec_info)

print(weakness)
print(weakness.related_attack_patterns)

def get_input():
    print('Enter the CWE ID:')
    cwe_id = input()
    create_summary(cwe_id)

def create_summary(cwe_id):
    related_attack_patterns = db.get(287).related_attack_patterns
    capec_id_list = get_capec_id(related_attack_patterns)
    capec_string = get_capec_info(capec_id_list)
    if len(capec_string) == 1:
        summary = "The attacker could leverage this using attack patterns such as "+capec_string[0]
    else:
        summary = "The attacker could leverage this using attack patterns such as "
        for attack_pattern in capec_string:
            if attack_pattern == capec_string[-1]:
                summary += "and "+attack_pattern
            elif  attack_pattern != capec_string[-2]:
                summary += attack_pattern+", "
            else:
                summary += attack_pattern+" "
                
    print(summary)
        
def get_capec_info(capec_id_list):
    vulnerability_names = []
    for capec_id in capec_id_list:
        # re.findall return <str>
        capec_info = df[df['ID']==int(capec_id)]
        vulnerability_name = "\""+capec_info.iat[0,1]+ "\" (CAPEC-ID : "+capec_id+")"
        vulnerability_names.append(vulnerability_name)
    return (vulnerability_names)
    
def get_capec_id(related_attack_patterns):
    return(re.findall("[^(\:\:)]\d+", related_attack_patterns))
    
def main():
    get_input()

main()
