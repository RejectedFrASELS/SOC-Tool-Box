import re
import requests
import sqlite3
from datetime import datetime
import os

class cronjob():
    def runthis():
        print("STARTED")
        

        dir_path = os.path.dirname(os.path.realpath(__file__))
        log_path = os.path.join(dir_path, 'logs', 'log.log')
        now = datetime.now()
        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
        with open(log_path, 'a') as f:
            f.write(formatted_time+" PORTAL"+" CRON"+" Automation has started :"+""+"\n")
        
        #ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
        #domain_pattern = re.compile(r'\b((?:[a-zA-Z0-9]+\.)+[a-zA-Z]{2,6})\b')
        #ip_pattern = re.compile(r'[0-9]+(?:\.[0-9]+){3}')
        #ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/gm')
        ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        #domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.+[a-zA-Z]{2,6}$')
        domain_pattern = re.compile(r'^(?:[_a-z0-9](?:[_a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)?$')
        hash_pattern = re.compile(r'\b[0-9a-f]{32}\b')

        #EXCEPTIONS
        ##subnets will be added to ips
        ip_pattern_subnet = re.compile(r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-3][0-2]$|[0-2][0-9]$|0?[0-9]$)')

        
        
        
        addbyregex = re.compile(r'[^(?:http:\/\/|www\.|https:\/\/)]([^\/]+)')

        db_file = 'database.db'
        table_name = 'blacklist'

        with open("whitelist.txt", 'r') as f:
            whitelist_set = set(f.read().splitlines()) #whitelist set

        #added_by = 'PORTAL'

        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()

        cursor.execute(f'SELECT value FROM {table_name}')
        blacklist_values = set(row[0] for row in cursor.fetchall())

        '''
        with requests.Session() as session:
            urls_file = session.get(urls_file_url)
            urls = list(set(urls_file.content.decode().splitlines()))
        '''
        with open("automation-urls.txt", "r") as file:
            urls = list(set(file.read().splitlines())) 

        with requests.Session() as session:
            #urls_file = session.get(urls_file_url)
            #html_content = urls_file.content.decode()
            #urls = re.findall(r'(https?://\S+)', html_content)
        
            for url in urls:
                try:
                    
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                    with open(log_path, 'a') as f:
                        f.write(formatted_time+" PORTAL"+" CRON"+" Trying url :"+url+"\n")
                    #print("trying "+url)
                    file = session.get(url)
                    lines = set(file.content.decode().splitlines())

                    added_by_match = addbyregex.search(url)
                    added_by = added_by_match.group(0)

                    new_ips, new_domains, new_hashes, existing_values = set(), set(), set(), set()
                
                    for line in lines:
                        match_ip = ip_pattern.search(line)
                        match_domain = domain_pattern.search(line)
                        match_hash = hash_pattern.search(line)
                        match_subnet = ip_pattern_subnet.search(line)

                        if match_ip or match_subnet:
                            value = line
                            if value not in blacklist_values:
                                new_ips.add(value)
                            else:
                                existing_values.add(value)                        
                        elif match_domain:
                            value = line
                            if value not in blacklist_values:
                                new_domains.add(value)
                            else:
                                existing_values.add(value)          
                        elif match_hash:
                            value = line
                            if value not in blacklist_values:
                                new_hashes.add(value)
                            else:
                                existing_values.add(value)
                        #else: 
                            #print(value+" zaten var source= "+ url)
                    
                    
                    #existing_values = blacklist_values & get_values
                    
                    
                    all_values = existing_values | new_ips | new_domains | new_hashes
                    #get_values = new_ips | new_domains | new_hashes
                    
                    new_ips = new_ips - whitelist_set
                    new_domains = new_domains - whitelist_set
                    new_hashes = new_hashes - whitelist_set
                    #print(whitelist_set)
                    tried_to_add = all_values & whitelist_set

                    now = datetime.now() 
                    date_time = now.strftime("%m/%d/%Y %H:%M:%S")

                    cursor.executemany(
                        "INSERT INTO blacklist (type, value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?, ?)",
                        [("ip", ip, added_by, date_time, 0) for ip in new_ips] +
                        [("domain", domain, added_by, date_time, 0) for domain in new_domains] +
                        [("hash", hash_val, added_by, date_time, 0) for hash_val in new_hashes]
                    )
                    
                    cursor.executemany(
                        f'UPDATE {table_name} SET isPassive=0, modificationTime="{date_time}", modifiedBy="{added_by}" WHERE value=?',
                        ((value,) for value in (existing_values - whitelist_set))
                    )
                    
                    for value in tried_to_add:
                        try:  
                            #print(value)
                            now = datetime.now()
                            formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                            cursor.execute("INSERT INTO tried_to_add_list (value, addedBy, addTime) VALUES (?, ?, ?)",
                            (value, f'{added_by} automation tried', formatted_time))                
                        except:
                            print("block write fail")

                    conn.commit()
                    #print("done!! "+url)
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                    with open(log_path, 'a') as f:
                        f.write(formatted_time+" PORTAL"+" CRON"+" URL done! :"+url+"\n")
                except:
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S,%f")[:-3]
                    with open(log_path, 'a') as f:
                        f.write(formatted_time+" PORTAL"+" CRON"+" URL failed! :"+url+"\n")
                    #print(url+" failed")
        print("STOPPED\n")
        now = datetime.now()
        current_time = now.strftime("%H:%M:%S")
        print("Current Time =", current_time)
        conn.close()
