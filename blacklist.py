
#      #Create a table to hold the blacklist data
 #       cursor.execute('''CREATE TABLE blacklist
  #               (id INTEGER PRIMARY KEY,
   #               type TEXT,
    #              value TEXT UNIQUE,
     #             addedBy TEXT,
      #            addTime DATETIME,
       #           isPassive INT,
        #          modifiedBy TEXT,
         #         modificationTime DATETIME)''')

# Read the data from the file and insert into the table
import sqlite3
from datetime import datetime
import re

class blacklist_add():
    def runthis(self, input, option, logged_user):

        value_list = input.splitlines()
        value_set = set(value_list) #set yap

        #Regex patterns
        ip_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$')
        ip_pattern_subnet = re.compile(r'^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([1-3][0-2]$|[0-2][0-9]$|0?[0-9]$)')
        #domain_pattern = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9]?\.+[a-zA-Z]{2,6}$')
        domain_pattern = re.compile(r'^(?:[_a-z0-9](?:[_a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)?$')
        hash_pattern = re.compile(r'\b[0-9a-f]{32}\b')
        ###############

        with open("whitelist.txt", 'r') as f:
            whitelist_set = set(f.read().splitlines()) #whitelist set
                

        blacklist_set = value_set - whitelist_set #whitelist set'i cikar
        tried_to_add = value_set & whitelist_set
            
        # Connect to the database (create if it does not exist)
        conn = sqlite3.connect('database.db')

        # Create a cursor object
        cursor = conn.cursor()



        try:
            for value in blacklist_set:
                match_ip = ip_pattern.search(value)
                match_domain = domain_pattern.search(value)
                match_hash = hash_pattern.search(value)
                match_subnet = ip_pattern_subnet.search(value)

                #from now on, inputs will be testing for regex matches
                if (match_ip or match_subnet) and option =="ip":
                    try:
                        now = datetime.now()
                        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                        cursor.execute("INSERT INTO blacklist (type, value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?, ?)",
                                    (option, value, logged_user, formatted_time, False))                        
                    except:
                        print("ayni value")                        
                elif match_domain and option =="domain":
                    try:
                        now = datetime.now()
                        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                        cursor.execute("INSERT INTO blacklist (type, value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?, ?)",
                                    (option, value, logged_user, formatted_time, False))                        
                    except:
                        print("ayni value")         
                elif match_hash and option =="hash":
                    try:
                        now = datetime.now()
                        formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                        cursor.execute("INSERT INTO blacklist (type, value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?, ?)",
                                    (option, value, logged_user, formatted_time, False))                        
                    except:
                        print("ayni value")
                else:
                    print(value+" is not a valid ip, domain or hash!")
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("INSERT INTO tried_to_add_list (value, addedBy, addTime) VALUES (?, ?, ?)",
                    (value, f'{logged_user} tried to add a non valid {option} value', formatted_time))              
                
            # Commit the changes
            conn.commit()
        except:
            print("farkli error")
        # Close the connection
        finally:
            for value in tried_to_add:
                try:  
                    print(value)
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("INSERT INTO tried_to_add_list (value, addedBy, addTime) VALUES (?, ?, ?)",
                    (value, f'{logged_user} tried to add a Whitelist value', formatted_time))                
                except:
                    print("block write fail")
        conn.commit()
        conn.close()
