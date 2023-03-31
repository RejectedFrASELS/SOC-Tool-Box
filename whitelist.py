
# Create a table to hold the whitelist data
#        cursor.execute('''CREATE TABLE whitelist
 #                (id INTEGER PRIMARY KEY,
  #                value TEXT,
   #               addedBy TEXT,
    #              addTime DATETIME,
     #             isPassive INT,
      #            modifiedBy TEXT,
       #           modificationTime DATETIME)''')

# Read the data from the file and insert into the table
import sqlite3
from datetime import datetime

class whitelist_add():
    def runthis(self, input, logged_user):

        ip_list = input.splitlines()
        '''
        with open("whitelist.txt",'a') as f:
           for ip_addr in ip_list:
               f.write(f"{ip_addr}\n")
        '''
        # Connect to the database (create if it does not exist)
        conn = sqlite3.connect('database.db')

        # Create a cursor object
        cursor = conn.cursor()


        try:
            
            for ip_addr in ip_list:
                #try:    
                    now = datetime.now()
                    formatted_time = now.strftime("%Y-%m-%d %H:%M:%S")
                    cursor.execute("INSERT INTO whitelist (value, addedBy, addTime, isPassive) VALUES (?, ?, ?, ?)",
                                    ( ip_addr, logged_user, formatted_time, False))
                    with open("whitelist.txt",'a') as f:
                        f.write(f"{ip_addr}\n")      
                        # Commit the changes
                    cursor.execute(f'UPDATE blacklist SET isPassive=1, modificationTime="{formatted_time}", modifiedBy="{logged_user} via Whitelist" WHERE value="{ip_addr}"')
                    conn.commit()
                
                #except:
                    print("ayni value")    
                
        except ArithmeticError:
            print("farkli error")
        # Close the connection
        conn.close()