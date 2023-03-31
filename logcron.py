
import os
from datetime import datetime

class Cronlog:
    def runthis():
        
        print("logs")

        now = datetime.now()
        today = now.strftime("%m-%d-%Y")

        
        dir_path = os.path.dirname(os.path.realpath(__file__))
        log_path = os.path.join(dir_path, 'logs', 'log.log')
        new_log_path = os.path.join(dir_path, 'logs', f'{today}logs.log')
        os.rename(log_path, new_log_path)

        open(log_path, 'w').close()