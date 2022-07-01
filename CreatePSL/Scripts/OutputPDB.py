"""
Script to check processes in Process list
Made by Reatmos
Github : reatmos
Twitter : @Pa1ath
Blog: https://re-atmosphere.tistory.com/
"""

import subprocess

# Set locate for Process list
file = 'C:\\PS\\Process.db'

def OutDB():
    # Set the location of the file to save and the column to load 
    subprocess.call(['sqlite3', file, '.output C:/PS/Temp/Temp.txt', 'SELECT Process_Name FROM PROCESS'])
