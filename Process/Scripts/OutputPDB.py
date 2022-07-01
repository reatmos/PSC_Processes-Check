"""
파일 검사시 WhiteList에 존재하는지 확인하기 위한 스크립트
제작 : 리트
Github : reatmos
Twitter : @Pa1ath
블로그 : https://re-atmosphere.tistory.com/
"""

import subprocess

# 불러올 WhiteList 경로 지정
file = 'C:\\PS\\Process.db'

def OutDB():
    # 데이터베이스에서 불러올 컬럼과 저장할 파일 경로 지정
    subprocess.call(['sqlite3', file, '.output C:/PS/Temp/Temp.txt', 'SELECT Process_Name FROM PROCESS'])
