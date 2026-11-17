@echo off
cd /d C:\Users\gilw\python\fetch_nvd
if not exist logs mkdir logs
"C:\Program Files\Python315\python.exe" -m fetch_nvd --api-key-file api_key.txt --output-dir H:\nvd --timestamp-file last_run_timestamp.txt >> logs\fetch_nvd.log 2>&1
exit /b %ERRORLEVEL%