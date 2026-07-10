@echo off
python -u "%~dp0nui-wallfix.py" %*
exit /b %ERRORLEVEL%
