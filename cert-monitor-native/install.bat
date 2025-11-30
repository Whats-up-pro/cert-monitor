@echo off
:: Thay đổi đường dẫn này trỏ tới file nm_host.json của bạn
set KEY_NAME=HKCU\Software\Google\Chrome\NativeMessagingHosts\com.certmonitor.native
:: Lấy đường dẫn hiện tại
set MANIFEST_PATH=%~dp0nm_host.json

reg add "%KEY_NAME%" /ve /t REG_SZ /d "%MANIFEST_PATH%" /f

echo Da dang ky Native Host thanh cong!
pause