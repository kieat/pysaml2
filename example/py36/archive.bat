del latest.zip
7z\7za a -x@7z\ignore latest.zip *.* * ..\..\src\saml2\ -r
7z\7za a latest.zip ..\..\..\..\config\pysaml2-lambda\idp_conf.py -r
7z\7za a latest.zip ..\..\..\..\config\pysaml2-lambda\sp_bydesign.xml -r
call aws lambda update-function-code --function-name sso-byd --zip-file fileb://latest.zip
REM pause
REM timeout -t 10
pause
