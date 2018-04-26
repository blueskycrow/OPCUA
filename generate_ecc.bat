@ECHO off
SETLOCAL

set SRCDIR=%~dp0
set OPENSSL=X:\Work\OPC\UA-AnsiC-ECCTest\third-party\openssl\bin\openssl.exe
set CERTGEN=PKI\Opc.Ua.CertificateGenerator.exe
set CURVE=%1
set NAME=%2
set KEYFILE=%SRCDIR%PKI\own\private\%2
set DERFILE=%SRCDIR%PKI\own\certs\%2

echo Generating %CURVE% based ECC key.
%CERTGEN% -cmd issue -sp pki\own -an %NAME%-%CURVE% -dn %COMPUTERNAME% -kt %CURVE% -hs 256 -au urn:%COMPUTERNAME%:OPCFoundation:%NAME%

REM %OPENSSL% ecparam -name %CURVE% -genkey -param_enc explicit -out %KEYFILE%.pem

REM echo ---
REM echo Generating %CURVE% based ECC key.
REM %OPENSSL% ecparam -name %CURVE% -genkey -out "%KEYFILE%.pem"
REM %OPENSSL% ecparam -in "%KEYFILE%.pem" -text -noout

REM echo ---
REM echo Creating self-signed certificate.
REM %OPENSSL% req -new -x509 -key "%KEYFILE%.pem" -out "%DERFILE%.der" -days 730 -outform DER -subj "/DC=%COMPUTERNAME%/CN=%2"
REM %OPENSSL% x509 -in "%DERFILE%.der" -inform DER -text -noout

REM echo ---
REM echo Creating PFX file.
REM %OPENSSL% x509 -in "%DERFILE%.der" -inform DER -out "%DERFILE%.pem"
REM %OPENSSL% pkcs12 -export -inkey "%KEYFILE%.pem" -in "%DERFILE%.pem" -name %2 -out "%KEYFILE%.pfx" -passout pass:

:theEnd
ENDLOCAL