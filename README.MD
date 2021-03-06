#JWT Token Generator

## Creating RSA Public/Private Key with Powershell
 
 Execute the following in and elevated Powershell prompt to create a new Self Signed RSA Certficate

 New-SelfSignedCertificate -Type Custom -Subject "CN=FirstName LastName,OU=UserAccounts,DC=org,DC=company,DC=com" -KeyUsage DigitalSignature -KeyAlgorithm RSA -KeyLength 2048 -CertStoreLocation "Cert:\LocalMachine\My" -FriendlyName "Development" -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

## Creating RSA with OpenSSL

Generate Private key file

openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048


Generate public key file

openssl rsa -pubout -in private_key.pem -out public_key.pem


# Create JWT token from key in Store

JWTGenerator.exe thumb -t "thumbprint" -i "issuer" -a "audience"


# Create JWT token from key file

JWTGenerator.exe file -p "private_key.pem" -i "issuer" -a "audience"