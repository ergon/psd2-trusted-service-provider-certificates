# Purpose
The European Payment Services Directive relies for its security on PKI technology. To establish trust all 
participants are required to verify each others certificates. To execute the verification the CA certificate that 
issued the participants certificate is needed. This piece of software was written to provide a convenient way for 
system administrators to download all CA certificates required in PSD2 verifications. 

# Usage
To run the program requires python version 3 or higher and a few libraries must be installed (see requirements.txt).  
A filename must be provided on the command line and this file will contain the list of PEM encoded CA certificates 
as a result of the execution. The program requires access to the Internet so it can connect to 
the European Trust List Browser API.

# Disclaimer
This software is provided as source code under an MIT license (see LICENSE)

# Limitations
The website of the European Trust List Browser  (see https://webgate.ec.europa.eu/tl-browser/) and the 
API documentation (see https://webgate.ec.europa.eu/tl-browser/swagger-ui.html  ) do not provide any information 
on the semantics of the information provided. The algorithm used to collect the CA certificates was reverse 
engineered from the data provided on the API.

# Security
The European Trust List Browser does provide limited security on the API. The  API is offered over TLS so 
it is possible to ascertain the source of the information. The information itself is not signed so the 
authenticity and integrity cannot be validated.

# Further Development
The software meets its intended purpose and there are not plans to further develop this software. 
Feedback on functionality as well as bug reports are welcome.