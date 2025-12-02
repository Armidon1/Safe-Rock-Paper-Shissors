# Safe-Rock-Paper-Shissors
## usage
first of all is needed to generate private key and public key for both players and also the server
```bash
openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
openssl req -x509 -newkey rsa:4096 -keyout alice_key.pem -out alice_cert.pem -days 365 -nodes
openssl req -x509 -newkey rsa:4096 -keyout bob_key.pem -out bob_cert.pem -days 365 -nodes
```
then run the server
```bash
python server.py
```
then in another terminal run alice
```bash
python alice.py
```
then in another terminal run bob
```bash
python bob.py
```
after that follow the instructions in the terminal