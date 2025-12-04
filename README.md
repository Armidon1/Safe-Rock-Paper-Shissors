# Safe-Rock-Paper-Shissors
## Introduction
This project implements a secure version of the classic Rock-Paper-Scissors game using Python and Docker. The game is played between two players, Alice and Bob, with a server facilitating the communication. The communication between the players and the server is secured using encryption techniques.

This project is part of the homework for the Cybersecurity course at the University of La Sapienza.

## Instructions to run the project
First of all it is required to have Docker and Docker Compose installed on your machine.

Starting from the repository root folder, (so clone it first if you haven't already) you need to generate the certificates for the server and both players:
```bash
openssl req -x509 -newkey rsa:4096 -keyout server_key.pem -out server_cert.pem -days 365 -nodes
openssl req -x509 -newkey rsa:4096 -keyout alice_key.pem -out alice_cert.pem -days 365 -nodes
openssl req -x509 -newkey rsa:4096 -keyout bob_key.pem -out bob_cert.pem -days 365 -nodes
```
then build and run the docker containers with:
```bash
docker-compose up --build
```

after that follow the instructions in the terminal. After the first game, each Bob and Alice have to insert yes/no to answer to the question "Do you want to play again? (yes/no)". To do so, you need to attach to the corresponding docker container terminal.

for Alice
```
docker attach safe-rock-paper-shissors-alice-1
```
for Bob
```
docker attach safe-rock-paper-shissors-bob-1
```