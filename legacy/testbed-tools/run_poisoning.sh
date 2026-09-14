#!/bin/bash
source venv/bin/activate
python3 /home/eldemaster/poisoning_sim.py
curl -X POST --data-binary @poisoning_defense.pdf http://192.168.1.140:8080/poisoning_defense.pdf
