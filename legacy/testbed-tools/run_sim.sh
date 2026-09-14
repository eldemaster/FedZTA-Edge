#!/bin/bash
source venv/bin/activate
python3 /home/eldemaster/fl_simulation.py > sim_output.txt

curl -X POST --data-binary @fl_metrics.pdf http://192.168.1.140:8080/fl_metrics.pdf
cat sim_output.txt
