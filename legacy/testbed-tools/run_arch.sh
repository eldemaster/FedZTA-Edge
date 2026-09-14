#!/bin/bash
source venv/bin/activate
python3 /home/eldemaster/draw_arch.py
curl -X POST --data-binary @fl_architecture.pdf http://192.168.1.140:8080/fl_architecture.pdf
