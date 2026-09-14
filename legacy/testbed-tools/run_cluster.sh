#!/bin/bash
source venv/bin/activate
pip install scikit-learn numpy > /dev/null 2>&1

pkill -f cloud_aggregator
pkill -f edge_node

nohup python3 /home/eldemaster/cloud_aggregator.py > cloud.log 2>&1 &
sleep 2
python3 /home/eldemaster/edge_node.py --node 'Edge-A (Stoccolma)' --scenario scenario2 > edgeA.log 2>&1 &
python3 /home/eldemaster/edge_node.py --node 'Edge-B (Milano)' --scenario scenario1 > edgeB.log 2>&1 &

sleep 5
echo "--- EDGE A LOG ---"
cat edgeA.log
echo "--- EDGE B LOG ---"
cat edgeB.log
echo "--- CLOUD LOG ---"
cat cloud.log
