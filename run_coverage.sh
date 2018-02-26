#This script runs our DIY code coverage script for the function resolve in view.py
 . venv/bin/activate && cd test/mitmproxy/addons && pytest --cov mitmproxy.addons.view test_view.py
python3 diy_sort_coverage.py
cat diy_coverage.txt
