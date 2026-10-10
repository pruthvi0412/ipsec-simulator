import re
import subprocess

out = subprocess.check_output(['python3', 'ipsec_core.py']).decode('utf-8')

with open('templates/index.html', 'r') as f:
    html = f.read()

pattern = re.compile(r'<pre class="terminal-block"><code>.*?</code></pre>', re.DOTALL)
new_html = pattern.sub('<pre class="terminal-block"><code>$ python3 ipsec_core.py\n' + out.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') + '</code></pre>', html)

with open('templates/index.html', 'w') as f:
    f.write(new_html)
