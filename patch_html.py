import re

with open('ipsec_core.py', 'r') as f:
    code = f.read()

with open('templates/index.html', 'r') as f:
    html = f.read()

# Replace everything between <pre class="code-block"><code> and </code></pre>
pattern = re.compile(r'<pre class="code-block"><code>.*?</code></pre>', re.DOTALL)
new_html = pattern.sub('<pre class="code-block"><code>' + code.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;') + '</code></pre>', html)

with open('templates/index.html', 'w') as f:
    f.write(new_html)
