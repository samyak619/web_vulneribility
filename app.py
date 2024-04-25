from flask import Flask, render_template, request, jsonify
import scanner  # Assuming the scanner code is in the scanner.py file

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def run_scanner():
    data = request.get_json()
    target_url = data['targetUrl']
    ignore_links = data['ignoreLinks']

    vulnerabilities_scanner = scanner.Scanner(target_url, ignore_links)
    vulnerabilities_scanner.crawl()
    output = vulnerabilities_scanner.run_scanner()

    return jsonify(output)

if __name__ == '__main__':
    app.run(debug=False)