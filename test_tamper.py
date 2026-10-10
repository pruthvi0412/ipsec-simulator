import requests

def run():
    requests.post('http://localhost:5050/api/add_sa', json={"spi": 1001, "source": "1.1.1.1", "destination": "2.2.2.2"})
    r = requests.post('http://localhost:5050/api/tamper_test', json={"spi": 1001, "text": "TRANSFER $10,000 TO ACCOUNT B"})
    print(r.json())

if __name__ == "__main__":
    run()
