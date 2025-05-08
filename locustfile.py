from locust import HttpUser, task, between
import random
import json

class ProxyTestUser(HttpUser):
    wait_time = between(0.1, 0.5)  # Simulate small user delay

    def on_start(self):
        self.headers = {
            "Authorization": "Bearer dummy-token",
            "User-Agent": "LocustLoadTest/1.0",
            "Accept": "application/json"
        }

    @task(2)
    def get_api(self):
        self.client.get("/api", headers=self.headers)

    @task(1)
    def get_root(self):
        self.client.get("/", headers=self.headers)