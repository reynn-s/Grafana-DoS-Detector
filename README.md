# Grafana DoS Detector
This Grafana dashboard aims to detect DoS based on the network traffic and cpu usage. The log aggregation system is using loki. We're using python to read all the traffic activities and forward it to loki and visualized by grafana.

## Grafana and Loki Setup
Grafana and Loki runs using docker. since this project is just a local test we're using ```--network host``` so the docker will be able to use the static local ip so when i move around or when the ip on my interfaces changes i dont have to reconfigure the ip configuration.

Grafana installation using docker:
```docker run -d --name grafana --network host grafana/grafana:latest```

Loki Installation using docker:
```docker run -d --name loki --network host grafana/loki:latest```

## Python Script
In this project we're using 2 python script:

Log Forwader = [Log Forwarder](./pythonScript/python_forwader_dos.py)

DoS Simulation = [Test Loopback](./pythonScript/test_loopback.py)

Note: To run this script Grafana and Loki must be running at first and then you must run both script with ```sudo```.

## Grafana Dashboard Config
[Grafana JSON Config](./grafanaConfig/grafana-config.json)

## Script Configuration
in [Log Forwarder](./pythonScript/python_forwader_dos.py) line 13-18 we can change the value of each to match the need of our project:
```
   SAMPLE_INTERVAL = 1          # seconds between samples
   WINDOW_SECONDS = 10          # rolling window size for network rate checks
   THRESH_NET_BYTES_PER_SEC = 100_000_000   # 100 MB/s (example threshold)
   THRESH_CPU_PERCENT = 85      # 85% CPU considered suspicious
   ALERT_CONSECUTIVE = 2        # how many consecutive samples before alert
   ALERT_COOLDOWN = 1          # seconds before new alert allowed
```

in [Test Loopback](./pythonScript/test_loopback.py) line 11-17 we can change the value or ip of each to match the need of our project:
```
   TARGET_IP = '127.0.0.1'
   TARGET_PORT = 9999
   SOURCE_IPS = ['127.0.0.2', '127.0.0.3', '127.0.0.4', '127.0.0.5']
   CONNECTIONS_PER_IP = 600
   CONNECTION_DURATION = 30  # seconds
   DATA_SIZE = 1024 * 100  # 100KB per packet
   PACKETS_PER_SEC = 50    # Send 50 packets/sec = ~5MB/s per IP
```

## Screenshot of Our Grafana Dashboard
![Screenshot of DoS Detector Dashboard](https://github.com/reynn-s/Grafana-DoS-Detector/blob/main/Screenshot/DoS_Detector_Dashboard.jpeg)
