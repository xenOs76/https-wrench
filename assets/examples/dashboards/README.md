# HTTPS Wrench Grafana Dashboards

This directory contains sample Grafana dashboards for monitoring [https-wrench](https://github.com/xenos76/https-wrench) synthetic probes and observability metrics.

## Available Dashboards

- **[`https-wrench.json`](./https-wrench.json)**: Production-grade Grafana dashboard (schema version 39) providing full visibility into:
  - **Overall Health & Key Performance Indicators (KPIs)**:
    - Overall probe success rate (%)
    - Count of passing vs. failing probes
    - Average probe latency
    - Minimum certificate days remaining before expiry
    - Collector cycle execution duration
  - **Synthetic Probes & Endpoint Availability**:
    - Live probe status & target inventory table (UP/DOWN, HTTP code, latency, payload size)
    - Per-endpoint availability percentage over time
  - **Probe Latency & Performance Distributions**:
    - Latency quantiles (P50 median, P90, P99) derived from histogram buckets
    - Per-endpoint last probe duration tracking
  - **Traffic, Status Codes & Content Verification**:
    - Request throughput stacked by HTTP status codes (2xx, 3xx, 4xx, 5xx)
    - Response body regex matching verification state timeline (`MATCHED` vs `MISMATCH`)
    - Response payload size (transferred bytes)
  - **SSL / TLS Security & Certificate Lifecycle**:
    - Days until certificate expiration bar gauge with warning (<=30d) and critical (<=14d) thresholds
    - Certificate inventory and negotiated TLS parameters (TLS Version, Cipher Suite, Key Exchange, Chain Index, Expiry timestamp, Validity status)
  - **Observability Engine Diagnostics & Exporters**:
    - Scrape collector cycle duration
    - Prometheus Remote Write and OTLP push exporter error rate
    - Push export lag (time elapsed since last successful push)
    - Process CPU, RSS memory usage, and Go runtime goroutine count

## Dashboard Templating & Filtering

The dashboard includes dynamic variables populated directly from Prometheus:

| Variable | Type | Query / Source | Description |
| :--- | :--- | :--- | :--- |
| `datasource` | `datasource` | Prometheus | Prometheus / Mimir / VictoriaMetrics datasource |
| `job` | `query` | `label_values(https_wrench_probe_requests_total, job)` | Filter by Prometheus scrape job |
| `instance` | `query` | `label_values(https_wrench_probe_requests_total{job=~"$job"}, instance)` | Filter by exporter instance / host |
| `target` | `query` | `label_values(https_wrench_probe_requests_total{job=~"$job", instance=~"$instance"}, target)` | Filter by custom target label |
| `request_name` | `query` | `label_values(https_wrench_probe_requests_total{...}, request_name)` | Filter by probe request block name |
| `host` | `query` | `label_values(https_wrench_probe_requests_total{...}, host)` | Filter by target host/domain |

## How to Import into Grafana

1. Open Grafana in your browser (`http://localhost:3000` or your environment's URL).
2. In the left navigation bar, navigate to **Dashboards** > **New** > **Import**.
3. Either:
   - Upload the [`https-wrench.json`](./https-wrench.json) file, or
   - Paste the contents of [`https-wrench.json`](./https-wrench.json) into the text box.
4. Select your Prometheus data source from the dropdown prompt.
5. Click **Import**.
