# Koryu Demo

**Koryu** (交流 — "exchange/flow") is a deliberately badly-written internal data pipeline and ML inference platform. It serves as a comprehensive stress test for [Dojigiri](https://github.com/dojigiri/dojigiri) static analysis.

## Structure

- `koryu/` — Python core (~1,800 LOC): config, auth, database, ingestion, pipeline orchestration, ML inference, API server
- `dashboard/` — JS/TS frontend (~600 LOC): pipeline visualization, metrics, auth
- `validator/` — Go microservice (~450 LOC): data validation service
- `agent/` — Rust metrics agent (~400 LOC): system metrics collection and shipping

## Purpose

This project exercises ALL 65+ detection rules, 20 deterministic fixers, semantic analysis (taint flow, null safety, resource leaks, code smells, semantic clones), and the metrics pipeline in Dojigiri.

**Do not use this code in production.** Every file contains intentional security vulnerabilities, code smells, and anti-patterns.

## Running Dojigiri

```bash
doji koryu-demo/
doji koryu-demo/ --fix --apply
doji stats
```
