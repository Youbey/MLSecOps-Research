# Project Journal

---

## 🗓️ Week 45 — 3/11 to 7/11

### 🎯 Week Objectives

* Understanding and reading research papers related to Federated Learning security
* Finalizing a first complete version of the report (state of the art)
* Preparing slides for the project pitch

### ✅ Work Done

* Produced **version 2 of the state-of-the-art report**, including structural improvements and clearer explanations.
* Reviewed and analyzed **8 research papers** focused on attacks against Federated Learning systems.
* Improved explanations around Federated Learning concepts and their relationship with MLSecOps.
* Updated LaTeX sources and report content to reflect feedback and new findings.

### ⚠️ Problems Found

* **Limited available time** due to parallel academic workload.

#### 💡 Solutions Considered

* Working outside regular hours.

#### ✔️ Solution Applied

* Used holiday time to focus on reading and synthesizing one research paper in depth.

### 📝 Notes

* [Note 1]

### 📣 Notification to Tutors

* Should the report **deeply detail attack mechanisms**, or is it acceptable to **provide high-level explanations and reference the original research papers** for deeper technical details?

---

## 🗓️ Week 47 — 24/11 to 28/11

### 🎯 Week Objectives

* Finalize report formatting and LaTeX pipeline
* Deploy and stabilize the CI/CD pipeline
* Publish project artifacts online

### ✅ Work Done

* Designed and deployed a **new web interface** for the project website.
* Integrated **GitHub Pages** for automatic publication of reports and documentation.
* Built a **complete LaTeX CI pipeline**, including bibliography handling, artifact naming, and error management.
* Cleaned unused files and standardized project structure.
* Added deployment configuration and environment variables to support automation.

### ⚠️ Problems Found

* LaTeX compilation errors related to bibliography and file paths.

#### ✔️ Solution Applied

* Adjusted CI flags, fixed naming inconsistencies, and refined LaTeX build steps.

---

## 🗓️ Week 48 — 1/12 to 5/12

### 🎯 Week Objectives

* Improve project visibility and documentation
* Refine Meta-Model presentation

### ✅ Work Done

* Added a **Meta-Model preview** to the web interface.
* Updated contributors section and fixed broken links to referenced papers.
* Improved documentation clarity and overall presentation quality.

---

## 🗓️ Week 2 — 8/01 to 12/01

### 🎯 Week Objectives

* Containerize the Federated Learning environment
* Introduce monitoring capabilities

### ✅ Work Done

* Containerized the Federated Learning model and execution environment.
* Integrated **Prometheus** for metrics collection.
* Laid the groundwork for observability of FL training processes.

---

## 🗓️ Week 4 — 21/01 to 25/01

### 🎯 Week Objectives

* Strengthen Federated Learning experimentation
* Improve automation and testing

### ✅ Work Done

* Fixed aggregation logic in the Federated Learning process.
* Added **Grafana and Loki** for log aggregation and visualization.
* Introduced malicious client simulations, detection rules, and automated tests.
* Reorganized the project structure to support CI builds and Docker image creation.

---

## 🗓️ Week 5 — 26/01 to 30/01

### 🎯 Week Objectives

* Stabilize CI/CD pipeline
* Ensure cross-platform Docker compatibility
* Improve FL training reliability

### ✅ Work Done

* Migrated all CI scripts and tooling to **Python 3**, replacing legacy tools such as `jq` with Python-based processing.
* Improved CI robustness by allowing empty security report archives and fixing pipeline edge cases.
* Reworked Docker and CI configurations to handle **multi-architecture builds** (amd64 / arm64).
* Integrated control logic into server containers and fixed Docker Compose naming issues.
* Updated Federated Learning datasets and adapted models to support new data formats.
* Tuned training behavior to run a **single controlled training cycle per launch**, preventing unintended continuous execution.
* Updated models to support **larger vocabularies (10k)** and improved LSTM compatibility.
* Added missing Python dependencies (NumPy, TensorFlow variants) to ensure reproducible execution.
