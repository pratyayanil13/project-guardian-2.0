Deployment Strategy: Asynchronous PII Redaction in the Logging Pipeline



1\. Introduction



The root cause of the recent fraud incident at Flixkart was the leakage of PII through application logs. To address this without impacting application performance, we propose an asynchronous, centralized PII redaction service that integrates directly into our existing logging pipeline. This approach focuses on sanitizing data after it's generated but before it's stored, ensuring that our logs are clean and safe without adding any latency to the critical user-facing request path.



2\. Proposed Architecture



Our solution plugs into the existing architecture between the Log/Metric Collector and the Logging Platform (e.g., ELK). We will introduce a message queue (like Apache Kafka) and our PII Redaction Service to create a robust and scalable data sanitization layer.



The data flow will be as follows:



&nbsp;   Log Generation: Microservices (Service A, B, C) continue to write logs to stdout/stderr as they currently do.



&nbsp;   Log Collection: The Log/Metric Collector (e.g., Fluentd, Vector) on each host collects these logs.



&nbsp;   Ingestion to Raw Topic: Instead of sending logs directly to the logging platform, the collector forwards all raw, un-sanitized logs to a dedicated Kafka topic named raw\_logs.



&nbsp;   PII Detection \& Redaction: Our new PII Redaction Service (running the Python code) continuously consumes messages from the raw\_logs topic. It inspects each log message, detects PII based on the established rules, and redacts any sensitive information.



&nbsp;   Publishing to Clean Topic: The service then publishes the sanitized log messages to a second Kafka topic named redacted\_logs.



&nbsp;   Final Storage: A separate instance of the Log/Metric Collector consumes from the redacted\_logs topic and securely forwards the clean data to the final Logging Platform for storage, analysis, and monitoring.



3\. Justification



This asynchronous model is the most effective strategy for Flixkart for the following reasons:



&nbsp;   Zero Latency Impact: The entire PII scanning process happens out-of-band. It does not block or slow down the main application's request-response cycle. This is the single most important advantage, as it preserves the user experience and meets the core requirement of the challenge.



&nbsp;   High Scalability \& Resilience: By using Kafka as a buffer, the system can handle massive spikes in log volume without losing data. The PII Redaction Service itself is a stateless application that can be scaled horizontally (by adding more containers) independently of the main application services, making the solution both scalable and cost-effective.



&nbsp;   Centralized \& Easy to Maintain: The PII detection logic is maintained in a single, dedicated service. When rules need to be updated (e.g., to identify a new type of PII), we only need to update and redeploy this one service, rather than modifying and redeploying dozens of different microservices.



&nbsp;   Language Agnostic: This solution is completely decoupled from the application services. It doesn't matter if services are written in Go, Java, or Node.js; as long as they produce logs, this system will sanitize them. This avoids the need to maintain multiple PII-scanning libraries.



4\. Implementation Details



&nbsp;   Technology Stack: The PII Redaction Service will be the Python application developed for this challenge, containerized using Docker, and deployed as a scalable service on our Kubernetes cluster.



&nbsp;   Integration: The service will use the standard Kafka Python client to consume from and produce to Kafka topics. The existing Log/Metric Collector will be reconfigured to point to the raw\_logs Kafka topic as its output destination.



&nbsp;   Security \& Alerting: The service will do more than just redact; it will also generate metrics and alerts. When a log containing PII is detected, an alert can be sent to a security dashboard or a Slack channel. This provides the security team with real-time visibility into which service or endpoint is leaking PII, enabling them to address the root cause, not just the symptom.



By implementing this strategy, we can effectively plug the data leakage gap, protect our customer data, and prevent future PII-related fraud incidents with a robust, scalable, and non-intrusive solution.



