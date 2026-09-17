# Offline IOC Normalizer

Classifies and normalizes IPv4/IPv6 addresses, domains, URLs, and MD5/SHA-family hash strings from a text file. It performs no reputation lookup and sends no data externally.

```bash
python main.py sample_iocs.txt
python -m unittest -v
```

Useful for preparing indicator lists before authorized enrichment or case correlation.
