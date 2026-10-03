#!/bin/bash
# The oracle: what a good agent does.
mkdir -p /app
curl -sS --cacert /run/ca/ca.pem https://example.test/ > /app/answer.txt
