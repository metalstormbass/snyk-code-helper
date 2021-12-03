# Snyk Code Helper

[![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)](https://snyk.io)

This is a script to provide addtional information from a Snyk Code scan. Requires ```jq``` to be installed.

Install:  
```cp ./snyk-code-helper.sh /usr/local/bin```   

Usage:
```snyk code test --json | snyk-code-helper.sh```

For CI/CD use ```snyk-code-helper-nc.sh``` for uncolorized output

Limitations: <br>
This tool needs to be run in the same directory that the code is being scanned.
