# CT Log Phishing Detection Tool

A comprehensive phishing detection system that monitors Certificate Transparency (CT) logs to identify potentially malicious domains targeting popular brands and services.

## Overview

This tool continuously monitors certificate transparency logs through the crt.sh API to detect suspicious domain registrations that could be used for phishing attacks. It combines multiple detection methods including heuristic analysis, threat intelligence feeds, and typosquatting detection to provide comprehensive protection against phishing domains.

## Features

### Core Functionality
- **Certificate Transparency Monitoring**: Queries crt.sh API for recent certificates containing target keywords
- **Multi-source Threat Detection**: Integrates with multiple security services for comprehensive analysis
- **Real-time Monitoring**: Continuous monitoring with configurable intervals
- **SQLite Database**: Persistent storage for processed certificates and alerts
- **Enhanced Risk Scoring**: Sophisticated scoring system combining multiple threat indicators

### Integrated Security Services
- **VirusTotal API**: Domain reputation checking with caching (24h)
- **Google Safe Browsing**: URL threat detection
- **PhishTank**: Known phishing site database
- **DNSTwist**: Typosquatting domain generation and detection

### Target Keywords
Monitors certificates for popular brands and services including:
- **Tech Giants**: PayPal, Amazon, Google, Microsoft, Apple, Facebook
- **Social Media**: Instagram, Twitter, LinkedIn
- **Streaming**: Netflix, Spotify
- **Financial**: Major US and European banks
- **Email Services**: Gmail, Outlook, Yahoo
- **Polish Banks**: PKO BP, mBank, ING Bank, Santander, and others

## Installation

### Prerequisites
