# Epic: router-admin-ingestion

Owns authenticated router admin ingestion and router-native network/device data extraction.

## Goal

Let users access their own router-native network and device data and turn that into free user-visible value plus tailored insights.

## Scope

- Credential entry and authentication flows.
- Router UI navigation and extraction.
- Xfinity at `http://10.0.0.1` as the first live target.
- Durable notes for router-specific discoveries and adaptable extraction strategy.

## Out Of Scope

- One-off hardcoded scraping that cannot adapt beyond a single markup shape.
- General LAN scanner research unless it directly informs router inventory comparison.

## TODO

- Add router-specific discovery notes.
- Define secure credential-handling constraints before implementation.
