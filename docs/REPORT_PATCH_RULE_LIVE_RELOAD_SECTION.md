# Report Patch: Live Detection Rule Reload

You can paste/adapt this section into Chapter 6 or Chapter 7 of the final report.

## Live Detection Rule Reload

The v-Guard DPI engine supports configurable signature-based detection rules through the external `vguard_rules.json` file. To improve operational flexibility, a live rule reload mechanism was added to the DPI engine. This mechanism allows detection signatures to be updated without restarting the packet inspection process.

During runtime, the engine periodically checks the modification timestamp of `vguard_rules.json`. If the timestamp changes, the rule manager reloads the JSON configuration and refreshes the in-memory attack signature dictionary. This approach avoids reading and parsing the rule file for every packet, while still allowing rule updates to become active within a short configurable interval.

The reload interval can be configured using the `--rules-reload-interval` command-line option or the `VGUARD_RULE_RELOAD_INTERVAL` environment variable. Live reload can also be disabled using `--disable-rule-reload` or `VGUARD_RULE_RELOAD_ENABLED=0`. These options provide flexibility for both demonstration and long-running test environments.

This feature strengthens the manageability of the system because administrators can update detection rules through the dashboard or directly through the JSON configuration file. The DPI engine continues to inspect traffic while the rule set is refreshed in memory. As a result, the system better satisfies the requirement for configurable inspection behavior and supports a more realistic SOC workflow.
