# Path B frame templates (public ecloud)

Shipped pre/post TLS frame blocks for Path B SPICE HEART keepalive.

- Source: nest capture `reports/r26_live/capture/t14_frame_templates_restored/`
- Product path uses `assets/templates/{pre,post}` (no /tmp dependency)
- Secrets: none. These are protocol frames, not tokens/connectStr.
- PIN: public_ecloud only · ban jtydn · production_claim=false

Restore CLI: `bin/public-spice-keepalive restore-templates`
