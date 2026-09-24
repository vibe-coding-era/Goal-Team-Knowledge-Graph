---
type: Playbook
title: "Incident response: data freshness alert"
description: Steps to triage a freshness alert on the orders pipeline.
tags: [oncall, incident]
status: draft
generated: { by: human:ahormati, at: 2026-04-12T09:00:00Z }
owner_team: analytics-oncall
x_acme_priority: P1
---

# Trigger

A freshness alert fires when `orders` lags more than 30 minutes behind its
expected SLA. See the [orders table](/tables/orders.md).

# Steps

1. Check the [ingestion job dashboard](https://example.com/dash).
2. Escalate to the owning team.
