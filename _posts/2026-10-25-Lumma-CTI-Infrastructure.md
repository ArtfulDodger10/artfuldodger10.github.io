---
title: "Lumma Stealer: From Config to Infrastructure"
date: 2026-10-25 12:00:00 +0300
categories: [Threat Intelligence, Lumma]
tags: [Lumma, CTI, Infrastructure, Diamond Model]
description: "Coming soon. The threat-intelligence layer on the Lumma campaign: passive enrichment of the recovered C2 domains, clustering, hunting queries and judgments."
# placeholder: kept off the home page until the real post replaces this file (same file name, same URL)
hidden: true
---

> **Coming soon.** This write-up is still being written. Check back shortly; it will be published at this same address.
{: .prompt-info }

The threat-intelligence layer on the Lumma campaign: passive enrichment of the recovered C2 domains, clustering, hunting queries and judgments.

## What it will cover

- Passive enrichment of the C2 domains recovered by my extractor
- Clustering by registrar, name servers, TLS certificates, hosting and timing
- Hunting queries and how precise each one is
- A Diamond Model per delivery chain and confidence-rated judgments

## Meanwhile

- The case file in my portfolio: [https://artfuldodger10.github.io/portfolio/#/case/lumma-cti](https://artfuldodger10.github.io/portfolio/#/case/lumma-cti)
- The code, detections and IOCs: [lumma-stealer-campaign](https://github.com/ArtfulDodger10/lumma-stealer-campaign)
