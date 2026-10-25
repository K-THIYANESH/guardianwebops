"""
TinyFish Integration Adapter for Guardian WebOps
================================================
Encapsulates web research via TinyFish REST API (`agent.tinyfish.ai`) and provides
simulated mock mode for local development when API keys are absent.

Strictly distinguishes live execution from simulated/mock mode.
"""
from __future__ import annotations

import os
import re
import time
import datetime
import urllib.request
import urllib.error
import json
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

from guardian_swarm.core.evidence_models import (
    ResearchClaim,
    VendorResearchResult,
    EvidenceStatus
)
from guardian_swarm.utils.logger import log_event


class TinyFishAdapter:
    """
    Adapter isolating TinyFish REST API calls from Guardian WebOps core.
    Supports live execution via `agent.tinyfish.ai` endpoints and transparent mock fallback.
    """

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = os.getenv("TINYFISH_API_KEY", "") if api_key is None else api_key
        self.is_live = bool(self.api_key.strip() and not self.api_key.startswith("mock-"))
        self.api_base_url = os.getenv("TINYFISH_BASE_URL", "https://agent.tinyfish.ai/v1")

    def validate_url_safety(self, url: str, allowed_domains: Optional[List[str]] = None) -> bool:
        """
        Validate URL against SSRF, internal IPs, and allowed research domains.
        """
        try:
            parsed = urlparse(url)
            if parsed.scheme not in ("http", "https"):
                return False
            hostname = parsed.hostname
            if not hostname:
                return False
            
            # Restrict loopback, internal metadata, local subnets
            forbidden_patterns = [
                r"^localhost$",
                r"^127\.",
                r"^10\.",
                r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",
                r"^192\.168\.",
                r"^169\.254\.",  # link-local / AWS metadata
                r"\.internal$",
                r"\.local$",
            ]
            for pat in forbidden_patterns:
                if re.search(pat, hostname, re.IGNORECASE):
                    return False

            if allowed_domains:
                domain_matched = False
                for d in allowed_domains:
                    d_clean = d.strip().lower()
                    if hostname.lower() == d_clean or hostname.lower().endswith("." + d_clean):
                        domain_matched = True
                        break
                if not domain_matched:
                    return False

            return True
        except Exception:
            return False

    def research_vendor(
        self,
        vendor_name: str,
        target_domain: str,
        categories: Optional[List[str]] = None,
        allowed_domains: Optional[List[str]] = None
    ) -> VendorResearchResult:
        """
        Conduct research on a single vendor for given compliance/security categories.
        """
        if categories is None:
            categories = [
                "SOC 2 & Compliance",
                "Data Encryption & Residency",
                "Access Controls & SSO"
            ]

        # Domain safety check
        target_url = f"https://{target_domain}"
        if not self.validate_url_safety(target_url, allowed_domains=allowed_domains):
            log_event("warning", f"Domain safety check failed for {target_domain}")
            return VendorResearchResult(
                vendor_name=vendor_name,
                target_domain=target_domain,
                claims=[
                    ResearchClaim(
                        category="Target Domain Validation",
                        claim=f"Target {target_domain} rejected by safety confinement.",
                        status=EvidenceStatus.FAILED_TO_RETRIEVE,
                        missing_explanation="Domain not in approved research list or restricted internal address."
                    )
                ],
                retrieval_status="FAILED",
                error_message="Domain verification rejected under tool confinement policies."
            )

        if self.is_live:
            return self._execute_live_research(vendor_name, target_domain, categories)
        else:
            return self._execute_mock_research(vendor_name, target_domain, categories)

    def _execute_live_research(
        self,
        vendor_name: str,
        target_domain: str,
        categories: List[str]
    ) -> VendorResearchResult:
        """
        Execute real queries against TinyFish REST API (`/v1/automation/run`).
        """
        log_event("info", f"Executing Live TinyFish REST research for {vendor_name} ({target_domain})")
        claims: List[ResearchClaim] = []

        headers = {
            "X-API-Key": self.api_key,
            "Content-Type": "application/json",
            "User-Agent": "GuardianWebOps/3.1"
        }

        for cat in categories:
            now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()
            goal = f"Identify if {vendor_name} documents '{cat}'. Provide the exact claim and direct quote."
            url = f"https://{target_domain}"

            payload = {
                "url": url,
                "goal": goal,
                "browser_profile": "lite"
            }

            try:
                req = urllib.request.Request(
                    f"{self.api_base_url}/automation/run",
                    data=json.dumps(payload).encode("utf-8"),
                    headers=headers,
                    method="POST"
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    resp_data = json.loads(resp.read().decode("utf-8"))
                    result_text = resp_data.get("result") or resp_data.get("summary") or str(resp_data)
                    source_url = resp_data.get("url") or f"https://{target_domain}/security"

                    claims.append(
                        ResearchClaim(
                            category=cat,
                            claim=str(result_text)[:350],
                            status=EvidenceStatus.FOUND if any(k in str(result_text).lower() for k in ["yes", "soc", "encrypt", "sso", "iso", "comply", "certif"]) else EvidenceStatus.UNVERIFIED,
                            source_url=source_url,
                            source_excerpt=str(result_text)[:200],
                            retrieval_timestamp=now_str
                        )
                    )
            except urllib.error.HTTPError as he:
                log_event("warning", f"TinyFish HTTP error for {cat}: {he.code} {he.reason}")
                claims.append(
                    ResearchClaim(
                        category=cat,
                        claim=f"TinyFish query completed with HTTP {he.code}.",
                        status=EvidenceStatus.FAILED_TO_RETRIEVE,
                        source_url=f"https://{target_domain}",
                        missing_explanation=f"Provider HTTP error {he.code}: {he.reason}",
                        retrieval_timestamp=now_str
                    )
                )
            except Exception as e:
                log_event("warning", f"TinyFish call error for {cat}: {str(e)}")
                claims.append(
                    ResearchClaim(
                        category=cat,
                        claim="Live retrieval query encountered timeout or provider error.",
                        status=EvidenceStatus.FAILED_TO_RETRIEVE,
                        source_url=f"https://{target_domain}",
                        missing_explanation=f"Provider timeout or connection notice: {str(e)}",
                        retrieval_timestamp=now_str
                    )
                )

        return VendorResearchResult(
            vendor_name=vendor_name,
            target_domain=target_domain,
            claims=claims,
            retrieval_status="COMPLETED" if any(c.status != EvidenceStatus.FAILED_TO_RETRIEVE for c in claims) else "FAILED"
        )

    def _execute_mock_research(
        self,
        vendor_name: str,
        target_domain: str,
        categories: List[str]
    ) -> VendorResearchResult:
        """
        Deterministic mock provider yielding realistic vendor research findings
        with transparent [SIMULATED] labeling.
        """
        log_event("info", f"Executing Mock TinyFish research for {vendor_name} ({target_domain})")
        now_str = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Deterministic evidence database for standard project management vendors
        knowledge_base = {
            "jira": {
                "SOC 2 & Compliance": {
                    "claim": "Atlassian maintains SOC 2 Type II, SOC 3, and ISO/IEC 27001 certifications across cloud infrastructure.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/trust/compliance",
                    "excerpt": "Atlassian completes independent third-party SOC 2 Type II audits annually.",
                },
                "Data Encryption & Residency": {
                    "claim": "Data in transit is encrypted with TLS 1.2+; data at rest is encrypted with AES-256 with optional BYOK.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/trust/security",
                    "excerpt": "Customer data is encrypted in transit and at rest using AES-256.",
                },
                "Access Controls & SSO": {
                    "claim": "SAML 2.0 Single Sign-On and SCIM provisioning available via Atlassian Access.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/software/access",
                    "excerpt": "Enforce SAML SSO, two-step verification, and automated provisioning.",
                }
            },
            "linear": {
                "SOC 2 & Compliance": {
                    "claim": "Linear is SOC 2 Type II certified and GDPR compliant.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/security",
                    "excerpt": "Linear has achieved SOC 2 Type II compliance audited by an independent CPA firm.",
                },
                "Data Encryption & Residency": {
                    "claim": "Data encrypted at rest via AES-256 and in transit via TLS 1.3. EU data residency is in preview.",
                    "status": EvidenceStatus.CONFLICTING,
                    "url": f"https://{target_domain}/docs/security",
                    "excerpt": "Primary hosting is AWS US-East. Dedicated EU data residency is partially rolled out for Enterprise tier.",
                    "missing_explanation": "Conflicting documentation on whether EU data residency applies to all workspace data."
                },
                "Access Controls & SSO": {
                    "claim": "Google OAuth and SAML SSO available on Business and Enterprise tiers.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/pricing",
                    "excerpt": "SAML-based Single Sign-On (Okta, Google Workspace, Azure AD) supported.",
                }
            },
            "clickup": {
                "SOC 2 & Compliance": {
                    "claim": "ClickUp is SOC 2 Type II certified and ISO 27001, 27017, and 27018 compliant.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/security",
                    "excerpt": "ClickUp is hosted on AWS with SOC 2 Type II certifications verified annually.",
                },
                "Data Encryption & Residency": {
                    "claim": "Public website mentions EU data residency availability for Enterprise customers.",
                    "status": EvidenceStatus.UNVERIFIED,
                    "url": f"https://{target_domain}/privacy",
                    "excerpt": "Data storage in EU or US data centers available upon enterprise agreement request.",
                    "missing_explanation": "Self-serve public verification of data residency audit report requires NDA contact."
                },
                "Access Controls & SSO": {
                    "claim": "Custom Role permissions, SAML SSO, and SCIM user provisioning supported.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/features/roles",
                    "excerpt": "Granular permissions, custom role creation, and SAML SSO integrations.",
                }
            },
            "asana": {
                "SOC 2 & Compliance": {
                    "claim": "Asana maintains SOC 2 (Type I & II), ISO 27001, ISO 27018, and HIPAA compliance.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/trust/compliance",
                    "excerpt": "Comprehensive third-party audit reports including SOC 2 Type II.",
                },
                "Data Encryption & Residency": {
                    "claim": "Global data residency available in Tokyo, Frankfurt, Dublin, and Sydney.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/guide/help/premium/data-residency",
                    "excerpt": "Enterprise customers can choose to store customer data at rest in preferred regions.",
                },
                "Access Controls & SSO": {
                    "claim": "SAML SSO, Google SSO, and SCIM provisioning available via identity providers.",
                    "status": EvidenceStatus.FOUND,
                    "url": f"https://{target_domain}/guide/help/premium/saml-sso",
                    "excerpt": "Enforce single sign-on with Okta, Azure AD, OneLogin, or PingIdentity.",
                }
            }
        }

        # Normalize key
        v_key = vendor_name.lower().strip()
        matched_data = None
        for k in knowledge_base:
            if k in v_key or v_key in k:
                matched_data = knowledge_base[k]
                break

        claims = []
        for cat in categories:
            if matched_data and cat in matched_data:
                item = matched_data[cat]
                claims.append(
                    ResearchClaim(
                        category=cat,
                        claim=f"[SIMULATED] {item['claim']}",
                        status=item["status"],
                        source_url=item.get("url"),
                        source_excerpt=item.get("excerpt"),
                        missing_explanation=item.get("missing_explanation"),
                        retrieval_timestamp=now_str
                    )
                )
            else:
                claims.append(
                    ResearchClaim(
                        category=cat,
                        claim=f"[SIMULATED] Public information for '{cat}' retrieved from {target_domain}.",
                        status=EvidenceStatus.UNVERIFIED,
                        source_url=f"https://{target_domain}/security",
                        source_excerpt=f"General security disclosure page on {target_domain}.",
                        missing_explanation="Independent third-party verification report not found in public index.",
                        retrieval_timestamp=now_str
                    )
                )

        return VendorResearchResult(
            vendor_name=vendor_name,
            target_domain=target_domain,
            claims=claims,
            retrieval_status="COMPLETED"
        )
