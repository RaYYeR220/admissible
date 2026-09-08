"""Paying for an agent service, and keeping the receipt.

Admissible only ever calls a paid endpoint in order to *learn something it can
prove later*. So this module's job is not really "make the HTTP request go
through" -- it is to come back holding a settlement transaction hash that
:meth:`admissible.chain.BaseChain.verify_settlement` can re-derive from the
chain months afterwards. A 200 response with no recoverable tx hash leaves the
memory at WITNESSED; it never reaches ATTESTED. That asymmetry is the design.

Version negotiation, and why it is not optional
-----------------------------------------------
x402 v2 renamed the headers: ``X-PAYMENT`` became ``PAYMENT-SIGNATURE`` and
``X-PAYMENT-RESPONSE`` became ``PAYMENT-RESPONSE``, and networks became CAIP-2
(``eip155:8453`` rather than ``base``).

The live counterparty we integrate against has not moved. Fetched today, agent
20880's endpoints answer ``{"x402Version": 1, ... "network": "base"}`` and
advertise ``Access-Control-Allow-Headers: X-PAYMENT``. Hardcoding the v2 names
would have produced a client that is correct against the specification and
broken against the only server we actually need to pay.

So nothing here hardcodes a header name. We read ``x402Version`` off the
challenge and let the SDK pick the matching header -- v1 payloads go out as
``X-PAYMENT``, v2 as ``PAYMENT-SIGNATURE`` -- which means this keeps working
when sibylcap upgrades, without a change here.

Spending
--------
The SDK caps a single payment at $1 in USDC by default. That default is a
sensible guard and a bad silent failure: a $0.50 advisory call is under it, but
anything larger would be rejected with a message about spend controls rather
than a payment. :data:`DEFAULT_SPEND_CAP` raises it explicitly so the limit is
a number in this file that a reviewer can see and argue with.

:func:`pay` will not broadcast unless it is told to. ``dry_run`` defaults to
``True``, so signing a real EIP-3009 authorization and then sending it is
always a deliberate act rather than the accidental consequence of calling a
function named "pay".
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Mapping, NamedTuple

import httpx
from x402.client import x402Client
from x402.client_base import SpendControls
from x402.http.utils import (
    decode_payment_response_header,
    encode_payment_signature_header,
)
from x402.mechanisms.evm.exact import register_exact_evm_client
from x402.schemas import PaymentRequired
from x402.schemas.v1 import PaymentRequiredV1

from .chain import BaseChain, VerifiedSettlement

__all__ = [
    "DEFAULT_SPEND_CAP",
    "SIBYL_SERVICES",
    "Challenge",
    "PaidResult",
    "PaymentRefused",
    "PreparedPayment",
    "X402Payer",
    "fetch_challenge",
]

#: Raised from the SDK's $1 default. USDC on Base has six decimals, so this is
#: five dollars; the priciest thing agent 20880 sells is $0.50.
DEFAULT_SPEND_CAP = "$5.00"

#: Header carrying an already-settled transaction hash. Not part of x402: it is
#: an extension agent 20880 advertises under ``alt.directTx``, and it is the
#: flow Admissible prefers, because it inverts the trust order -- the payment is
#: on chain and final *before* the server is asked for anything, so the evidence
#: exists whether or not the server ever answers.
DIRECT_TX_HEADER = "X-PAYMENT-TX"

#: Endpoints read from https://sibylcap.com/8004.json (agent 20880's tokenURI).
#: ``safety-check`` is listed in that manifest at /api/check but returns 404 on
#: Base mainnet today, so it is recorded here as known-broken rather than
#: quietly dropped.
SIBYL_SERVICES: dict[str, dict[str, Any]] = {
    "project-evaluation": {
        "endpoint": "https://sibylcap.com/api/evaluate",
        "price_base_units": 250_000,
        "live": True,
    },
    "advisory-analysis": {
        "endpoint": "https://sibylcap.com/api/advisory",
        "price_base_units": 500_000,
        "live": True,
    },
    "safety-check": {
        "endpoint": "https://sibylcap.com/api/check",
        "price_base_units": 20_000,
        "live": False,
    },
}


class PaymentRefused(RuntimeError):
    """We declined to pay, or the server declined to be paid."""


@dataclass(frozen=True)
class Challenge:
    """A parsed HTTP 402, whichever protocol version produced it."""

    version: int
    raw: dict[str, Any]
    parsed: PaymentRequired | PaymentRequiredV1
    url: str

    @property
    def requirement(self) -> Any:
        """The first accepted way to pay. Servers list preference-ordered."""
        return self.parsed.accepts[0]

    @property
    def pay_to(self) -> str:
        return str(self.requirement.pay_to)

    @property
    def asset(self) -> str:
        return str(self.requirement.asset)

    @property
    def amount(self) -> int:
        """Price in base units -- 250000 is $0.25 of six-decimal USDC."""
        return int(self.requirement.get_amount())

    @property
    def network(self) -> str:
        """``base`` under v1, ``eip155:8453`` under v2. Both mean chain 8453."""
        return str(self.requirement.network)

    @property
    def agent(self) -> dict[str, Any]:
        """The ERC-8004 identity the server volunteers, if any.

        Agent 20880 returns its id, registry and both wallets here. Convenient,
        and worth exactly nothing until checked against the registry -- which is
        what :meth:`X402Payer.expected_recipient` does.
        """
        value = self.raw.get("agent")
        return value if isinstance(value, dict) else {}

    @property
    def supports_direct_tx(self) -> bool:
        alt = self.raw.get("alt")
        return isinstance(alt, dict) and "directTx" in alt


@dataclass(frozen=True)
class PreparedPayment:
    """A signed authorization that has not been sent anywhere.

    Holding this is holding a signature that would move money if transmitted,
    which is why preparing and sending are two calls rather than one.
    """

    challenge: Challenge
    header_name: str
    header_value: str
    payload: Any

    @property
    def x402_version(self) -> int:
        return int(self.payload.x402_version)

    def describe(self) -> dict[str, Any]:
        """A loggable summary. Deliberately omits the signature."""
        inner = self.payload.model_dump(by_alias=True, exclude_none=True)
        auth = (inner.get("payload") or {}).get("authorization", {})
        return {
            "x402_version": self.x402_version,
            "header": self.header_name,
            "network": self.challenge.network,
            "from": auth.get("from"),
            "to": auth.get("to"),
            "value": auth.get("value"),
            "valid_before": auth.get("validBefore"),
        }


class PaidResult(NamedTuple):
    """What a paid call returns: the answer, and the proof it was paid for."""

    response: httpx.Response | None
    settlement_tx_hash: str | None
    payment_receipt: dict[str, Any] | None


@dataclass
class X402Payer:
    """Pays one x402 endpoint, and hands back something verifiable.

    ``chain`` is optional but strongly recommended: with it,
    :meth:`settle_and_verify` re-reads the settlement from Base rather than
    trusting the ``PAYMENT-RESPONSE`` header, which is the server's own account
    of whether it got paid.
    """

    private_key: str | None = None
    spend_cap: str = DEFAULT_SPEND_CAP
    timeout: float = 45.0
    chain: BaseChain | None = None
    _client: x402Client | None = field(default=None, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.private_key:
            from eth_account import Account

            account = Account.from_key(self.private_key)
            client = x402Client()
            # Registers the v2 eip155:* wildcard and every v1 legacy network,
            # so whichever version the server speaks is already covered.
            register_exact_evm_client(client, account)
            client.set_spend_controls(SpendControls(max_amount_per_payment=self.spend_cap))
            self._client = client

    @classmethod
    def from_env(cls, **kw: Any) -> "X402Payer":
        import os

        return cls(private_key=os.environ.get("PRIVATE_KEY") or None, **kw)

    @property
    def can_sign(self) -> bool:
        return self._client is not None

    # -- discovery ---------------------------------------------------------------

    async def challenge(
        self, url: str, *, method: str = "POST", json_body: Mapping[str, Any] | None = None
    ) -> Challenge:
        """Ask an endpoint what it wants, without paying."""
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as http:
            response = await http.request(
                method, url, json=dict(json_body) if json_body is not None else None
            )
        return _parse_challenge(response, url)

    def expected_recipient(self, challenge: Challenge, agent_id: int | None = None) -> str:
        """The address we will accept as proof of payment, checked onchain.

        The challenge names a ``payTo``. Believing it unconditionally is how you
        pay an impostor who copied someone's manifest. When a chain client is
        available we resolve the agent's ERC-8004 record and require ``payTo`` to
        be one of the wallets that record vouches for.

        Agent 20880 makes this concrete: its identity NFT is owned by
        ``0x4069ef1a…`` but payments settle to ``0xe3e14118…``. Checking against
        the owner alone would reject every genuine payment; skipping the check
        entirely would accept every forged one. The manifest's ``payment``
        wallet is the answer, and it has to be fetched to be trusted.
        """
        pay_to = challenge.pay_to
        if self.chain is None:
            return pay_to
        claimed = agent_id if agent_id is not None else challenge.agent.get("id")
        if claimed is None:
            return pay_to
        record = self.chain.resolve_agent(int(claimed))
        allowed = record.payment_wallets()
        if allowed and pay_to.lower() not in allowed:
            raise PaymentRefused(
                f"endpoint asks to be paid at {pay_to}, but ERC-8004 agent "
                f"{claimed} vouches only for {', '.join(allowed)}"
            )
        return pay_to

    # -- paying ------------------------------------------------------------------

    async def prepare(self, challenge: Challenge) -> PreparedPayment:
        """Sign the authorization. Sends nothing.

        This is the whole payment except the last step, which makes it the right
        place to stop when the wallet is unfunded or the caller has not opted
        into spending.
        """
        if self._client is None:
            raise PaymentRefused("no signer configured; set PRIVATE_KEY to pay")
        payload = await self._client.create_payment_payload(challenge.parsed)
        encoded = encode_payment_signature_header(payload)
        # v1 payloads must go out as X-PAYMENT, v2 as PAYMENT-SIGNATURE. The
        # payload knows its own version, so the header follows from the data
        # rather than from a constant somebody has to remember to update.
        name = "PAYMENT-SIGNATURE" if int(payload.x402_version) == 2 else "X-PAYMENT"
        return PreparedPayment(
            challenge=challenge, header_name=name, header_value=encoded, payload=payload
        )

    async def pay(
        self,
        url: str,
        *,
        method: str = "POST",
        json_body: Mapping[str, Any] | None = None,
        agent_id: int | None = None,
        dry_run: bool = True,
    ) -> PaidResult:
        """Fetch the challenge, sign, and -- only if asked -- send.

        Returns ``(response, settlement_tx_hash, payment_receipt)``.

        With ``dry_run`` left at its default nothing is transmitted: the
        response is ``None``, and ``payment_receipt`` describes the payment that
        *would* have been made. That is the mode this was built and tested in,
        because the wallet is unfunded and a signed EIP-3009 authorization is
        bearer-ish -- it is only inert for as long as nobody sends it.
        """
        challenge = await self.challenge(url, method=method, json_body=json_body)
        recipient = self.expected_recipient(challenge, agent_id)
        prepared = await self.prepare(challenge)
        receipt = prepared.describe() | {"pay_to_verified": recipient}
        if dry_run:
            return PaidResult(None, None, receipt | {"dry_run": True})

        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as http:
            response = await http.request(
                method,
                url,
                json=dict(json_body) if json_body is not None else None,
                headers={prepared.header_name: prepared.header_value},
            )
        tx_hash, settle = _settlement_from(response)
        return PaidResult(response, tx_hash, receipt | {"settlement": settle})

    async def pay_with_settled_tx(
        self,
        url: str,
        tx_hash: str,
        *,
        method: str = "POST",
        json_body: Mapping[str, Any] | None = None,
    ) -> PaidResult:
        """Present an already-settled transaction instead of a signature.

        Agent 20880 advertises this under ``alt.directTx``: transfer the USDC
        yourself, then resend within 120 seconds carrying the hash. It costs an
        extra onchain transaction, and it is the flow Admissible prefers anyway,
        because the evidence is final before the request is made rather than
        arriving in a header we would have to take on faith.
        """
        async with httpx.AsyncClient(timeout=self.timeout, follow_redirects=True) as http:
            response = await http.request(
                method,
                url,
                json=dict(json_body) if json_body is not None else None,
                headers={DIRECT_TX_HEADER: tx_hash},
            )
        return PaidResult(response, tx_hash, {"mode": "direct-tx"})

    # -- proving -----------------------------------------------------------------

    def settle_and_verify(
        self, result: PaidResult, challenge: Challenge
    ) -> VerifiedSettlement | None:
        """Re-read the claimed settlement from Base.

        The header says we paid. The chain says whether we did. Only the second
        one can still be checked next month, which is the only kind of evidence
        worth writing into a memory.
        """
        if self.chain is None or not result.settlement_tx_hash:
            return None
        return self.chain.verify_settlement(
            result.settlement_tx_hash,
            self.chain.chain_id,
            expected_to=challenge.pay_to,
            expected_amount=challenge.amount,
            expected_token=challenge.asset,
        )


def fetch_challenge(url: str, *, method: str = "POST", json_body: Mapping[str, Any] | None = None,
                    timeout: float = 45.0) -> Challenge:
    """Synchronous 402 fetch, for scripts and tests that have no event loop."""
    with httpx.Client(timeout=timeout, follow_redirects=True) as http:
        response = http.request(
            method, url, json=dict(json_body) if json_body is not None else None
        )
    return _parse_challenge(response, url)


def _parse_challenge(response: httpx.Response, url: str) -> Challenge:
    """Turn a 402 into a typed challenge, or explain why it is not one."""
    if response.status_code != 402:
        raise PaymentRefused(
            f"{url} answered {response.status_code}, not 402; "
            "either it is free, it is broken, or the path is wrong"
        )
    try:
        raw = response.json()
    except json.JSONDecodeError as exc:
        raise PaymentRefused(f"{url} returned a 402 that is not JSON") from exc
    version = int(raw.get("x402Version", 2))
    parsed = (
        PaymentRequiredV1.model_validate(raw) if version == 1 else PaymentRequired.model_validate(raw)
    )
    if not parsed.accepts:
        raise PaymentRefused(f"{url} demands payment but lists no way to pay")
    return Challenge(version=version, raw=raw, parsed=parsed, url=url)


def _settlement_from(response: httpx.Response) -> tuple[str | None, dict[str, Any] | None]:
    """Pull the settlement tx hash out of whichever response header carried it.

    Checked case-insensitively and under both spellings, because the version the
    server answers with is the version it will reply in, and we support both.
    """
    for name in ("PAYMENT-RESPONSE", "X-PAYMENT-RESPONSE"):
        value = response.headers.get(name)
        if not value:
            continue
        try:
            settled = decode_payment_response_header(value)
        except Exception:
            continue
        return settled.transaction or None, settled.model_dump(by_alias=True, exclude_none=True)
    return None, None
