import asyncio
import json
import logging
import os
import sys
import time
import datetime

from aiohttp import ClientError
from qrcode import QRCode

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.agent import (  # noqa:E402
    CRED_FORMAT_INDY,
    CRED_FORMAT_JSON_LD,
    SIG_TYPE_BLS,
)
from runners.support.utils import (  # noqa:E402
    log_msg,
    log_status,
    prompt,
    prompt_loop,
)


CRED_PREVIEW_TYPE = "https://didcomm.org/issue-credential/2.0/credential-preview"
SELF_ATTESTED = os.getenv("SELF_ATTESTED")
TAILS_FILE_COUNT = int(os.getenv("TAILS_FILE_COUNT", 100))

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class FSOAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        endorser_role: str = None,
        revocation: bool = False,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="FSO",
            no_auto=no_auto,
            endorser_role=endorser_role,
            revocation=revocation,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}
        # TODO define a dict to hold credential attributes
        # based on cred_def_id
        self.cred_attrs = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def generate_credential_offer(self, aip, cred_type, cred_def_id, exchange_tracing):
        if aip == 20:
            print("Using AIP 20")
            if cred_type == CRED_FORMAT_INDY:
                self.cred_attrs[cred_def_id] = {
                 "Product ID": "PD001",
                 "Product Name": "Mango",
                 "Product Category": "Fruit",
                 "Farm Location": "Ramnagar",
                 "Farming Practice": "Organic",
                 "Retailer ID": "RT001",
                 "Retailer Name":"MNO",
                 "Outlet Location": "New Delhi",
                 "Expiry Date": "25/05/23"
                }

                cred_preview = {
                    "@type": CRED_PREVIEW_TYPE,
                    "attributes": [
                        {"name": n, "value": v}
                        for (n, v) in self.cred_attrs[cred_def_id].items()
                    ],
                }
                offer_request = {
                    "connection_id": self.connection_id,
                    "comment": f"Offer on cred def id {cred_def_id}",
                    "auto_remove": False,
                    "credential_preview": cred_preview,
                    "filter": {"indy": {"cred_def_id": cred_def_id}},
                    "trace": exchange_tracing,
                }
                return offer_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                offer_request = {
                    "connection_id": self.connection_id,
                    "filter": {
                        "ld_proof": {
                            "credential": {
                                "@context": [
                                    "https://www.w3.org/2018/credentials/v1",
                                    "https://w3id.org/citizenship/v1",
                                    "https://w3id.org/security/bbs/v1",
                                ],
                                "type": [
                                    "VerifiableCredential",
                                    "PermanentResident",
                                ],
                                "id": "https://credential.example.com/residents/1234567890",
                                "issuer": self.did,
                                "issuanceDate": "2020-01-01T12:00:00Z",
                                "credentialSubject": {
                                    "type": ["PermanentResident"],
                                    "givenName": "ALICE",
                                    "familyName": "SMITH",
                                    "gender": "Female",
                                    "birthCountry": "Bahamas",
                                    "birthDate": "1958-07-17",
                                },
                            },
                            "options": {"proofType": SIG_TYPE_BLS},
                        }
                    },
                }
                return offer_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")

 

async def main(args):
    fso_agent = await create_agent_with_args(args, ident="fso")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {fso_agent.wallet_type})"
                if fso_agent.wallet_type
                else ""
            )
        )
        agent = FSOAgent(
            "fso.agent",
            fso_agent.start_port,
            fso_agent.start_port + 1,
            genesis_data=fso_agent.genesis_txns,
            genesis_txn_list=fso_agent.genesis_txn_list,
            no_auto=fso_agent.no_auto,
            tails_server_base_url=fso_agent.tails_server_base_url,
            revocation=fso_agent.revocation,
            timing=fso_agent.show_timing,
            multitenant=fso_agent.multitenant,
            mediation=fso_agent.mediation,
            wallet_type=fso_agent.wallet_type,
            seed=fso_agent.seed,
            aip=fso_agent.aip,
            endorser_role=fso_agent.endorser_role,
        )

        fso_schema_name = "Food Traceability Schema"
        fso_schema_attrs = ["Product ID","Product Name","Product Category","Farm Location","Farming Practice","Retailer ID", "Retailer Name","Outlet Location","Expiry Date"]

        if fso_agent.cred_type == CRED_FORMAT_INDY:
            fso_agent.public_did = True
            await fso_agent.initialize(
                the_agent=agent,
                schema_name=fso_schema_name,
                schema_attrs=fso_schema_attrs,
                create_endorser_agent=(fso_agent.endorser_role == "author")
                if fso_agent.endorser_role
                else False,
            )
        elif fso_agent.cred_type == CRED_FORMAT_JSON_LD:
            fso_agent.public_did = True
            await fso_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + fso_agent.cred_type)

        # generate an invitation for Alice
        await fso_agent.generate_invitation(
            display_qr=True, reuse_connections=fso_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Send Message \n"
            "    (2) Create Invitation \n"
            "    (3) Issue Food Traceability Credential \n"
            "    (4) Revoke the Credential \n"
            "    (X) Exit \n"
         )
      


        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "1":
                msg = await prompt("Enter message: ")
                await fso_agent.agent.admin_POST(
                    f"/connections/{fso_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            elif option == "2":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await fso_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=fso_agent.reuse_connections,
                    wait=True,
                )

            elif option == "3":
                log_status("#13 Issue credential offer to X")

                if fso_agent.aip == 10:
                    offer_request = fso_agent.agent.generate_credential_offer(
                        fso_agent.aip, None, fso_agent.cred_def_id, exchange_tracing
                    )
                    await fso_agent.agent.admin_POST(
                        "/issue-credential/send-offer", offer_request
                    )

                elif fso_agent.aip == 20:
                    print("Using AIP 20")
                    if fso_agent.cred_type == CRED_FORMAT_INDY:
                        offer_request = fso_agent.agent.generate_credential_offer(
                            fso_agent.aip,
                            fso_agent.cred_type,
                            fso_agent.cred_def_id,
                            exchange_tracing,
                        )

                    elif fso_agent.cred_type == CRED_FORMAT_JSON_LD:
                        offer_request = fso_agent.agent.generate_credential_offer(
                            fso_agent.aip,
                            fso_agent.cred_type,
                            None,
                            exchange_tracing,
                        )

                    else:
                        raise Exception(
                            f"Error invalid credential type: {fso_agent.cred_type}"
                        )

                    await fso_agent.agent.admin_POST(
                        "/issue-credential-2.0/send-offer", offer_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {fso_agent.aip}")

           
            elif option == "4" and fso_agent.revocation:
                rev_reg_id = (await prompt("Enter revocation registry ID: ")).strip()
                cred_rev_id = (await prompt("Enter credential revocation ID: ")).strip()
                publish = (
                    await prompt("Publish now? [Y/N]: ", default="N")
                ).strip() in "yY"
                try:
                    await fso_agent.agent.admin_POST(
                        "/revocation/revoke",
                        {
                            "rev_reg_id": rev_reg_id,
                            "cred_rev_id": cred_rev_id,
                            "publish": publish,
                            "connection_id": fso_agent.agent.connection_id,
                            # leave out thread_id, let aca-py generate
                            # "thread_id": "12345678-4444-4444-4444-123456789012",
                            "comment": "Revocation reason goes here ...",
                        },
                    )
                except ClientError:
                    pass

           
        if fso_agent.show_timing:
            timing = await fso_agent.agent.fetch_timing()
            if timing:
                for line in fso_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await fso_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="fso", port=9020)
    args = parser.parse_args()

   

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
