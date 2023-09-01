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


class CustomerAgent(AriesAgent):
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
            prefix="Customer",
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


    async def handle_present_proof_v2_0(self, message):
        state = message["state"]
        pres_ex_id = message["pres_ex_id"]
        self.log(f"Presentation: state = {state}, pres_ex_id = {pres_ex_id}")

        if state == "presentation-received":
            log_status("#27 Process the proof provided by X")
            log_status("#28 Check if proof is valid")
            proof = await self.admin_POST(
                f"/present-proof-2.0/records/{pres_ex_id}/verify-presentation"
            )
            self.log("Proof = ", proof["verified"])

            # if presentation is a degree schema (proof of food traceability),
            # check values received
            pres_req = message["by_format"]["pres_request"]["indy"]
            pres = message["by_format"]["pres"]["indy"]
            is_proof_of_identity = (
                pres_req["name"] == "Proof of Food Traceability"
            )
            if is_proof_of_identity:
                log_status("#28.1 Received proof of food traceability, check claims")
                for (referent, attr_spec) in pres_req["requested_attributes"].items():
                    if referent in pres['requested_proof']['revealed_attrs']:
                        self.log(
                            f"{attr_spec['name']}: "
                            f"{pres['requested_proof']['revealed_attrs'][referent]['raw']}"
                        )
                    else:
                        self.log(
                            f"{attr_spec['name']}: "
                            "(attribute not revealed)"
                        )
                for id_spec in pres["identifiers"]:
                    # just print out the schema/cred def id's of presented claims
                    self.log(f"schema_id: {id_spec['schema_id']}")
                    self.log(f"cred_def_id {id_spec['cred_def_id']}")
                # TODO placeholder for the next step
            else:
                # in case there are any other kinds of proofs received
                self.log("#28.1 Received ", pres_req["name"])    

   
    def generate_proof_request_web_request(
        self, aip, cred_type, revocation, exchange_tracing, connectionless=False
    ):
        
        if aip == 20:
            print("Using AIP 20")
            if cred_type == CRED_FORMAT_INDY:
                req_attrs = [
                    {   "name": "Product ID",
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Product Name",
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Product Category",
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Farm Location",
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Farming Practice" ,
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Retailer ID" ,
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Retailer Name" ,
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Outlet Location" ,
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    },
                    {
                        "name": "Expiry Date" ,
                        "restrictions": [{"schema_name": "Food Traceability Schema"}]
                    }
                ]
                '''if revocation:
                    req_attrs.append(
                        {
                            "name": "Identity",
                            "restrictions": [{"schema_name": "Identity Schema"}],
                            "non_revoked": {"to": int(time.time() - 1)},
                        },
                    )
                else:
                    req_attrs.append(
                        {
                            "name": "Identity",
                            "restrictions": [{"schema_name": "Identity Schema"}],
                        }
                    )'''
              
                req_preds = []
                indy_proof_request = {
                    "name": "Proof of Food Traceability",
                    "version": "1.0",
                    "requested_attributes": {
                        f"0_{req_attr['name']}_uuid": req_attr for req_attr in req_attrs
                    },
                    "requested_predicates": {
                        f"0_{req_pred['name']}_GE_uuid": req_pred
                        for req_pred in req_preds
                    },
                }

                if revocation:
                    indy_proof_request["non_revoked"] = {"to": int(time.time())}

                proof_request_web_request = {
                    "presentation_request": {"indy": indy_proof_request},
                    "trace": exchange_tracing,
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            elif cred_type == CRED_FORMAT_JSON_LD:
                proof_request_web_request = {
                    "comment": "test proof request for json-ld",
                    "presentation_request": {
                        "dif": {
                            "options": {
                                "challenge": "3fa85f64-5717-4562-b3fc-2c963f66afa7",
                                "domain": "4jt78h47fh47",
                            },
                            "presentation_definition": {
                                "id": "32f54163-7166-48f1-93d8-ff217bdb0654",
                                "format": {"ldp_vp": {"proof_type": [SIG_TYPE_BLS]}},
                                "input_descriptors": [
                                    {
                                        "id": "citizenship_input_1",
                                        "name": "EU Driver's License",
                                        "schema": [
                                            {
                                                "uri": "https://www.w3.org/2018/credentials#VerifiableCredential"
                                            },
                                            {
                                                "uri": "https://w3id.org/citizenship#PermanentResident"
                                            },
                                        ],
                                        "constraints": {
                                            "limit_disclosure": "required",
                                            "is_holder": [
                                                {
                                                    "directive": "required",
                                                    "field_id": [
                                                        "1f44d55f-f161-4938-a659-f8026467f126"
                                                    ],
                                                }
                                            ],
                                            "fields": [
                                                {
                                                    "id": "1f44d55f-f161-4938-a659-f8026467f126",
                                                    "path": [
                                                        "$.credentialSubject.familyName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                    "filter": {"const": "SMITH"},
                                                },
                                                {
                                                    "path": [
                                                        "$.credentialSubject.givenName"
                                                    ],
                                                    "purpose": "The claim must be from one of the specified person",
                                                },
                                            ],
                                        },
                                    }
                                ],
                            },
                        }
                    },
                }
                if not connectionless:
                    proof_request_web_request["connection_id"] = self.connection_id
                return proof_request_web_request

            else:
                raise Exception(f"Error invalid credential type: {self.cred_type}")

        else:
            raise Exception(f"Error invalid AIP level: {self.aip}")



async def main(args):
    customer_agent = await create_agent_with_args(args, ident="customer")

    try:
        log_status(
            "#1 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {customer_agent.wallet_type})"
                if customer_agent.wallet_type
                else ""
            )
        )
        agent = CustomerAgent(
            "customer.agent",
            customer_agent.start_port,
            customer_agent.start_port + 1,
            genesis_data=customer_agent.genesis_txns,
            genesis_txn_list=customer_agent.genesis_txn_list,
            no_auto=customer_agent.no_auto,
            tails_server_base_url=customer_agent.tails_server_base_url,
            revocation=customer_agent.revocation,
            timing=customer_agent.show_timing,
            multitenant=customer_agent.multitenant,
            mediation=customer_agent.mediation,
            wallet_type=customer_agent.wallet_type,
            seed=customer_agent.seed,
            aip=customer_agent.aip,
            endorser_role=customer_agent.endorser_role,
        )

      
        if customer_agent.cred_type == CRED_FORMAT_INDY:
            customer_agent.public_did = True
            await customer_agent.initialize(
                the_agent=agent,
               # schema_name=customer_schema_name,
               # schema_attrs=customer_schema_attrs,
                #create_endorser_agent=(customer_agent.endorser_role == "author")
                #if customer_agent.endorser_role
                #else False,
            )
        elif customer_agent.cred_type == CRED_FORMAT_JSON_LD:
            customer_agent.public_did = True
            await customer_agent.initialize(the_agent=agent)
        else:
            raise Exception("Invalid credential type:" + customer_agent.cred_type)

        # generate an invitation for Alice
        await customer_agent.generate_invitation(
            display_qr=True, reuse_connections=customer_agent.reuse_connections, wait=True
        )

        exchange_tracing = False
        options = (
            "    (1) Send Message \n"
            "    (2) Create New Invitation \n"
            "    (3) Send Proof Request for Food Traceability \n"
            "    (X) Exit \n"
        )
      
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "1":
                msg = await prompt("Enter message: ")
                await customer_agent.agent.admin_POST(
                    f"/connections/{customer_agent.agent.connection_id}/send-message",
                    {"content": msg},
                )

            
          
            elif option == "2":
                log_msg(
                    "Creating a new invitation, please receive "
                    "and accept this invitation using Alice agent"
                )
                await customer_agent.generate_invitation(
                    display_qr=True,
                    reuse_connections=customer_agent.reuse_connections,
                    wait=True,
                )


            elif option == "3":
                log_status("#20 Request proof of Food Traceability from Customer")
                if customer_agent.aip == 10:
                    proof_request_web_request = (
                        customer_agent.agent.generate_proof_request_web_request(
                            customer_agent.aip,
                            customer_agent.cred_type,
                            customer_agent.revocation,
                            exchange_tracing,
                        )
                    )
                    await customer_agent.agent.admin_POST(
                        "/present-proof/send-request", proof_request_web_request
                    )
                    pass

                elif customer_agent.aip == 20:
                    print("Using AIP 20")
                    if customer_agent.cred_type == CRED_FORMAT_INDY:
                        proof_request_web_request = (
                            customer_agent.agent.generate_proof_request_web_request(
                                customer_agent.aip,
                                customer_agent.cred_type,
                                customer_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    elif customer_agent.cred_type == CRED_FORMAT_JSON_LD:
                        proof_request_web_request = (
                            customer_agent.agent.generate_proof_request_web_request(
                                customer_agent.aip,
                                customer_agent.cred_type,
                                customer_agent.revocation,
                                exchange_tracing,
                            )
                        )

                    else:
                        raise Exception(
                            "Error invalid credential type:" + customer_agent.cred_type
                        )

                    await agent.admin_POST(
                        "/present-proof-2.0/send-request", proof_request_web_request
                    )

                else:
                    raise Exception(f"Error invalid AIP level: {customer_agent.aip}")


        if customer_agent.show_timing:
            timing = await customer_agent.agent.fetch_timing()
            if timing:
                for line in customer_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await customer_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="customer", port=9040)
    args = parser.parse_args()

    

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
