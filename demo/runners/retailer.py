import asyncio
import base64
import binascii
import json
import logging
import os
import sys
from urllib.parse import urlparse

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from runners.agent_container import (  # noqa:E402
    arg_parser,
    create_agent_with_args,
    AriesAgent,
)
from runners.support.utils import (  # noqa:E402
    check_requires,
    log_msg,
    log_status,
    log_timer,
    prompt,
    prompt_loop,
)

logging.basicConfig(level=logging.WARNING)
LOGGER = logging.getLogger(__name__)


class RetailerAgent(AriesAgent):
    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        no_auto: bool = False,
        aip: int = 20,
        endorser_role: str = None,
        **kwargs,
    ):
        super().__init__(
            ident,
            http_port,
            admin_port,
            prefix="Retailer",
            no_auto=no_auto,
            seed=None,
            aip=aip,
            endorser_role=endorser_role,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        self.cred_state = {}

    async def detect_connection(self):
        await self._connection_ready
        self._connection_ready = None

    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()


async def input_invitation(agent_container):
    agent_container.agent._connection_ready = asyncio.Future()
    async for details in prompt_loop("Invite details: "):
        b64_invite = None
        try:
            url = urlparse(details)
            query = url.query
            if query and "c_i=" in query:
                pos = query.index("c_i=") + 4
                b64_invite = query[pos:]
            elif query and "oob=" in query:
                pos = query.index("oob=") + 4
                b64_invite = query[pos:]
            else:
                b64_invite = details
        except ValueError:
            b64_invite = details

        if b64_invite:
            try:
                padlen = 4 - len(b64_invite) % 4
                if padlen <= 2:
                    b64_invite += "=" * padlen
                invite_json = base64.urlsafe_b64decode(b64_invite)
                details = invite_json.decode("utf-8")
            except binascii.Error:
                pass
            except UnicodeDecodeError:
                pass

        if details:
            try:
                details = json.loads(details)
                break
            except json.JSONDecodeError as e:
                log_msg("Invalid invitation:", str(e))

    with log_timer("Connect duration:"):
        connection = await agent_container.input_invitation(details, wait=True)


async def main(args):
    retailer_agent = await create_agent_with_args(args, ident="retailer")

    try:
        log_status(
            "#7 Provision an agent and wallet, get back configuration details"
            + (
                f" (Wallet type: {retailer_agent.wallet_type})"
                if retailer_agent.wallet_type
                else ""
            )
        )
        agent = RetailerAgent(
            "retailer.agent",
            retailer_agent.start_port,
            retailer_agent.start_port + 1,
            genesis_data=retailer_agent.genesis_txns,
            genesis_txn_list=retailer_agent.genesis_txn_list,
            no_auto=retailer_agent.no_auto,
            tails_server_base_url=retailer_agent.tails_server_base_url,
            revocation=retailer_agent.revocation,
            timing=retailer_agent.show_timing,
            multitenant=retailer_agent.multitenant,
            mediation=retailer_agent.mediation,
            wallet_type=retailer_agent.wallet_type,
            aip=retailer_agent.aip,
            endorser_role=retailer_agent.endorser_role,
        )

        await retailer_agent.initialize(the_agent=agent)

        
        await input_invitation(retailer_agent)

        options = "    (1) Send Message\n" "    (2) Input New Invitation\n" " (X) Exit \n "
        
        async for option in prompt_loop(options):
            if option is not None:
                option = option.strip()

            if option is None or option in "xX":
                break

            elif option == "1":
                msg = await prompt("Enter message: ")
                if msg:
                    await retailer_agent.agent.admin_POST(
                        f"/connections/{retailer_agent.agent.connection_id}/send-message",
                        {"content": msg},
                    )

            elif option == "2":
                # handle new invitation
                log_status("Input new invitation details")
                await input_invitation(retailer_agent)

        if retailer_agent.show_timing:
            timing = await retailer_agent.agent.fetch_timing()
            if timing:
                for line in retailer_agent.agent.format_timing(timing):
                    log_msg(line)

    finally:
        terminated = await retailer_agent.terminate()

    await asyncio.sleep(0.1)

    if not terminated:
        os._exit(1)


if __name__ == "__main__":
    parser = arg_parser(ident="retailer", port=9030)
    args = parser.parse_args()


    check_requires(args)

    try:
        asyncio.get_event_loop().run_until_complete(main(args))
    except KeyboardInterrupt:
        os._exit(1)
