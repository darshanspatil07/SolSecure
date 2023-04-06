from pathlib import Path
from types import SimpleNamespace
import argparse
import logging
import os
from pathlib import Path
import re
import shutil
import solc
import subprocess
import json
import sys
import warnings
from eth_utils import int_to_big_endian
from semantic_version import Version, NpmSpec
from typing import List, Tuple, Optional, TYPE_CHECKING
from mythril.support.support_utils import sha3, zpad
from mythril.ethereum import util
from mythril.ethereum.interface.rpc.client import EthJsonRpc
from mythril.exceptions import CriticalError, CompilerError, NoContractFoundError
from mythril.support import signatures
from mythril.support.support_utils import rzpad
from mythril.support.support_args import args
from mythril.ethereum.evmcontract import EVMContract
from mythril.ethereum.interface.rpc.exceptions import ConnectionError
from mythril.solidity.soliditycontract import SolidityContract
from mythril.solidity.soliditycontract import get_contracts_from_file
from mythril.support.support_args import args
from argparse import Namespace
from manticore.ethereum import ManticoreEVM
from manticore.core.smtlib import solver
from mythril.support.source_support import Source
from mythril.support.loader import DynLoader
from mythril.support.support_args import args
from mythril.analysis.symbolic import SymExecWrapper
from mythril.analysis.callgraph import generate_graph
from mythril.analysis.traceexplore import get_serializable_statespace
from mythril.analysis.security import fire_lasers, retrieve_callback_issues
from mythril.analysis.report import Report, Issue
from mythril.ethereum.evmcontract import EVMContract
from mythril.laser.smt import SolverStatistics
from mythril.support.start_time import StartTime
from mythril.exceptions import DetectorNotFoundError
from mythril.laser.execution_info import ExecutionInfo
from typing import Optional, List
import traceback
from getSolVersion import get_sol_version



parser = argparse.ArgumentParser()
parser.add_argument("-sol", help="something", required=True, default="umd_example.sol")
args = parser.parse_args()

log = logging.getLogger(__name__)
m = ManticoreEVM()

#Inputs
path = subprocess.check_output("pwd", shell=True)
path = path.decode("utf-8").strip()
contractfolder = "sol_examples"
contractfile = "{}/{}/{}".format(path,contractfolder, args.sol)
exec_time = 5
onchain_data= True
parallelsolve = True
sol_version = get_sol_version(contractfile).strip()
print(sol_version)

mythriloutput = "mythrilout.txt"
manticoreoutputdir = "{}".format(m.workspace)
contract_outpath = "SolSecure_output"
print(manticoreoutputdir)

def get_contracts_from_foundry(input_file, foundry_json):
    """
    :param input_file:
    :param solc_settings_json:
    :param solc_binary:
    """

    try:
        contract_names = foundry_json["contracts"][input_file].keys()
    except KeyError:
        raise NoContractFoundError

    for contract_name in contract_names:
        if len(
            foundry_json["contracts"][input_file][contract_name]["evm"][
                "deployedBytecode"
            ]["object"]
        ):

            yield SolidityContract(
                input_file=input_file,
                name=contract_name,
                solc_settings_json=None,
                solc_binary=None,
                solc_data=foundry_json,
            )

def format_Warning(message, category, filename, lineno, line=""):
    return "{}: {}\n\n".format(str(filename), str(message))


warnings.formatwarning = format_Warning


log = logging.getLogger(__name__)


class MythrilDisassembler:
    """
    The Mythril Disassembler class
    Responsible for generating disassembly of smart contracts:
        - Compiles solc code from file/onchain
        - Can also be used to access onchain storage data
    """

    def __init__(
        self,
        eth: Optional[EthJsonRpc] = None,
        solc_version: str = None,
        solc_settings_json: str = None,
        enable_online_lookup: bool = False,
        solc_args=None,
    ) -> None:
        args.solc_args = solc_args
        self.solc_binary = self._init_solc_binary(solc_version)
        self.solc_settings_json = solc_settings_json
        self.eth = eth
        self.enable_online_lookup = enable_online_lookup
        self.sigs = signatures.SignatureDB(enable_online_lookup=enable_online_lookup)
        self.contracts = []  # type: List[EVMContract]

    @staticmethod
    def _init_solc_binary(version: str) -> Optional[str]:
        """
        Only proper versions are supported. No nightlies, commits etc (such as available in remix).
        :param version: Version of the solc binary required
        :return: The solc binary of the corresponding version
        """

        if not version:
            return None

        # tried converting input to semver, seemed not necessary so just slicing for now
        try:
            main_version = solc.get_solc_version_string()
        except:
            main_version = ""  # allow missing solc will download instead
        main_version_number = re.search(r"\d+.\d+.\d+", main_version)

        if version.startswith("v"):
            version = version[1:]
        if version and NpmSpec("^0.8.0").match(Version(version)):
            args.use_integer_module = False
        if version == main_version_number:
            log.info("Given version matches installed version")
            solc_binary = os.environ.get("SOLC") or "solc"
        else:
            solc_binary = util.solc_exists(version)
            if solc_binary is None:
                raise CriticalError(
                    "The version of solc that is needed cannot be installed automatically"
                )
            else:
                log.info("Setting the compiler to %s", solc_binary)

        return solc_binary

    def load_from_bytecode(
        self, code: str, bin_runtime: bool = False, address: Optional[str] = None
    ) -> Tuple[str, EVMContract]:
        """
        Returns the address and the contract class for the given bytecode
        :param code: Bytecode
        :param bin_runtime: Whether the code is runtime code or creation code
        :param address: address of contract
        :return: tuple(address, Contract class)
        """
        if address is None:
            address = util.get_indexed_address(0)

        if bin_runtime:
            self.contracts.append(
                EVMContract(
                    code=code,
                    name="MAIN",
                    enable_online_lookup=self.enable_online_lookup,
                )
            )
        else:
            self.contracts.append(
                EVMContract(
                    creation_code=code,
                    name="MAIN",
                    enable_online_lookup=self.enable_online_lookup,
                )
            )
        return address, self.contracts[-1]  # return address and contract object

    def load_from_address(self, address: str) -> Tuple[str, EVMContract]:
        """
        Returns the contract given it's on chain address
        :param address: The on chain address of a contract
        :return: tuple(address, contract)
        """
        if not re.match(r"0x[a-fA-F0-9]{40}", address):
            raise CriticalError("Invalid contract address. Expected format is '0x...'.")

        if self.eth is None:
            raise CriticalError(
                "Please check whether the Infura key is set or use a different RPC method."
            )

        try:
            code = self.eth.eth_getCode(address)
        except FileNotFoundError as e:
            raise CriticalError("IPC error: " + str(e))
        except ConnectionError:
            raise CriticalError(
                "Could not connect to RPC server. Make sure that your node is running and that RPC parameters are set correctly."
            )
        except Exception as e:
            raise CriticalError("IPC / RPC error: " + str(e))

        if code == "0x" or code == "0x0":
            raise CriticalError(
                "Received an empty response from eth_getCode. Check the contract address and verify that you are on the correct chain."
            )
        else:
            self.contracts.append(
                EVMContract(
                    code, name=address, enable_online_lookup=self.enable_online_lookup
                )
            )
        return address, self.contracts[-1]  # return address and contract object

    def load_from_foundry(self):
        project_root = os.getcwd()

        cmd = ["forge", "build", "--build-info", "--force"]

        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=project_root,
            executable=shutil.which(cmd[0]),
        ) as p:

            stdout, stderr = p.communicate()
            stdout, stderr = (stdout.decode(), stderr.decode())
            if stderr:
                log.error(stderr)

            build_dir = Path(project_root, "artifacts", "contracts", "build-info")

        build_dir = os.path.join(project_root, "artifacts", "contracts", "build-info")

        files = os.listdir(build_dir)
        address = util.get_indexed_address(0)

        files = sorted(
            os.listdir(build_dir), key=lambda x: os.path.getmtime(Path(build_dir, x))
        )

        files = [str(f) for f in files if str(f).endswith(".json")]
        if not files:
            txt = f"`compile` failed. Can you run it?\n{build_dir} is empty"
            raise Exception(txt)
        contracts = []
        for file in files:
            build_info = Path(build_dir, file)

            uniq_id = file if ".json" not in file else file[0:-5]

            with open(build_info, encoding="utf8") as file_desc:
                loaded_json = json.load(file_desc)

                targets_json = loaded_json["output"]

                version_from_config = loaded_json["solcVersion"]
                input_json = loaded_json["input"]
                compiler = "solc" if input_json["language"] == "Solidity" else "vyper"
                optimizer = input_json["settings"]["optimizer"]["enabled"]

                if compiler == "vyper":
                    raise NotImplementedError("Support for Vyper is not implemented.")

                if "contracts" in targets_json:
                    for original_filename, contracts_info in targets_json[
                        "contracts"
                    ].items():
                        for contract in get_contracts_from_foundry(
                            original_filename, targets_json
                        ):
                            self.contracts.append(contract)
                            contracts.append(contract)
                            self.sigs.add_sigs(original_filename, targets_json)
        return address, contracts

    def load_from_solidity(
        self, solidity_files: List[str]
    ) -> Tuple[str, List[SolidityContract]]:
        """
        :param solidity_files: List of solidity_files
        :return: tuple of address, contract class list
        """
        address = util.get_indexed_address(0)
        contracts = []
        for file in solidity_files:
            if ":" in file:
                file, contract_name = file.split(":")
            else:
                contract_name = None

            file = os.path.expanduser(file)
            solc_binary = self.solc_binary or util.extract_binary(file)
            try:
                # import signatures from solidity source
                self.sigs.import_solidity_file(
                    file,
                    solc_binary=solc_binary,
                    solc_settings_json=self.solc_settings_json,
                )
                if contract_name is not None:
                    contract = SolidityContract(
                        input_file=file,
                        name=contract_name,
                        solc_settings_json=self.solc_settings_json,
                        solc_binary=solc_binary,
                    )
                    self.contracts.append(contract)
                    contracts.append(contract)
                else:
                    for contract in get_contracts_from_file(
                        input_file=file,
                        solc_settings_json=self.solc_settings_json,
                        solc_binary=solc_binary,
                    ):
                        self.contracts.append(contract)
                        contracts.append(contract)

            except FileNotFoundError as e:
                raise CriticalError(f"Input file not found {e}")
            except CompilerError as e:
                error_msg = str(e)
                # Check if error is related to solidity version mismatch
                if (
                    "Error: Source file requires different compiler version"
                    in error_msg
                ):
                    # Grab relevant line "pragma solidity <solv>...", excluding any comments
                    solv_pragma_line = error_msg.split("\n")[-3].split("//")[0]
                    # Grab solidity version from relevant line
                    solv_match = re.findall(r"[0-9]+\.[0-9]+\.[0-9]+", solv_pragma_line)
                    error_suggestion = (
                        "<version_number>" if len(solv_match) != 1 else solv_match[0]
                    )
                    error_msg = (
                        error_msg
                        + '\nSolidityVersionMismatch: Try adding the option "--solv '
                        + error_suggestion
                        + '"\n'
                    )

                raise CriticalError(error_msg)
            except NoContractFoundError:
                log.error(
                    "The file " + file + " does not contain a compilable contract."
                )

        return address, contracts

    @staticmethod
    def hash_for_function_signature(func: str) -> str:
        """
        Return function nadmes corresponding signature hash
        :param func: function name
        :return: Its hash signature
        """
        print(sha3(func))
        return "0x%s" % sha3(func)[:4].hex()

    def get_state_variable_from_storage(
        self, address: str, params: Optional[List[str]] = None
    ) -> str:
        """
        Get variables from the storage
        :param address: The contract address
        :param params: The list of parameters param types: [position, length] or ["mapping", position, key1, key2, ...  ]
                       or [position, length, array]
        :return: The corresponding storage slot and its value
        """
        params = params or []
        (position, length, mappings) = (0, 1, [])
        try:
            if params[0] == "mapping":
                if len(params) < 3:
                    raise CriticalError("Invalid number of parameters.")
                position = int(params[1])
                position_formatted = zpad(int_to_big_endian(position), 32)
                for i in range(2, len(params)):
                    key = bytes(params[i], "utf8")
                    key_formatted = rzpad(key, 32)
                    mappings.append(
                        int.from_bytes(
                            sha3(key_formatted + position_formatted), byteorder="big"
                        )
                    )

                length = len(mappings)
                if length == 1:
                    position = mappings[0]

            else:
                if len(params) >= 4:
                    raise CriticalError("Invalid number of parameters.")

                if len(params) >= 1:
                    position = int(params[0])
                if len(params) >= 2:
                    length = int(params[1])
                if len(params) == 3 and params[2] == "array":
                    position_formatted = zpad(int_to_big_endian(position), 32)
                    position = int.from_bytes(sha3(position_formatted), byteorder="big")

        except ValueError:
            raise CriticalError(
                "Invalid storage index. Please provide a numeric value."
            )

        outtxt = []

        try:
            if length == 1:
                outtxt.append(
                    "{}: {}".format(
                        position, self.eth.eth_getStorageAt(address, position)
                    )
                )
            else:
                if len(mappings) > 0:
                    for i in range(0, len(mappings)):
                        position = mappings[i]
                        outtxt.append(
                            "{}: {}".format(
                                hex(position),
                                self.eth.eth_getStorageAt(address, position),
                            )
                        )
                else:
                    for i in range(position, position + length):
                        outtxt.append(
                            "{}: {}".format(
                                hex(i), self.eth.eth_getStorageAt(address, i)
                            )
                        )
        except FileNotFoundError as e:
            raise CriticalError("IPC error: " + str(e))
        except ConnectionError:
            raise CriticalError(
                "Could not connect to RPC server. "
                "Make sure that your node is running and that RPC parameters are set correctly."
            )
        return "\n".join(outtxt)

class MythrilAnalyzer:
    """
    The Mythril Analyzer class
    Responsible for the analysis of the smart contracts
    """

    def __init__(
        self,
        disassembler: MythrilDisassembler,
        cmd_args: Namespace,
        strategy: str = "dfs",
        address: Optional[str] = None,
    ):
        """
        :param disassembler: The MythrilDisassembler class
        :param cmd_args: The command line args Namespace
        :param strategy: Search strategy
        :param address: Address of the contract
        """
        self.eth = disassembler.eth
        self.contracts = disassembler.contracts or []  # type: List[EVMContract]
        self.enable_online_lookup = disassembler.enable_online_lookup
        self.use_onchain_data = not cmd_args.no_onchain_data
        self.strategy = strategy
        self.address = address
        self.max_depth = cmd_args.max_depth
        self.execution_timeout = cmd_args.execution_timeout
        self.loop_bound = cmd_args.loop_bound
        self.create_timeout = cmd_args.create_timeout
        self.disable_dependency_pruning = cmd_args.disable_dependency_pruning
        self.custom_modules_directory = (
            cmd_args.custom_modules_directory
            if cmd_args.custom_modules_directory
            else ""
        )
        args.pruning_factor = cmd_args.pruning_factor
        args.solver_timeout = cmd_args.solver_timeout
        args.parallel_solving = cmd_args.parallel_solving
        args.unconstrained_storage = cmd_args.unconstrained_storage
        args.call_depth_limit = cmd_args.call_depth_limit
        args.iprof = cmd_args.enable_iprof
        args.solver_log = cmd_args.solver_log
        args.transaction_sequences = cmd_args.transaction_sequences

    def dump_statespace(self, contract: EVMContract = None) -> str:
        """
        Returns serializable statespace of the contract
        :param contract: The Contract on which the analysis should be done
        :return: The serialized state space
        """
        sym = SymExecWrapper(
            contract or self.contracts[0],
            self.address,
            self.strategy,
            dynloader=DynLoader(self.eth, active=self.use_onchain_data),
            max_depth=self.max_depth,
            execution_timeout=self.execution_timeout,
            create_timeout=self.create_timeout,
            disable_dependency_pruning=self.disable_dependency_pruning,
            run_analysis_modules=False,
            custom_modules_directory=self.custom_modules_directory,
        )

        return get_serializable_statespace(sym)

    def graph_html(
        self,
        contract: EVMContract = None,
        enable_physics: bool = False,
        phrackify: bool = False,
        transaction_count: Optional[int] = None,
    ) -> str:
        """
        :param contract: The Contract on which the analysis should be done
        :param enable_physics: If true then enables the graph physics simulation
        :param phrackify: If true generates Phrack-style call graph
        :param transaction_count: The amount of transactions to be executed
        :return: The generated graph in html format
        """

        sym = SymExecWrapper(
            contract or self.contracts[0],
            self.address,
            self.strategy,
            dynloader=DynLoader(self.eth, active=self.use_onchain_data),
            max_depth=self.max_depth,
            execution_timeout=self.execution_timeout,
            transaction_count=transaction_count,
            create_timeout=self.create_timeout,
            disable_dependency_pruning=self.disable_dependency_pruning,
            run_analysis_modules=False,
            custom_modules_directory=self.custom_modules_directory,
        )
        return generate_graph(sym, physics=enable_physics, phrackify=phrackify)

    def fire_lasers(
        self,
        modules: Optional[List[str]] = None,
        transaction_count: Optional[int] = None,
    ) -> Report:
        """
        :param modules: The analysis modules which should be executed
        :param transaction_count: The amount of transactions to be executed
        :return: The Report class which contains the all the issues/vulnerabilities
        """
        all_issues = []  # type: List[Issue]
        SolverStatistics().enabled = True
        exceptions = []
        execution_info = None  # type: Optional[List[ExecutionInfo]]
        for contract in self.contracts:
            StartTime()  # Reinitialize start time for new contracts
            try:
                sym = SymExecWrapper(
                    contract,
                    self.address,
                    self.strategy,
                    dynloader=DynLoader(self.eth, active=self.use_onchain_data),
                    max_depth=self.max_depth,
                    execution_timeout=self.execution_timeout,
                    loop_bound=self.loop_bound,
                    create_timeout=self.create_timeout,
                    transaction_count=transaction_count,
                    modules=modules,
                    compulsory_statespace=False,
                    disable_dependency_pruning=self.disable_dependency_pruning,
                    custom_modules_directory=self.custom_modules_directory,
                )
                issues = fire_lasers(sym, modules)
                execution_info = sym.execution_info
            except DetectorNotFoundError as e:
                # Bubble up
                raise e
            except KeyboardInterrupt:
                log.critical("Keyboard Interrupt")
                issues = retrieve_callback_issues(modules)
            except Exception:
                log.critical(
                    "Exception occurred, aborting analysis. Please report this issue to the Mythril GitHub page.\n"
                    + traceback.format_exc()
                )
                issues = retrieve_callback_issues(modules)
                exceptions.append(traceback.format_exc())
            for issue in issues:
                issue.add_code_info(contract)

            all_issues += issues
            log.info("Solver statistics: \n{}".format(str(SolverStatistics())))

        source_data = Source()
        source_data.get_source_from_contracts_list(self.contracts)

        # Finally, output the results
        report = Report(
            contracts=self.contracts,
            exceptions=exceptions,
            execution_info=execution_info,
        )
        for issue in all_issues:
            report.append_issue(issue)

        return report


disassembler = MythrilDisassembler(eth=None, solc_version="v{}".format(sol_version))
disassembler.load_from_solidity(["{}".format(contractfile)])
args = SimpleNamespace(
        execution_timeout=exec_time,
        max_depth=30,
        solver_timeout=10000,
        no_onchain_data=onchain_data,
        loop_bound=None,
        create_timeout=None,
        disable_dependency_pruning=False,
        custom_modules_directory=None,
        pruning_factor=0,
        parallel_solving=parallelsolve,
        unconstrained_storage=True,
        call_depth_limit=3,
        enable_iprof=False,
        solver_log=None,
        transaction_sequences=None,
    )
analyzer = MythrilAnalyzer(disassembler, cmd_args=args)
justvar = analyzer.fire_lasers(transaction_count=1)
mythout = justvar.as_text()
with open(mythriloutput, "w") as f:
    f.write(mythout)
f.close()
print("Results has been written to {}".format(mythriloutput))

with open("./sol_examples/unprotected.sol") as f:
    source_code = f.read()

# Generate the accounts. Creator has 10 ethers; attacker 0
creator_account = m.create_account(balance=10*10**18)
attacker_account = m.create_account(balance=10*10**18)
contract_account = m.solidity_create_contract(source_code, owner=creator_account)

contract_account.deposit(caller=creator_account, value=10**18)
# Two raw transactions from the attacker
symbolic_data = m.make_symbolic_buffer(320)
m.transaction(caller=attacker_account,address=contract_account,data=symbolic_data,value=0)
symbolic_data = m.make_symbolic_buffer(320)
m.transaction(caller=attacker_account,address=contract_account,data=symbolic_data,value=0)
for state in m.running_states:
    # Check if the attacker can ends with some ether
    balance = state.platform.get_balance(attacker_account.address)
    state.constrain(balance >= 10 * 10 ** 18)
    if state.is_feasible():
        print("Attacker can steal the ether! see {}".format(m.workspace))
        m.generate_testcase(state, 'WalletHack')
        print(f'Bug found, results are in {m.workspace}')   
