import subprocess
import pipes
import time
import json

class BitcoindAdapter:

    def __init__(self, network="mainnet"):
        self.network = network
   
    def run_subprocess(self, exe, *args):
        """
        Run a subprocess (bitcoind or bitcoin-cli)
        Returns => (command, return code, output)
    
        exe: executable file name (e.g. bitcoin-cli)
        args: arguments to exe
        """
        cmd_list = [exe] + list(args)
        pipe = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=1)
        output, _ = pipe.communicate()
        retcode = pipe.returncode
        return (cmd_list, retcode, output)
    
    def bitcoin_cli_call(self, *args):
        """
        Run `bitcoin-cli`, return OS return code
        """
        _, retcode, _ = self.run_subprocess("bitcoin-cli", f"-{self.network}", *args)
        return retcode
        
    def bitcoin_cli_checkoutput(self, *args):
        """
        Run `bitcoin-cli`, fail if OS return code nonzero, return output
        """
        cmd_list, retcode, output = self.run_subprocess("bitcoin-cli", f"-{self.network}", *args)
        if retcode != 0: raise subprocess.CalledProcessError(retcode, cmd_list, output=output)
        return output
        
    def bitcoin_cli_json(self, *args):
        """
        Run `bitcoin-cli`, parse output as JSON
        """
        return json.loads(self.bitcoin_cli_checkoutput(*args))
        
    def bitcoind_call(self, *args):
        """
        Run `bitcoind`, return OS return code
        """
        _, retcode, _ = self.run_subprocess("bitcoind", f"-{self.network}", *args)
        return retcode
    
    def ensure_bitcoind_running(self, *args):
        """
        Start bitcoind (if it's not already running) and ensure it's functioning properly
        """
        # start bitcoind.  If another bitcoind process is already running,
        # this will just print an error message (to /dev/null) and exit.

        self.bitcoind_call("-daemon", *args)
    
        # verify bitcoind started up and is functioning correctly
        times = 0
        while times <= 20:
            times += 1
            if self.bitcoin_cli_call("getnetworkinfo") == 0:
                return
            time.sleep(0.5)
    
        raise Exception("Timeout while starting bitcoin server")
