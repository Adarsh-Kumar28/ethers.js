import { Wallet } from "@ethersproject/wallet";
import { parseEther } from "@ethersproject/units";

(async () => {
    const mnemonic = "announce room limb pattern dry unit scale effort smooth jazz weasel alcohol";
    const walletMnemonic = Wallet.fromMnemonic(mnemonic);

    // Signing a message
    // console.log(await walletMnemonic.signMessage("Hello World"));

    const tx = {
        to: "0x8ba1f109551bD432803012645Ac136ddd64DBA72",
        value: parseEther("1.0")
    };

    // Signing a transaction
    const res = await walletMnemonic.signTransaction(tx);
    //should return null
    console.log(res);
})();