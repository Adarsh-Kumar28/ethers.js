// import { Wallet } from "@ethersproject/wallet";
// import { parseEther } from "@ethersproject/units";
import { ethers } from "ethers";

(async () => {
    const provider = new ethers.providers.JsonRpcBatchProvider("https://eth-goerli.g.alchemy.com/v2/FMdPttuCsebag_-Fpiv7_v--kLU8FlLF");
    const wallet = new ethers.Wallet("1abd8d123a31e65a34e9567cc941db8de97e0f9385c50c0191695258f6651a1a", provider);

    // Signing a message
    // console.log(await walletMnemonic.signMessage("Hello World"));

    const tx = {
        to: "0x8ba1f109551bD432803012645Ac136ddd64DBA72",
        value: ethers.utils.parseEther("1.0")
    };

    // Signing a transaction
    const res = await wallet.signTransaction(tx);
    //should return null
    console.log("signTransaction:");
    console.log(res);
})();