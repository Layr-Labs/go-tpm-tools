// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Script, console} from "forge-std/Script.sol";
import {BaseImageAllowlist} from "../src/BaseImageAllowlist.sol";

contract DeployScript is Script {
    function run() public {
        vm.startBroadcast();

        BaseImageAllowlist allowlist = new BaseImageAllowlist();
        console.log("BaseImageAllowlist deployed at:", address(allowlist));

        vm.stopBroadcast();
    }
}
