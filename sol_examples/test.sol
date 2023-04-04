pragma solidity 0.8.0;

contract TestContract {
    uint256 private secretNumber;

    function setSecretNumber(uint256 _secretNumber) public {
        secretNumber = _secretNumber;
    }

    function getSecretNumber() public view returns (uint256) {
        return secretNumber;
    }
}

