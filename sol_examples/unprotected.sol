pragma solidity ^0.8;

contract UnprotectedWallet{
    address public owner;

    modifier onlyowner {
        require(msg.sender==owner);
        _;
    }

    constructor() public {
        owner = msg.sender;
    }
    function changeOwner(address _newOwner) public {
       owner = _newOwner;
    }

    function deposit() payable public {
    }

    function withdraw() onlyowner public {
        payable(msg.sender).transfer(address(this).balance);
    }
}