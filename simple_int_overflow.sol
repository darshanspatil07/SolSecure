pragma solidity ^0.8.1;

contract SimpleDAO {
  mapping (address => uint) public credit;
    
  function donate(address to) payable public{
    credit[to] += msg.value;
  }
    
  function withdraw(uint amount) public {
    if (credit[msg.sender]>= amount) {
      credit[msg.sender]-=amount;
      (bool success,) = msg.sender.call{value: amount}("");
	require(success);
    }
  }  

  function queryCredit(address to) view public returns (uint){
    return credit[to];
  }
}
