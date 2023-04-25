pragma solidity >=0.4.24 <0.9.0;
                    `contract Simple {
                        function f(uint a) payable public{
                            if (a == 65) {
                                revert();
                            }
                        }
                    }
