// contracts/ThredCore.sol
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

import "@openzeppelin/contracts/utils/Strings.sol";
import "@openzeppelin/contracts/utils/Counters.sol";
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
import "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts-upgradeable/security/PausableUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/token/ERC1155/ERC1155Upgradeable.sol";
import "@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/utils/cryptography/draft-EIP712Upgradeable.sol";

contract ThredCore is
    Initializable,
    ReentrancyGuardUpgradeable,
    PausableUpgradeable,
    EIP712Upgradeable,
    ERC1155Upgradeable
{
    using Counters for Counters.Counter;
    using SafeMath for uint256;
    using Strings for uint256;

    address public deployerAddress;

    mapping(uint256 => bool) private _soulbounds;

    mapping(address => uint256) private _deductibles;

    event Soulbound(uint256 indexed id, bool bounded);

    event Install(
        uint256 indexed tokenId,
        uint256 indexed price,
        address indexed user
    );

    event Uninstall(uint256 indexed tokenId, address indexed user);

    struct SmartUtil {
        string name;
        string id;
        address pay_address;
        uint256 category;
        uint256 price;
        uint256 created;
        uint256 modified;
        uint256 chainId;
        bytes signature;
    }

    Counters.Counter private registeredIds;

    mapping(bytes32 => uint256) private _keys;

    mapping(address => uint256) private _reputation;

    mapping(bytes32 => uint256) private _downloads;

    mapping(uint256 => string) private _ids;

    function pause() public {
        require(msg.sender == deployerAddress, "Unauthorized!");
        PausableUpgradeable._pause();
    }

    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    function getAppIdForToken(uint256 tokenId)
        public
        view
        returns (string memory)
    {
        return _ids[tokenId];
    }

    /**
     * @dev See {ERC1155-_beforeTokenTransfer}.
     */
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
        for (uint256 i = 0; i < ids.length; ++i) {
            if (isSoulbound(ids[i])) {
                require(
                    from == address(0) || to == address(0),
                    "Soulbound, Non-Transferable"
                );
            }
        }
    }

    function _afterTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual override {
        super._afterTokenTransfer(operator, from, to, ids, amounts, data);
        for (uint256 i = 0; i < ids.length; ++i) {
            if (to == address(0)) {
                emit Uninstall(ids[i], from);
            }
        }
    }

    /**
     * @dev Returns true if a token type `id` is soulbound.
     */

    function isSoulbound(uint256 id) public view virtual returns (bool) {
        return _soulbounds[id];
    }

    function _setSoulbound(uint256 id, bool soulbound) internal {
        _soulbounds[id] = soulbound;
        emit Soulbound(id, soulbound);
    }

    function unpause() public {
        require(msg.sender == deployerAddress, "Unauthorized!");
        PausableUpgradeable._unpause();
    }

    function initialize(
        address owner,
        string memory domain,
        string memory version
    ) public initializer {
        ReentrancyGuardUpgradeable.__ReentrancyGuard_init();
        PausableUpgradeable.__Pausable_init();
        ERC1155Upgradeable.__ERC1155_init(
            "https://storage.googleapis.com/thred-protocol.appspot.com/smart-utils/{id}.json"
        );
        EIP712Upgradeable.__EIP712_init(domain, version);
        deployerAddress = owner;
    }

    function fetchPayouts(address[] calldata payoutAddresses)
        public
        view
        returns (uint256[] memory)
    {
        uint256[] memory payouts = new uint256[](payoutAddresses.length);
        for (uint256 i = 0; i < payoutAddresses.length; ++i) {
            payouts[i] = _deductibles[payoutAddresses[i]];
        }
        return payouts;
    }

    function buySmartUtil(SmartUtil calldata util, address[] calldata to)
        public
        payable
        nonReentrant
    {
        require(!PausableUpgradeable.paused(), "Transacting Paused");
        require(to.length > 0, "Invalid To Length. Must be > than 0");

        address signer = _verify(util);

        require(
            util.chainId == getChainID(),
            "This item is not compatible with this chain"
        );

        uint256 totalPrice = util.price.mul(to.length);

        require(msg.value == totalPrice, "Insufficient Funds");

        bytes32 key = keccak256(abi.encodePacked(util.id, signer));

        uint256 tokenId = _keys[key];

        if (tokenId == 0) {
            registeredIds.increment();
            tokenId = registeredIds.current();
            _keys[key] = tokenId;
        }

        _ids[tokenId] = util.id;

        for (uint256 i = 0; i < to.length; ++i) {
            _mint(to[i], tokenId, 1, "");
            _setSoulbound(tokenId, true);
            emit Install(tokenId, util.price, to[i]);
        }

        _downloads[key] = _downloads[key].add(to.length);

        uint256 fees = _calculateFee(totalPrice, 2);
        uint256 netPrice = totalPrice.sub(fees);

        _deductibles[util.pay_address] = _deductibles[util.pay_address].add(
            netPrice
        );
        _deductibles[deployerAddress] = _deductibles[deployerAddress].add(fees);
        _reputation[signer] = _calculateExp(signer, util.price, 200);
    }

    function withDrawFunds() public nonReentrant {
        require(
            !PausableUpgradeable.paused() || msg.sender == deployerAddress,
            "Transacting Paused"
        );

        uint256 balance = _deductibles[msg.sender];
        require(balance > 0, "Nothing to withdraw.");
        (bool success, ) = msg.sender.call{value: balance}("");
        require(success, "Something went wrong.");
        _deductibles[msg.sender] = 0;
    }

    function _calculateFee(uint256 _num, uint256 percentWhole)
        internal
        pure
        returns (uint256)
    {
        uint256 onePercentofTokens = _num.mul(100).div(100 * 10**uint256(2));
        uint256 twoPercentOfTokens = onePercentofTokens.mul(percentWhole);
        return twoPercentOfTokens;
    }

    function _calculateExp(
        address user,
        uint256 cost,
        uint256 base
    ) internal view returns (uint256) {
        return _reputation[user].add(base.add(cost.div(10)));
    }

    function fetchRep(address user) public view returns (uint256) {
        return _reputation[user];
    }

    function fetchDownloads(string calldata id, address creator)
        public
        view
        returns (uint256)
    {
        bytes32 key = keccak256(abi.encodePacked(id, creator));

        return _downloads[key];
    }

    function _verify(SmartUtil calldata util) internal view returns (address) {
        bytes32 digest = _hash(util);
        return ECDSAUpgradeable.recover(digest, util.signature);
    }

    function _hash(SmartUtil calldata util) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "SmartUtil(string name,string id,address pay_address,uint256 category,uint256 price,uint256 created,uint256 modified, uint chainId)"
                        ),
                        keccak256(bytes(util.name)),
                        keccak256(bytes(util.id)),
                        util.pay_address,
                        util.category,
                        util.price,
                        util.created,
                        util.modified,
                        util.chainId
                    )
                )
            );
    }
}
