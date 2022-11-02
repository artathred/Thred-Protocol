// contracts/ThredCore.sol
// SPDX-License-Identifier: MIT
pragma solidity >=0.8.3;

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
        address indexed signer,
        address indexed user
    );

    event Uninstall(uint256 indexed tokenId, address indexed user);

    struct SmartUtil {
        string id;
        address signer;
        address payAddress;
        address feeAddress;
        uint256 fee;
        uint256 price;
        uint256 chainId;
        uint256 version;
        bool listed;
        bytes signature;
    }

    Counters.Counter private registeredIds;

    mapping(bytes32 => uint256) private _keys;

    mapping(address => uint256) private _reputation;

    mapping(bytes32 => uint256) private _downloads;

    mapping(uint256 => string) private _ids;

    mapping(bytes32 => uint256) private _versions;

    /**
     * @dev Pause all installations and withdrawals on the Thred Protocol.
     */
    function pause() public {
        require(msg.sender == deployerAddress, "Unauthorized!");
        PausableUpgradeable._pause();
    }

    /**
     * @dev Retrieves the current Chain ID of the protocol.
     * @return The Chain ID of the protocol
     */
    function getChainID() public view returns (uint256) {
        uint256 id;
        assembly {
            id := chainid()
        }
        return id;
    }

    /**
     * @dev Retrieves the registered App ID for the provided Token ID.
     * @param tokenId Token ID of the installed application.
     * @return The App ID corresponding to the Token ID
     */
    function getAppIdForToken(uint256 tokenId)
        public
        view
        returns (string memory)
    {
        return _ids[tokenId];
    }

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

    function isSoulbound(uint256 id) public view virtual returns (bool) {
        return _soulbounds[id];
    }

    function _setSoulbound(uint256 id, bool soulbound) internal {
        _soulbounds[id] = soulbound;
        emit Soulbound(id, soulbound);
    }

    /**
     * @dev Unpause all installations and withdrawals on the Thred Protocol.
     */
    function unpause() public {
        require(msg.sender == deployerAddress, "Unauthorized!");
        PausableUpgradeable._unpause();
    }

    /**
     * @dev Initialize the Thred Protocol.
     * @param owner The Whitelisted Owner Address of the Protocol.
     * @param domain Domain used for verification in TVS.
     * @param version Protocol version used for verification in TVS.
     */
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

    /**
     * @dev Retrieves the current payouts for a given list of addresses.
     * @param payoutAddresses Array of addresses to fetch the payouts for.
     * @return The available payouts for the provided addresses
     */
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

    /**
     * @dev Retrieves the current installed apps for the wallet.
     * @return The installed apps for the wallet
     */
    function fetchAppsForUser(address user)
        public
        view
        returns (string[] memory)
    {
        uint256 appCount = registeredIds.current();
        string[] memory apps = new string[](appCount);

        for (uint256 i = 0; i < appCount; ++i) {
            if (balanceOf(user, i) > 0) {
                apps[i] = getAppIdForToken(i);
            }
        }
        return apps;
    }

    /**
     * @dev Purchase, verify, and install an application under 'msg.sender'
     * @param util Signature of the app being installed.
     */
    function buySmartUtil(SmartUtil calldata util) public payable nonReentrant {
        require(!PausableUpgradeable.paused(), "Transacting Paused");
        address signer = _verifyTVS(util);
        require(
            signer == util.signer,
            "Unauthorized Signer. App can not be installed."
        );
        require(msg.value == util.price, "Insufficient Funds");
        require(
            util.chainId == getChainID(),
            "This item is not compatible with this chain"
        );
        bytes32 key = keccak256(abi.encodePacked(util.id, signer));
        require(
            util.version >= _versions[key],
            "Signature Expired. Please use a newer app signature"
        );
        require(
            util.listed, "App is not available for download"
        );
        _versions[key] = util.version;
        _registerDownload(util, signer, key);
        _setDeductibles(util);
        _setExp(util, signer);
    }

    /**
     * @dev Check if the given array contains the given element.
     * @param user The element to check for.
     * @param users The array to check.
     */
    function _addressContains(address user, address[] calldata users)
        private
        pure
        returns (bool)
    {
        uint256 length = users.length;
        if (length > 10) {
            length = 10;
        }
        for (uint i = 0; i < length; i++) {
            if (users[i] == user) {
                return true;
            }
        }
        return false;
    }

    /**
     * @dev Register the application under 'msg.sender'.
     * @param util Signature of the app being installed.
     * @param signer Signer of the application's TVS Signature.
     */
    function _registerDownload(
        SmartUtil calldata util,
        address signer,
        bytes32 key
    ) internal {
        uint256 tokenId = _keys[key];

        if (tokenId == 0) {
            registeredIds.increment();
            tokenId = registeredIds.current();
            _keys[key] = tokenId;
        }

        _ids[tokenId] = util.id;

        _mint(msg.sender, tokenId, 1, "");
        _setSoulbound(tokenId, true);
        emit Install(tokenId, signer, msg.sender);

        _downloads[key] = _downloads[key].add(1);
    }

    /**
     * @dev Set deductible fees for the application.
     * @param util Signature of the app being installed.
     */
    function _setDeductibles(SmartUtil calldata util) internal {
        uint256 fees = _calculateFee(util.price, 2);
        uint256 appFees = _calculateFee(util.price, util.fee);

        uint256 netPrice = util.price.sub(fees).sub(appFees);

        _deductibles[util.payAddress] = _deductibles[util.payAddress].add(
            netPrice
        );
        _deductibles[util.feeAddress] = _deductibles[util.feeAddress].add(
            appFees
        );

        _deductibles[deployerAddress] = _deductibles[deployerAddress].add(fees);
    }

    /**
     * @dev Set new Experience Points for the Signer.
     * @param util Signature of the app being installed.
     * @param signer Signer of the application's TVS Signature.
     */
    function _setExp(SmartUtil calldata util, address signer) internal {
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

    /**
     * @dev Calculate percentage fees from the given total.
     * @param _num The total amount.
     * @param percentWhole The percentage to calculate, must not be a fraction.
     * @return The calculated percentage fees.
     */
    function _calculateFee(uint256 _num, uint256 percentWhole)
        internal
        pure
        returns (uint256)
    {
        uint256 onePercentofTokens = _num.mul(100).div(100 * 10**uint256(2));
        uint256 twoPercentOfTokens = onePercentofTokens.mul(percentWhole);
        return twoPercentOfTokens;
    }

    /**
     * @dev Calculate the Experience Points to set for the 'user'.
     * @param user The user to calculate Exp for.
     * @param cost The price of the app that is being installed.
     * @param base The base amount to add to the user's Exp.
     * @return The calculated Experience Points for the 'user'.
     */
    function _calculateExp(
        address user,
        uint256 cost,
        uint256 base
    ) internal view returns (uint256) {
        return _reputation[user].add(base.add(cost.div(10)));
    }

    /**
     * @dev Fetch the current Experience Points for the 'user'.
     * @param user The user to fetch Exp for.
     * @return The current Experience Points for the 'user'.
     */
    function fetchRep(address user) public view returns (uint256) {
        return _reputation[user];
    }

    /**
     * @dev Fetch the current downloads for an application.
     * @param id The ID of the application.
     * @param signer Signer of the application's TVS Signature.
     * @return The current downloads of an application
     */
    function fetchDownloads(string calldata id, address signer)
        public
        view
        returns (uint256)
    {
        bytes32 key = keccak256(abi.encodePacked(id, signer));

        return _downloads[key];
    }

    /**
     * @dev Verify and retrieve the Signer of the app's TVS Signature using ECDSA Decryption.
     * @param util Signature of the app being installed.
     * @return The Decrypted Signer address.
     */
    function _verifyTVS(SmartUtil calldata util)
        internal
        view
        returns (address)
    {
        bytes32 digest = _hash(util);
        return ECDSAUpgradeable.recover(digest, util.signature);
    }

    /**
     * @dev Hash and return the application's TVS Signature.
     * @param util Signature of the app being installed.
     * @return The Digest of the TVS Signature
     */
    function _hash(SmartUtil calldata util) internal view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(
                    abi.encode(
                        keccak256(
                            "SmartUtil(string id,address signer,address payAddress,address feeAddress,uint256 fee,uint256 price,uint256 chainId,uint256 version,bool listed)"
                        ),
                        keccak256(bytes(util.id)),
                        util.signer,
                        util.payAddress,
                        util.feeAddress,
                        util.fee,
                        util.price,
                        util.chainId,
                        util.version,
                        util.listed
                    )
                )
            );
    }
}
